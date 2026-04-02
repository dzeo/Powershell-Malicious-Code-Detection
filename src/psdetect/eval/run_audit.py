"""Audit incremental pipeline runs for misleading or low-value results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditFinding:
    severity: str
    title: str
    detail: str


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _queue_family_distribution(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    per_queue: dict[str, dict[str, int]] = {}
    for row in rows:
        queue_name = str(row.get("review_queue", "unknown"))
        family = str(row.get("family", "unknown"))
        family_counts = per_queue.setdefault(queue_name, {})
        family_counts[family] = family_counts.get(family, 0) + 1
    return per_queue


def _top_fraction(counts: dict[str, int]) -> float:
    if not counts:
        return 0.0
    total = sum(counts.values())
    return max(counts.values()) / total if total else 0.0


def audit_run(run_dir: Path, queue_cap: int = 500) -> dict[str, Any]:
    artifact_path = run_dir / "final" / "final_artifact.json"
    artifact = _load_json(artifact_path)
    findings: list[AuditFinding] = []
    phase_reports: list[dict[str, Any]] = []

    all_pseudo = 0
    all_input_only = True
    phase_rule_aucs: list[tuple[str, float]] = []

    for phase in artifact.get("phases", []):
        phase_name = str(phase["phase_name"])
        summary_path = run_dir / phase_name / "summary.json"
        summary = _load_json(summary_path)
        validation_auc = summary.get("validation_auc", {})
        validation_accuracy = float(summary.get("validation_accuracy", 0.0))
        group_split = summary.get("group_split", {})
        review_queue_counts = summary.get("review_queue_counts", {})
        validation_queue_counts = summary.get("validation_review_queue_counts", {})
        phase_reports.append(
            {
                "phase_name": phase_name,
                "validation_accuracy": validation_accuracy,
                "validation_auc": validation_auc,
                "group_overlap": int(group_split.get("group_overlap", 0) or 0),
                "unique_validation_groups": int(group_split.get("unique_validation_groups", 0) or 0),
                "review_queue_counts": review_queue_counts,
                "validation_review_queue_counts": validation_queue_counts,
                "pseudo_labels_created": int(summary.get("pseudo_labels_created", 0) or 0),
            }
        )

        logistic_auc = float(validation_auc.get("logistic", 0.0) or 0.0)
        boost_auc = float(validation_auc.get("boost", 0.0) or 0.0)
        rule_auc = float(validation_auc.get("rule", 0.0) or 0.0)
        phase_rule_aucs.append((phase_name, rule_auc))

        if int(group_split.get("group_overlap", 0) or 0) != 0:
            findings.append(
                AuditFinding(
                    severity="critical",
                    title=f"{phase_name}: group leakage",
                    detail=f"group_overlap={group_split.get('group_overlap')} should be 0 for a family-isolated split.",
                )
            )

        if validation_accuracy >= 0.999 and logistic_auc >= 0.999 and boost_auc >= 0.999:
            findings.append(
                AuditFinding(
                    severity="high",
                    title=f"{phase_name}: near-perfect metrics",
                    detail=(
                        f"validation_accuracy={validation_accuracy:.4f}, logistic_auc={logistic_auc:.4f}, "
                        f"boost_auc={boost_auc:.4f}. On security data this is usually a sign of an easy or synthetic split."
                    ),
                )
            )

        unique_validation_groups = int(group_split.get("unique_validation_groups", 0) or 0)
        if unique_validation_groups <= 3:
            findings.append(
                AuditFinding(
                    severity="medium",
                    title=f"{phase_name}: narrow holdout",
                    detail=f"Only {unique_validation_groups} validation groups were held out.",
                )
            )

        if any(int(count) >= queue_cap for count in review_queue_counts.values()):
            findings.append(
                AuditFinding(
                    severity="medium",
                    title=f"{phase_name}: review queue saturation",
                    detail=f"One or more review queues hit the cap of {queue_cap}, so analyst prioritization is truncated.",
                )
            )

        pseudo_count = int(summary.get("pseudo_labels_created", 0) or 0)
        all_pseudo += pseudo_count
        label_sources = summary.get("label_sources", {})
        if set(label_sources) != {"input"}:
            all_input_only = False

        review_queue_rows = _load_jsonl(Path(summary["review_queue_path"]))
        per_queue_families = _queue_family_distribution(review_queue_rows)
        for queue_name, family_counts in per_queue_families.items():
            top_share = _top_fraction(family_counts)
            if top_share >= 0.8 and len(family_counts) >= 1:
                top_family = max(family_counts, key=family_counts.get)
                findings.append(
                    AuditFinding(
                        severity="medium",
                        title=f"{phase_name}: queue dominated by one family",
                        detail=(
                            f"Queue '{queue_name}' is {top_share:.1%} {top_family}, which limits review diversity."
                        ),
                    )
                )

    if all_pseudo == 0:
        findings.append(
            AuditFinding(
                severity="medium",
                title="Pseudo-label loop inactive",
                detail="No pseudo labels were created in any phase, so the unlabeled-data improvement loop was not exercised.",
            )
        )

    if all_input_only:
        findings.append(
            AuditFinding(
                severity="medium",
                title="Input labels only",
                detail="Every phase trained only on input labels; reviewed and pseudo labels were not part of this run.",
            )
        )

    if len(phase_rule_aucs) >= 2:
        min_rule_auc = min(value for _, value in phase_rule_aucs)
        max_rule_auc = max(value for _, value in phase_rule_aucs)
        if (max_rule_auc - min_rule_auc) >= 0.20:
            findings.append(
                AuditFinding(
                    severity="medium",
                    title="Rule-stage instability across phases",
                    detail=(
                        f"Rule ROC-AUC ranges from {min_rule_auc:.4f} to {max_rule_auc:.4f}, suggesting evaluation sensitivity to which families were held out."
                    ),
                )
            )

    overall_verdict = "promising"
    severities = {finding.severity for finding in findings}
    if "critical" in severities:
        overall_verdict = "invalid"
    elif "high" in severities:
        overall_verdict = "overstated"
    elif "medium" in severities:
        overall_verdict = "needs_real_data"

    return {
        "run_dir": str(run_dir.resolve()),
        "artifact_path": str(artifact_path.resolve()),
        "overall_verdict": overall_verdict,
        "phase_reports": phase_reports,
        "findings": [
            {"severity": finding.severity, "title": finding.title, "detail": finding.detail}
            for finding in findings
        ],
    }
