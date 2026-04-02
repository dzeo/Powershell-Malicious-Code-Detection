"""Review queue construction from scored rows."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class QueueThresholds:
    high_model: float = 0.95
    medium_model: float = 0.75
    uncertain_low: float = 0.40
    uncertain_high: float = 0.60
    low_model: float = 0.10
    high_rule: float = 40.0
    medium_rule: float = 20.0


def _queue_reason(row: pd.Series, thresholds: QueueThresholds) -> tuple[str, str] | None:
    prob = float(
        row.get(
            "malicious_probability",
            row.get("malicious_probability_corrected", row.get("malicious_probability_ensemble", 0.0)),
        )
    )
    rule_score = float(row.get("rule_score", 0.0))
    matched_rules = row.get("matched_rule_ids", []) or []

    if prob >= thresholds.high_model and rule_score >= thresholds.high_rule:
        return "high_priority", "high_model_and_high_rule"
    if prob >= thresholds.high_model and rule_score < thresholds.medium_rule:
        return "model_rule_disagreement", "high_model_low_rule"
    if prob < 0.50 and rule_score >= thresholds.high_rule:
        return "model_rule_disagreement", "low_model_high_rule"
    if thresholds.uncertain_low <= prob <= thresholds.uncertain_high:
        return "uncertain_band", "near_decision_boundary"
    if prob >= thresholds.medium_model:
        return "elevated_model", "elevated_model_probability"
    if rule_score >= thresholds.high_rule:
        return "elevated_rules", "strong_known_pattern_match"
    if prob <= thresholds.low_model and rule_score < thresholds.medium_rule:
        return "control_benign", "low_model_low_rule"
    if prob >= thresholds.medium_model and not matched_rules:
        return "novel_pattern_candidate", "high_model_no_known_rules"
    return None


def build_review_queue(
    df: pd.DataFrame,
    *,
    thresholds: QueueThresholds | None = None,
    max_per_queue: int = 500,
) -> pd.DataFrame:
    thresholds = thresholds or QueueThresholds()
    rows: list[dict[str, object]] = []

    for _, row in df.iterrows():
        decision = _queue_reason(row, thresholds)
        if decision is None:
            continue
        queue_name, queue_reason = decision
        payload = row.to_dict()
        payload["review_queue"] = queue_name
        payload["review_reason"] = queue_reason
        rows.append(payload)

    if not rows:
        return pd.DataFrame()

    queued = pd.DataFrame(rows)
    queued["priority_score"] = queued.apply(
        lambda row: abs(
            float(
                row.get(
                    "malicious_probability",
                    row.get("malicious_probability_corrected", row.get("malicious_probability_ensemble", 0.0)),
                )
            )
            - 0.5
        )
        + (float(row.get("rule_score", 0.0)) / 100.0),
        axis=1,
    )
    probability_column = "malicious_probability"
    if probability_column not in queued.columns:
        if "malicious_probability_corrected" in queued.columns:
            probability_column = "malicious_probability_corrected"
        elif "malicious_probability_ensemble" in queued.columns:
            probability_column = "malicious_probability_ensemble"
    dedupe_column = "analysis_text"
    if dedupe_column not in queued.columns:
        if "decoded_text" in queued.columns:
            dedupe_column = "decoded_text"
        elif "text" in queued.columns:
            dedupe_column = "text"
        else:
            dedupe_column = "sample_id"
    queued["_dedupe_key"] = queued[dedupe_column].fillna("").astype(str)
    queued = queued.sort_values(
        by=["review_queue", "priority_score", probability_column, "rule_score"],
        ascending=[True, False, False, False],
    )
    queued["duplicate_count"] = queued.groupby(["review_queue", "_dedupe_key"])["_dedupe_key"].transform("size")
    queued = queued.drop_duplicates(subset=["review_queue", "_dedupe_key"], keep="first")
    queued = queued.drop(columns=["_dedupe_key"])
    queued = queued.groupby("review_queue", group_keys=False).head(max_per_queue).reset_index(drop=True)
    return queued
