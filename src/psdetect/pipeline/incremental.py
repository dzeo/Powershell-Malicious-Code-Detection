"""Single-command incremental training pipeline."""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from tqdm.auto import tqdm

from psdetect.features.extract import FeatureRecord, build_feature_record
from psdetect.logging_utils import logger
from psdetect.models.baseline import HybridPowerShellDetector
from psdetect.models.numeric_boost import NumericBoostPowerShellDetector
from psdetect.models.weak_labels import assign_weak_label
from psdetect.review.labels import load_reviewed_labels, resolve_label
from psdetect.review.queue import build_review_queue
from psdetect.rules.engine import evaluate_attack_patterns


@dataclass(frozen=True)
class PhaseSpec:
    phase_index: int
    fraction: float
    row_count: int
    name: str


@dataclass(frozen=True)
class IncrementalPipelineConfig:
    input_path: Path
    output_dir: Path
    text_column: str = "text"
    id_column: str = "sample_id"
    label_column: str = "label"
    group_column: str | None = None
    reviewed_labels_path: Path | None = None
    parser_backend: str = "auto"
    phase_fractions: tuple[float, ...] = (0.1, 0.5, 1.0)
    validation_fraction: float = 0.2
    malicious_threshold: float = 0.97
    benign_threshold: float = 0.03
    log_every: int = 5000


def load_dataframe(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".jsonl":
        rows = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return pd.DataFrame(rows)
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)
    raise ValueError(f"Unsupported input format: {path.suffix}")


def build_phase_specs(total_rows: int, fractions: tuple[float, ...]) -> list[PhaseSpec]:
    specs: list[PhaseSpec] = []
    seen_counts: set[int] = set()
    for index, fraction in enumerate(fractions, start=1):
        count = max(1, min(total_rows, int(math.ceil(total_rows * fraction))))
        if count in seen_counts:
            continue
        seen_counts.add(count)
        specs.append(
            PhaseSpec(
                phase_index=index,
                fraction=fraction,
                row_count=count,
                name=f"phase_{index}_{int(round(fraction * 100))}pct",
            )
        )
    if specs[-1].row_count != total_rows:
        specs.append(
            PhaseSpec(
                phase_index=len(specs) + 1,
                fraction=1.0,
                row_count=total_rows,
                name=f"phase_{len(specs) + 1}_100pct",
            )
        )
    return specs


def _map_input_label(value: object) -> int | None:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    normalized = str(value).strip().lower()
    if normalized in {"benign", "clean", "normal"}:
        return 0
    if normalized in {"malicious", "suspicious", "suspicious_surrogate", "anomalous"}:
        return 1
    return None


def _label_name(value: int) -> str:
    return "malicious" if int(value) == 1 else "benign"


def _compute_second_pass_rule_probability(record: FeatureRecord) -> float:
    if record.normalized.decoded_text == record.normalized.analysis_text:
        return record.rules.risk_score / 100.0
    decoded_rules = evaluate_attack_patterns(record.normalized.decoded_text)
    return max(record.rules.risk_score / 100.0, decoded_rules.risk_score / 100.0)


def _derive_model_weights(logistic_auc: float, boost_auc: float, rule_auc: float) -> dict[str, float]:
    raw = {
        "logistic": max(0.01, logistic_auc - 0.5),
        "boost": max(0.01, boost_auc - 0.5),
        "rule": max(0.01, rule_auc - 0.5),
    }
    total = sum(raw.values())
    return {name: value / total for name, value in raw.items()}


def _corrected_probability(
    record: FeatureRecord,
    logistic_prob: float,
    boost_prob: float,
    weights: dict[str, float],
) -> tuple[float, float]:
    second_pass_rule_prob = _compute_second_pass_rule_probability(record)
    rule_active = bool(record.rules.matches) or second_pass_rule_prob >= 0.05
    if rule_active:
        effective_weights = weights
    else:
        # If neither the first-pass rules nor the decoded second pass see a
        # known pattern, do not let the rule channel dilute the learned models.
        model_weight_total = weights["logistic"] + weights["boost"]
        effective_weights = {
            "logistic": weights["logistic"] / model_weight_total,
            "boost": weights["boost"] / model_weight_total,
            "rule": 0.0,
        }
    corrected = (
        effective_weights["logistic"] * logistic_prob
        + effective_weights["boost"] * boost_prob
        + effective_weights["rule"] * second_pass_rule_prob
    )

    if logistic_prob < 0.5 and second_pass_rule_prob >= 0.4:
        corrected = max(corrected, (logistic_prob + second_pass_rule_prob) / 2.0 + 0.15)
    if record.normalized.transforms and corrected < second_pass_rule_prob:
        corrected = (0.6 * corrected) + (0.4 * second_pass_rule_prob)

    corrected = min(0.999, max(0.001, corrected))
    correction_delta = corrected - logistic_prob
    return corrected, correction_delta


def _select_label_for_training(
    sample_id: str,
    row: dict[str, object],
    record: FeatureRecord,
    reviewed_labels: dict[str, dict[str, object]],
    pseudo_labels: dict[str, dict[str, object]],
    label_column: str,
) -> tuple[int | None, str]:
    reviewed_entry = reviewed_labels.get(sample_id)
    label = resolve_label(reviewed_entry.get("final_label")) if reviewed_entry else None
    if label is not None:
        return label, "reviewed"

    label = _map_input_label(row.get(label_column))
    if label is not None:
        return label, "input"

    pseudo_entry = pseudo_labels.get(sample_id)
    label = resolve_label(pseudo_entry.get("final_label")) if pseudo_entry else None
    if label is not None:
        return label, "pseudo"

    weak = assign_weak_label(record)
    if weak.label == "unknown":
        return None, "unknown"
    return (1 if weak.label == "suspicious" else 0), "weak"


def _split_indices(size: int, validation_fraction: float, labels: list[int]) -> tuple[np.ndarray, np.ndarray]:
    if size < 10 or len(set(labels)) < 2:
        train_end = max(1, int(round(size * (1.0 - validation_fraction))))
        train_idx = np.arange(train_end)
        val_idx = np.arange(train_end, size)
        if len(val_idx) == 0:
            val_idx = np.arange(size - 1, size)
            train_idx = np.arange(size - 1)
        return train_idx, val_idx

    indices = np.arange(size)
    train_idx, val_idx = train_test_split(
        indices,
        test_size=validation_fraction,
        random_state=42,
        stratify=np.asarray(labels),
    )
    return np.sort(train_idx), np.sort(val_idx)


def _split_indices_with_groups(
    size: int,
    validation_fraction: float,
    labels: list[int],
    groups: list[str] | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    if not groups:
        return _split_indices(size, validation_fraction, labels)

    unique_groups = {group for group in groups if group}
    if len(unique_groups) < 2:
        return _split_indices(size, validation_fraction, labels)

    indices = np.arange(size)
    groups_array = np.asarray(groups)
    labels_array = np.asarray(labels)

    try:
        from sklearn.model_selection import StratifiedGroupKFold

        split_count = max(2, int(round(1.0 / validation_fraction)))
        split_count = min(split_count, len(unique_groups))
        splitter = StratifiedGroupKFold(n_splits=split_count, shuffle=True, random_state=42)
        target_val_size = size * validation_fraction
        best_split: tuple[np.ndarray, np.ndarray] | None = None
        best_distance: float | None = None
        for train_idx, val_idx in splitter.split(indices, labels_array, groups_array):
            if len(np.unique(labels_array[val_idx])) < 2:
                continue
            distance = abs(len(val_idx) - target_val_size)
            if best_distance is None or distance < best_distance:
                best_split = (np.sort(train_idx), np.sort(val_idx))
                best_distance = distance
        if best_split is not None:
            return best_split
    except Exception:
        pass

    splitter = GroupShuffleSplit(n_splits=1, test_size=validation_fraction, random_state=42)
    train_idx, val_idx = next(splitter.split(indices, labels_array, groups_array))
    return np.sort(train_idx), np.sort(val_idx)


def _write_jsonl(rows: list[dict[str, object]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def _prediction_bands(probabilities: list[float]) -> dict[str, int]:
    return {
        "ge_0_99": int(sum(value >= 0.99 for value in probabilities)),
        "ge_0_95": int(sum(value >= 0.95 for value in probabilities)),
        "ge_0_90": int(sum(value >= 0.90 for value in probabilities)),
        "ge_0_75": int(sum(value >= 0.75 for value in probabilities)),
        "ge_0_50": int(sum(value >= 0.50 for value in probabilities)),
        "le_0_10": int(sum(value <= 0.10 for value in probabilities)),
    }


def load_final_artifact(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _resolve_artifact_path(raw_path: str, artifact_path: Path) -> Path:
    candidate = Path(raw_path)
    search_paths: list[Path] = []
    if candidate.is_absolute():
        search_paths.append(candidate)
    else:
        search_paths.extend(
            [
                candidate,
                Path.cwd() / candidate,
                artifact_path.parent / candidate,
                artifact_path.parent / candidate.name,
                artifact_path.parent.parent / candidate,
            ]
        )

    seen: set[Path] = set()
    for path in search_paths:
        normalized = path.resolve()
        if normalized in seen:
            continue
        seen.add(normalized)
        if normalized.exists():
            return normalized
    return candidate.resolve()


def run_incremental_training(config: IncrementalPipelineConfig) -> dict[str, object]:
    logger.info("Loading dataset for incremental pipeline from {}", config.input_path)
    df = load_dataframe(config.input_path)
    logger.info("Loaded {} rows", len(df))
    reviewed_labels = load_reviewed_labels(config.reviewed_labels_path)
    if reviewed_labels:
        logger.info("Loaded {} reviewed labels", len(reviewed_labels))

    raw_rows = df.to_dict(orient="records")
    records: list[FeatureRecord] = []
    # Precompute normalization, parsing, rules, and numeric features once so
    # each cumulative phase reuses the same expensive artifacts.
    for idx, row in enumerate(tqdm(raw_rows, total=len(raw_rows), desc="Building all feature records")):
        sample_id = str(row.get(config.id_column, f"row-{idx:09d}"))
        text = str(row.get(config.text_column, ""))
        record = build_feature_record(sample_id=sample_id, text=text, parser_backend=config.parser_backend)
        records.append(record)
        if config.log_every and (idx + 1) % config.log_every == 0:
            logger.debug("Built {} feature records", idx + 1)

    phase_specs = build_phase_specs(len(records), config.phase_fractions)
    pseudo_labels: dict[str, dict[str, object]] = {}
    phase_summaries: list[dict[str, object]] = []
    final_weights: dict[str, float] = {"logistic": 0.5, "boost": 0.1, "rule": 0.4}
    final_models: tuple[HybridPowerShellDetector, NumericBoostPowerShellDetector] | None = None

    for phase in phase_specs:
        logger.info("Starting {}", phase.name)
        phase_dir = config.output_dir / phase.name
        phase_dir.mkdir(parents=True, exist_ok=True)
        phase_rows = raw_rows[: phase.row_count]
        phase_records = records[: phase.row_count]

        labels: list[int] = []
        label_sources: list[str] = []
        group_values: list[str] = []
        usable_records: list[FeatureRecord] = []
        usable_rows: list[dict[str, object]] = []
        # Label precedence is deliberate: reviewed labels override input labels,
        # input labels override pseudo labels, and weak labels are the last
        # resort for partially labeled corpora.
        for row, record in zip(phase_rows, phase_records):
            label, source = _select_label_for_training(
                sample_id=record.sample_id,
                row=row,
                record=record,
                reviewed_labels=reviewed_labels,
                pseudo_labels=pseudo_labels,
                label_column=config.label_column,
            )
            if label is None:
                continue
            usable_records.append(record)
            usable_rows.append(row)
            labels.append(label)
            label_sources.append(source)
            if config.group_column:
                group_values.append(str(row.get(config.group_column, record.sample_id)))

        if len(usable_records) < 10 or len(set(labels)) < 2:
            raise ValueError(f"Phase {phase.name} does not have enough labeled data to train.")

        train_idx, val_idx = _split_indices_with_groups(
            len(usable_records),
            config.validation_fraction,
            labels,
            groups=group_values if config.group_column else None,
        )
        train_records = [usable_records[i] for i in train_idx]
        val_records = [usable_records[i] for i in val_idx]
        val_rows = [usable_rows[i] for i in val_idx]
        train_y = [labels[i] for i in train_idx]
        val_y = [labels[i] for i in val_idx]

        train_groups = sorted({group_values[i] for i in train_idx}) if config.group_column else []
        val_groups = sorted({group_values[i] for i in val_idx}) if config.group_column else []
        group_overlap = len(set(train_groups).intersection(val_groups)) if config.group_column else 0
        logger.info(
            "{} split: train_rows={}, validation_rows={}, label_sources={}, unique_train_groups={}, unique_validation_groups={}, group_overlap={}",
            phase.name,
            len(train_records),
            len(val_records),
            dict(Counter(label_sources)),
            len(train_groups),
            len(val_groups),
            group_overlap,
        )

        logistic = HybridPowerShellDetector().fit(train_records, train_y)
        boost = NumericBoostPowerShellDetector(backend="auto").fit(train_records, train_y)

        logistic_val = logistic.predict_proba(val_records)[:, 1]
        boost_val = boost.predict_proba(val_records)[:, 1]
        rule_val = np.array([_compute_second_pass_rule_probability(record) for record in val_records], dtype=float)

        logistic_auc = float(roc_auc_score(val_y, logistic_val))
        boost_auc = float(roc_auc_score(val_y, boost_val))
        rule_auc = float(roc_auc_score(val_y, rule_val))
        final_weights = _derive_model_weights(logistic_auc, boost_auc, rule_auc)
        final_models = (logistic, boost)

        corrected_val = []
        correction_delta_val = []
        for record, p_lr, p_boost in zip(val_records, logistic_val, boost_val):
            corrected_prob, correction_delta = _corrected_probability(record, float(p_lr), float(p_boost), final_weights)
            corrected_val.append(corrected_prob)
            correction_delta_val.append(correction_delta)
        corrected_pred = [1 if value >= 0.5 else 0 for value in corrected_val]
        validation_accuracy = float(accuracy_score(val_y, corrected_pred))
        validation_report = classification_report(
            val_y,
            corrected_pred,
            output_dict=True,
            zero_division=0,
        )
        validation_confusion = confusion_matrix(val_y, corrected_pred).tolist()

        logger.info(
            "{} validation ROC-AUCs: logistic={:.4f}, boost={:.4f}, rule={:.4f}, corrected_acc={:.4f}, weights={}",
            phase.name,
            logistic_auc,
            boost_auc,
            rule_auc,
            validation_accuracy,
            final_weights,
        )

        logistic_all = logistic.predict_proba(phase_records)[:, 1]
        boost_all = boost.predict_proba(phase_records)[:, 1]
        scored_rows: list[dict[str, object]] = []
        phase_pseudo_rows: list[dict[str, object]] = []

        # These phase scores are the operational outputs for the full cumulative
        # slice. Holdout-only evaluation is written separately below.
        for row, record, p_lr, p_boost in zip(phase_rows, phase_records, logistic_all, boost_all):
            corrected_prob, correction_delta = _corrected_probability(record, float(p_lr), float(p_boost), final_weights)
            second_pass_rule_prob = _compute_second_pass_rule_probability(record)
            weak = assign_weak_label(record)
            label_source = _select_label_for_training(
                sample_id=record.sample_id,
                row=row,
                record=record,
                reviewed_labels=reviewed_labels,
                pseudo_labels=pseudo_labels,
                label_column=config.label_column,
            )[1]

            if label_source in {"unknown", "weak"}:
                pseudo_label = None
                # Auto-label only the extreme ends of the score distribution so
                # later phases do not train on ambiguous self-generated labels.
                if corrected_prob >= config.malicious_threshold or (
                    corrected_prob >= 0.80 and second_pass_rule_prob >= 0.60
                ):
                    pseudo_label = "malicious"
                elif corrected_prob <= config.benign_threshold and second_pass_rule_prob < 0.20:
                    pseudo_label = "benign"

                if pseudo_label is not None:
                    pseudo_entry = {
                        "sample_id": record.sample_id,
                        "final_label": pseudo_label,
                        "confidence": round(abs(corrected_prob - 0.5) * 2.0, 4),
                        "reviewer": "auto-pipeline",
                        "reviewed_at": phase.name,
                        "rationale": f"corrected_probability={corrected_prob:.4f}; rule_score={record.rules.risk_score}",
                        "family_override": "",
                        "source": "auto_relabel",
                    }
                    existing = pseudo_labels.get(record.sample_id)
                    if existing is None or float(existing.get("confidence", 0.0)) < pseudo_entry["confidence"]:
                        pseudo_labels[record.sample_id] = pseudo_entry
                    phase_pseudo_rows.append(pseudo_entry)

            scored_rows.append(
                {
                    **row,
                    "sample_id": record.sample_id,
                    "analysis_text": record.normalized.analysis_text,
                    "decoded_text": record.normalized.decoded_text,
                    "malicious_probability": round(float(corrected_prob), 6),
                    "malicious_probability_logistic": round(float(p_lr), 6),
                    "malicious_probability_boost": round(float(p_boost), 6),
                    "malicious_probability_corrected": round(float(corrected_prob), 6),
                    "correction_delta": round(float(correction_delta), 6),
                    "second_pass_rule_probability": round(float(second_pass_rule_prob), 6),
                    "rule_score": record.rules.risk_score,
                    "matched_rule_ids": record.rules.matched_rule_ids,
                    "matched_techniques": record.rules.matched_techniques,
                    "weak_label": weak.label,
                    "weak_confidence": round(float(weak.confidence), 4),
                    "label_source": label_source,
                }
            )

        scores_path = phase_dir / "scores.jsonl"
        _write_jsonl(scored_rows, scores_path)
        queue_df = build_review_queue(pd.DataFrame(scored_rows), max_per_queue=500)
        queue_path = phase_dir / "review_queue.jsonl"
        if not queue_df.empty:
            queue_df.to_json(queue_path, orient="records", lines=True, force_ascii=True)
        else:
            queue_path.write_text("", encoding="utf-8")

        validation_scored_rows: list[dict[str, object]] = []
        for row, record, y_true, p_lr, p_boost, p_rule, p_corr, delta in zip(
            val_rows,
            val_records,
            val_y,
            logistic_val,
            boost_val,
            rule_val,
            corrected_val,
            correction_delta_val,
        ):
            validation_scored_rows.append(
                {
                    **row,
                    "sample_id": record.sample_id,
                    "analysis_text": record.normalized.analysis_text,
                    "decoded_text": record.normalized.decoded_text,
                    "true_label": int(y_true),
                    "predicted_label": int(p_corr >= 0.5),
                    "malicious_probability": round(float(p_corr), 6),
                    "malicious_probability_logistic": round(float(p_lr), 6),
                    "malicious_probability_boost": round(float(p_boost), 6),
                    "malicious_probability_corrected": round(float(p_corr), 6),
                    "correction_delta": round(float(delta), 6),
                    "second_pass_rule_probability": round(float(p_rule), 6),
                    "rule_score": record.rules.risk_score,
                    "matched_rule_ids": record.rules.matched_rule_ids,
                    "matched_techniques": record.rules.matched_techniques,
                }
            )
        validation_scores_path = phase_dir / "validation_scores.jsonl"
        _write_jsonl(validation_scored_rows, validation_scores_path)
        validation_queue_df = build_review_queue(pd.DataFrame(validation_scored_rows), max_per_queue=250)
        validation_queue_path = phase_dir / "validation_review_queue.jsonl"
        if not validation_queue_df.empty:
            validation_queue_df.to_json(validation_queue_path, orient="records", lines=True, force_ascii=True)
        else:
            validation_queue_path.write_text("", encoding="utf-8")

        pseudo_path = phase_dir / "auto_pseudo_labels.jsonl"
        _write_jsonl(phase_pseudo_rows, pseudo_path)

        logistic_path = phase_dir / "logistic.joblib"
        boost_path = phase_dir / "numeric_boost.joblib"
        logistic.save(str(logistic_path))
        boost.save(str(boost_path))

        phase_summary = {
            "phase_name": phase.name,
            "fraction": phase.fraction,
            "rows_in_phase": phase.row_count,
            "usable_labeled_rows": len(usable_records),
            "label_sources": dict(Counter(label_sources)),
            "validation_rows": int(len(val_records)),
            "validation_auc": {
                "logistic": logistic_auc,
                "boost": boost_auc,
                "rule": rule_auc,
            },
            "validation_accuracy": validation_accuracy,
            "validation_confusion_matrix": validation_confusion,
            "validation_classification_report": validation_report,
            "validation_prediction_bands": _prediction_bands(corrected_val),
            "calibrated_weights": final_weights,
            "group_split": {
                "group_column": config.group_column,
                "unique_train_groups": len(train_groups),
                "unique_validation_groups": len(val_groups),
                "group_overlap": group_overlap,
                "train_groups_sample": train_groups[:10],
                "validation_groups_sample": val_groups[:10],
            },
            "pseudo_labels_created": len(phase_pseudo_rows),
            "scores_path": str(scores_path),
            "review_queue_path": str(queue_path),
            "review_queue_counts": (
                {}
                if queue_df.empty
                else {str(name): int(count) for name, count in queue_df["review_queue"].value_counts().items()}
            ),
            "validation_scores_path": str(validation_scores_path),
            "validation_review_queue_path": str(validation_queue_path),
            "validation_review_queue_counts": (
                {}
                if validation_queue_df.empty
                else {
                    str(name): int(count)
                    for name, count in validation_queue_df["review_queue"].value_counts().items()
                }
            ),
            "pseudo_labels_path": str(pseudo_path),
            "logistic_model_path": str(logistic_path),
            "boost_model_path": str(boost_path),
        }
        phase_summaries.append(phase_summary)
        with (phase_dir / "summary.json").open("w", encoding="utf-8") as handle:
            json.dump(phase_summary, handle, indent=2, ensure_ascii=True)
        logger.info("{} complete; pseudo_labels_created={}", phase.name, len(phase_pseudo_rows))

    assert final_models is not None
    final_logistic, final_boost = final_models

    final_dir = config.output_dir / "final"
    final_dir.mkdir(parents=True, exist_ok=True)
    final_logistic_path = final_dir / "logistic_final.joblib"
    final_boost_path = final_dir / "numeric_boost_final.joblib"
    final_logistic.save(str(final_logistic_path))
    final_boost.save(str(final_boost_path))

    pseudo_store_path = final_dir / "auto_pseudo_labels_all.jsonl"
    _write_jsonl(list(pseudo_labels.values()), pseudo_store_path)

    final_artifact = {
        "input_path": str(config.input_path.resolve()),
        "phase_fractions": list(config.phase_fractions),
        "parser_backend": config.parser_backend,
        "final_weights": final_weights,
        "thresholds": {
            "malicious_threshold": config.malicious_threshold,
            "benign_threshold": config.benign_threshold,
        },
        "models": {
            "logistic": str(final_logistic_path.resolve()),
            "numeric_boost": str(final_boost_path.resolve()),
        },
        "pseudo_label_store": str(pseudo_store_path.resolve()),
        "phases": phase_summaries,
    }
    artifact_path = final_dir / "final_artifact.json"
    with artifact_path.open("w", encoding="utf-8") as handle:
        json.dump(final_artifact, handle, indent=2, ensure_ascii=True)
    logger.info("Saved final artifact to {}", artifact_path)
    return final_artifact


def run_final_inference(
    *,
    artifact_path: Path,
    input_path: Path,
    output_path: Path,
    summary_output: Path | None = None,
    review_queue_output: Path | None = None,
    review_queue_summary_output: Path | None = None,
    text_column: str = "text",
    id_column: str = "sample_id",
    parser_backend: str | None = None,
    top_k: int = 10,
    explain_top_n: int = 500,
    explain_all: bool = False,
    log_every: int = 5000,
) -> dict[str, object]:
    logger.info("Loading final artifact from {}", artifact_path)
    artifact = load_final_artifact(artifact_path)
    effective_parser_backend = parser_backend or str(artifact.get("parser_backend", "auto"))
    weights = artifact.get("final_weights", {"logistic": 0.5, "boost": 0.1, "rule": 0.4})

    logistic_path = _resolve_artifact_path(str(artifact["models"]["logistic"]), artifact_path)
    boost_path = _resolve_artifact_path(str(artifact["models"]["numeric_boost"]), artifact_path)
    logger.info("Loading final logistic model from {}", logistic_path)
    logistic = HybridPowerShellDetector.load(str(logistic_path))
    logger.info("Loading final numeric boost model from {}", boost_path)
    boost = NumericBoostPowerShellDetector.load(str(boost_path))

    logger.info("Loading inference dataset from {}", input_path)
    df = load_dataframe(input_path)
    logger.info("Loaded {} rows for inference", len(df))

    records: list[FeatureRecord] = []
    rows: list[dict[str, object]] = []
    raw_rows = df.to_dict(orient="records")
    for idx, row in enumerate(tqdm(raw_rows, total=len(raw_rows), desc="Building inference records")):
        sample_id = str(row.get(id_column, f"row-{idx:09d}"))
        text = str(row.get(text_column, ""))
        record = build_feature_record(sample_id=sample_id, text=text, parser_backend=effective_parser_backend)
        records.append(record)
        rows.append(row)
        if log_every and (idx + 1) % log_every == 0:
            logger.debug("Built {} inference records", idx + 1)

    logistic_scores = logistic.predict_proba(records)[:, 1]
    boost_scores = boost.predict_proba(records)[:, 1]

    corrected_scores: list[float] = []
    correction_deltas: list[float] = []
    second_pass_rule_scores: list[float] = []
    for record, p_lr, p_boost in zip(records, logistic_scores, boost_scores):
        corrected_prob, correction_delta = _corrected_probability(record, float(p_lr), float(p_boost), weights)
        second_pass_rule_prob = _compute_second_pass_rule_probability(record)
        corrected_scores.append(corrected_prob)
        correction_deltas.append(correction_delta)
        second_pass_rule_scores.append(second_pass_rule_prob)

    explain_indices: set[int] = set()
    if explain_all:
        explain_indices = set(range(len(records)))
    elif explain_top_n > 0 and records:
        ranked_indices = np.argsort(np.asarray(corrected_scores))[::-1][: min(explain_top_n, len(records))]
        explain_indices = {int(index) for index in ranked_indices.tolist()}

    logistic_explanations: dict[str, dict[str, object]] = {}
    boost_explanations: dict[str, dict[str, object]] = {}
    if explain_indices:
        explain_records = [records[index] for index in sorted(explain_indices)]
        logger.info("Generating explanations for {} high-priority inference rows", len(explain_records))
        logistic_explanations = {
            item["sample_id"]: item for item in logistic.explain(explain_records, top_k=top_k)
        }
        boost_explanations = {
            item["sample_id"]: item for item in boost.explain(explain_records, top_k=top_k)
        }

    scored_rows: list[dict[str, object]] = []
    for index, (row, record, p_lr, p_boost) in enumerate(zip(rows, records, logistic_scores, boost_scores)):
        corrected_prob = corrected_scores[index]
        correction_delta = correction_deltas[index]
        second_pass_rule_prob = second_pass_rule_scores[index]
        weak = assign_weak_label(record)
        logistic_explanation = logistic_explanations.get(
            record.sample_id,
            {"top_model_contributions": [], "top_numeric_signals": []},
        )
        boost_explanation = boost_explanations.get(
            record.sample_id,
            {"backend": boost.backend, "top_numeric_signals": []},
        )
        payload = {
            **row,
            "sample_id": record.sample_id,
            "analysis_text": record.normalized.analysis_text,
            "decoded_text": record.normalized.decoded_text,
            "transforms": record.normalized.transforms,
            "parser_backend": record.parsed.backend,
            "commands": record.parsed.commands,
            "parameters": record.parsed.parameters,
            "malicious_probability": round(float(corrected_prob), 6),
            "malicious_probability_logistic": round(float(p_lr), 6),
            "malicious_probability_boost": round(float(p_boost), 6),
            "malicious_probability_corrected": round(float(corrected_prob), 6),
            "correction_delta": round(float(correction_delta), 6),
            "second_pass_rule_probability": round(float(second_pass_rule_prob), 6),
            "rule_score": record.rules.risk_score,
            "rule_total_weight": record.rules.total_weight,
            "rule_max_level": record.rules.max_level,
            "matched_rule_ids": record.rules.matched_rule_ids,
            "matched_rule_categories": record.rules.matched_categories,
            "matched_techniques": record.rules.matched_techniques,
            "rule_matches": [
                {
                    "rule_id": match.rule_id,
                    "name": match.name,
                    "category": match.category,
                    "level": match.level,
                    "severity": match.severity,
                    "weight": match.weight,
                    "mitre_techniques": match.mitre_techniques,
                }
                for match in record.rules.matches
            ],
            "calibration_weights": {name: round(float(value), 6) for name, value in weights.items()},
            "weak_label": weak.label,
            "weak_confidence": round(float(weak.confidence), 4),
            "weak_rationale": weak.rationale,
            "has_detailed_explanation": record.sample_id in logistic_explanations,
            "top_model_contributions": logistic_explanation["top_model_contributions"],
            "top_numeric_signals": logistic_explanation["top_numeric_signals"],
            "numeric_boost_backend": boost_explanation["backend"],
            "top_numeric_boost_signals": boost_explanation["top_numeric_signals"],
        }
        scored_rows.append(payload)

    logger.info("Writing inference scores to {}", output_path)
    _write_jsonl(scored_rows, output_path)

    review_queue_rows = build_review_queue(pd.DataFrame(scored_rows), max_per_queue=500)
    queue_counts: dict[str, int] = {}
    if review_queue_output is not None:
        review_queue_output.parent.mkdir(parents=True, exist_ok=True)
        if review_queue_rows.empty:
            review_queue_output.write_text("", encoding="utf-8")
        else:
            review_queue_rows.to_json(review_queue_output, orient="records", lines=True, force_ascii=True)
        logger.info("Wrote inference review queue to {}", review_queue_output)
    if not review_queue_rows.empty:
        queue_counts = {
            str(name): int(count) for name, count in review_queue_rows["review_queue"].value_counts().items()
        }

    summary = {
        "artifact_path": str(artifact_path.resolve()),
        "input_path": str(input_path.resolve()),
        "rows": len(scored_rows),
        "parser_backend": effective_parser_backend,
        "prediction_bands": {
            "ge_0_99": sum(item["malicious_probability"] >= 0.99 for item in scored_rows),
            "ge_0_95": sum(item["malicious_probability"] >= 0.95 for item in scored_rows),
            "ge_0_90": sum(item["malicious_probability"] >= 0.90 for item in scored_rows),
            "ge_0_75": sum(item["malicious_probability"] >= 0.75 for item in scored_rows),
            "ge_0_50": sum(item["malicious_probability"] >= 0.50 for item in scored_rows),
        },
        "rule_bands": {
            "ge_60": sum(item["rule_score"] >= 60 for item in scored_rows),
            "ge_40": sum(item["rule_score"] >= 40 for item in scored_rows),
            "ge_20": sum(item["rule_score"] >= 20 for item in scored_rows),
        },
        "review_queue_counts": queue_counts,
        "detailed_explanations_generated": len(logistic_explanations),
        "top_suspicious_samples": sorted(
            scored_rows,
            key=lambda item: item["malicious_probability"],
            reverse=True,
        )[:top_k],
    }
    if summary_output is not None:
        summary_output.parent.mkdir(parents=True, exist_ok=True)
        with summary_output.open("w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, ensure_ascii=True)
        logger.info("Wrote inference summary to {}", summary_output)

    if review_queue_summary_output is not None:
        review_queue_summary_output.parent.mkdir(parents=True, exist_ok=True)
        queue_summary = {
            "rows": int(len(review_queue_rows)),
            "queue_counts": queue_counts,
        }
        with review_queue_summary_output.open("w", encoding="utf-8") as handle:
            json.dump(queue_summary, handle, indent=2, ensure_ascii=True)
        logger.info("Wrote inference review queue summary to {}", review_queue_summary_output)

    return summary
