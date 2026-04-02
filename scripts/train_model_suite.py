#!/usr/bin/env python3
"""Train and compare multiple detector stages on a shared split."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from tqdm.auto import tqdm


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.features.extract import build_feature_record
from psdetect.eval import choose_best_model
from psdetect.logging_utils import configure_logging, logger
from psdetect.models.baseline import HybridPowerShellDetector
from psdetect.models.numeric_boost import NumericBoostPowerShellDetector
from psdetect.models.weak_labels import assign_weak_label
from psdetect.review.labels import load_reviewed_labels, resolve_label


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train and compare the detector model suite.")
    parser.add_argument("--input", type=Path, required=True, help="Input JSONL or CSV dataset.")
    parser.add_argument("--text-column", default="text", help="Column containing script text.")
    parser.add_argument("--id-column", default="sample_id", help="Column containing sample id.")
    parser.add_argument("--label-column", default="label", help="Optional label column.")
    parser.add_argument("--reviewed-labels", type=Path, default=None, help="Optional reviewed label store.")
    parser.add_argument("--group-column", default=None, help="Optional group column, e.g. family.")
    parser.add_argument("--split-mode", choices=("random", "group"), default="random", help="Evaluation split strategy.")
    parser.add_argument("--test-size", type=float, default=0.25, help="Evaluation test fraction.")
    parser.add_argument("--parser-backend", choices=("auto", "fallback", "native"), default="auto")
    parser.add_argument("--suite-output", type=Path, default=ROOT / "reports" / "model_suite_report.json")
    parser.add_argument("--logistic-model-output", type=Path, default=ROOT / "models" / "suite_logistic.joblib")
    parser.add_argument("--boost-model-output", type=Path, default=ROOT / "models" / "suite_numeric_boost.joblib")
    parser.add_argument("--trace-output", type=Path, default=ROOT / "outputs" / "model_suite_trace.jsonl")
    parser.add_argument(
        "--selection-objective",
        choices=("recall_first", "balanced"),
        default="recall_first",
        help="How to choose the recommended champion model from the suite.",
    )
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--log-every", type=int, default=5000)
    return parser.parse_args()


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


def map_label(value: object) -> int | None:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    normalized = str(value).strip().lower()
    if normalized in {"benign", "clean", "normal"}:
        return 0
    if normalized in {"malicious", "suspicious", "suspicious_surrogate", "anomalous"}:
        return 1
    return None


def label_name(value: int) -> str:
    return "malicious" if int(value) == 1 else "benign"


def eval_metrics(name: str, true_y: list[int], probs: np.ndarray) -> dict[str, object]:
    preds = (probs >= 0.5).astype(int)
    return {
        "model_name": name,
        "roc_auc": float(roc_auc_score(true_y, probs)),
        "classification_report": classification_report(true_y, preds, digits=4, output_dict=True),
    }


def main() -> int:
    args = parse_args()
    configure_logging(level=args.log_level, log_file=args.log_file)
    logger.info("Loading model suite dataset from {}", args.input)
    df = load_dataframe(args.input)
    logger.info("Loaded {} raw rows", len(df))
    reviewed = load_reviewed_labels(args.reviewed_labels)
    if reviewed:
        logger.info("Loaded {} reviewed labels from {}", len(reviewed), args.reviewed_labels)

    records = []
    rows = []
    labels: list[int] = []
    groups: list[str] = []

    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Building suite records"):
        sample_id = str(row[args.id_column]) if args.id_column in df.columns else f"row-{idx:07d}"
        record = build_feature_record(sample_id=sample_id, text=str(row[args.text_column]), parser_backend=args.parser_backend)
        reviewed_entry = reviewed.get(sample_id)
        label = resolve_label(reviewed_entry.get("final_label")) if reviewed_entry else None
        if label is None:
            label = map_label(row[args.label_column]) if args.label_column in df.columns else None
        if label is None:
            weak = assign_weak_label(record)
            if weak.label == "unknown":
                continue
            label = 1 if weak.label == "suspicious" else 0
        records.append(record)
        rows.append(row.to_dict())
        labels.append(label)
        groups.append(str(row[args.group_column])) if args.group_column and args.group_column in df.columns else groups.append(f"row-group-{idx}")
        if args.log_every and (idx + 1) % args.log_every == 0:
            logger.debug("Prepared {} suite records", idx + 1)

    if args.split_mode == "group":
        splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=42)
        train_idx, test_idx = next(splitter.split(np.arange(len(records)), labels, groups=groups))
    else:
        train_idx, test_idx = train_test_split(
            np.arange(len(records)),
            test_size=args.test_size,
            random_state=42,
            stratify=labels,
        )

    train_records = [records[i] for i in train_idx]
    test_records = [records[i] for i in test_idx]
    train_y = [labels[i] for i in train_idx]
    test_y = [labels[i] for i in test_idx]
    test_rows = [rows[i] for i in test_idx]

    logger.info("Training logistic baseline model")
    logistic = HybridPowerShellDetector().fit(train_records, train_y)
    logistic_probs = logistic.predict_proba(test_records)[:, 1]

    logger.info("Training numeric boost model")
    boost = NumericBoostPowerShellDetector(backend="auto").fit(train_records, train_y)
    boost_probs = boost.predict_proba(test_records)[:, 1]

    ensemble_probs = (logistic_probs + boost_probs) / 2.0
    rule_probs = np.array([min(0.99, record.rules.risk_score / 100.0) for record in test_records], dtype=float)

    metrics = {
        "logistic": eval_metrics("logistic", test_y, logistic_probs),
        "numeric_boost": eval_metrics(f"numeric_boost_{boost.backend}", test_y, boost_probs),
        "rule_engine": eval_metrics("rule_engine", test_y, rule_probs),
        "ensemble_avg": eval_metrics("ensemble_avg", test_y, ensemble_probs),
    }

    args.logistic_model_output.parent.mkdir(parents=True, exist_ok=True)
    logistic.save(str(args.logistic_model_output))
    args.boost_model_output.parent.mkdir(parents=True, exist_ok=True)
    boost.save(str(args.boost_model_output))

    trace_rows = []
    for row, record, y_true, p_lr, p_boost, p_ens in zip(test_rows, test_records, test_y, logistic_probs, boost_probs, ensemble_probs):
        trace_rows.append(
            {
                **row,
                "sample_id": record.sample_id,
                "true_label": label_name(y_true),
                "analysis_text": record.normalized.analysis_text,
                "malicious_probability_logistic": round(float(p_lr), 6),
                "malicious_probability_boost": round(float(p_boost), 6),
                "malicious_probability_ensemble": round(float(p_ens), 6),
                "rule_score": record.rules.risk_score,
                "matched_rule_ids": record.rules.matched_rule_ids,
                "matched_techniques": record.rules.matched_techniques,
                "weak_label": assign_weak_label(record).label,
            }
        )

    args.trace_output.parent.mkdir(parents=True, exist_ok=True)
    with args.trace_output.open("w", encoding="utf-8") as handle:
        for item in trace_rows:
            handle.write(json.dumps(item, ensure_ascii=True) + "\n")

    suite_report = {
        "input": str(args.input),
        "rows_loaded": int(len(df)),
        "usable_rows": int(len(records)),
        "split_mode": args.split_mode,
        "group_column": args.group_column,
        "train_rows": int(len(train_records)),
        "test_rows": int(len(test_records)),
        "train_label_counts": dict(Counter(label_name(v) for v in train_y)),
        "test_label_counts": dict(Counter(label_name(v) for v in test_y)),
        "models": metrics,
        "selection": choose_best_model(metrics, objective=args.selection_objective),
        "boost_backend": boost.backend,
        "top_ensemble_examples": sorted(
            trace_rows, key=lambda item: item["malicious_probability_ensemble"], reverse=True
        )[:25],
    }

    args.suite_output.parent.mkdir(parents=True, exist_ok=True)
    with args.suite_output.open("w", encoding="utf-8") as handle:
        json.dump(suite_report, handle, indent=2, ensure_ascii=True)

    logger.info("Saved logistic model to {}", args.logistic_model_output)
    logger.info("Saved numeric boost model to {}", args.boost_model_output)
    logger.info("Saved suite trace to {}", args.trace_output)
    logger.info("Saved suite report to {}", args.suite_output)
    logger.info("Suite ROC-AUCs: {}", {name: round(info["roc_auc"], 4) for name, info in metrics.items()})
    logger.info(
        "Recommended champion under {}: {}",
        args.selection_objective,
        suite_report["selection"]["winner"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
