#!/usr/bin/env python3
"""Train a baseline hybrid detector on labeled or weakly labeled data."""

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
from psdetect.logging_utils import configure_logging, logger
from psdetect.models.baseline import HybridPowerShellDetector
from psdetect.models.weak_labels import assign_weak_label
from psdetect.review.labels import load_reviewed_labels, resolve_label


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the PowerShell baseline detector.")
    parser.add_argument("--input", type=Path, required=True, help="Input JSONL or CSV dataset.")
    parser.add_argument(
        "--model-output",
        type=Path,
        default=ROOT / "models" / "hybrid_detector.joblib",
        help="Where to save the trained model.",
    )
    parser.add_argument(
        "--text-column",
        default="text",
        help="Column containing the PowerShell text.",
    )
    parser.add_argument(
        "--id-column",
        default="sample_id",
        help="Column containing a stable sample identifier.",
    )
    parser.add_argument(
        "--label-column",
        default="label",
        help="Optional label column. If missing, weak labels are generated.",
    )
    parser.add_argument(
        "--reviewed-labels",
        type=Path,
        default=None,
        help="Optional reviewed-label store. Reviewed labels override input and weak labels.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.25,
        help="Fraction of rows used for evaluation.",
    )
    parser.add_argument(
        "--group-column",
        default=None,
        help="Optional group column for harder holdout splits, e.g. family.",
    )
    parser.add_argument(
        "--split-mode",
        choices=("random", "group"),
        default="random",
        help="Evaluation split strategy.",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=None,
        help="Optional JSON report output path.",
    )
    parser.add_argument(
        "--trace-output",
        type=Path,
        default=None,
        help="Optional JSONL trace output for evaluated samples.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=15,
        help="Top false positives and false negatives to include in the report.",
    )
    parser.add_argument(
        "--parser-backend",
        choices=("auto", "fallback", "native"),
        default="auto",
        help="Parser backend selection.",
    )
    parser.add_argument("--log-level", default="INFO", help="Logging level.")
    parser.add_argument("--log-file", default=None, help="Optional log file path.")
    parser.add_argument("--log-every", type=int, default=5000, help="Emit debug progress every N rows.")
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


def _label_name(value: int) -> str:
    return "malicious" if value == 1 else "benign"


def _build_trace_row(
    row: dict[str, object],
    record,
    true_label: int,
    pred_label: int,
    probability: float,
    weak,
    explanation: dict[str, object],
) -> dict[str, object]:
    return {
        **row,
        "sample_id": record.sample_id,
        "analysis_text": record.normalized.analysis_text,
        "decoded_text": record.normalized.decoded_text,
        "transforms": record.normalized.transforms,
        "parser_backend": record.parsed.backend,
        "commands": record.parsed.commands,
        "parameters": record.parsed.parameters,
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
        "true_label": _label_name(true_label),
        "predicted_label": _label_name(pred_label),
        "malicious_probability": round(float(probability), 6),
        "weak_label": weak.label,
        "weak_confidence": round(float(weak.confidence), 4),
        "weak_rationale": weak.rationale,
        "top_model_contributions": explanation["top_model_contributions"],
        "top_numeric_signals": explanation["top_numeric_signals"],
    }


def main() -> int:
    args = parse_args()
    configure_logging(level=args.log_level, log_file=args.log_file)
    logger.info("[1/5] Loading dataset from {}", args.input)
    df = load_dataframe(args.input)
    if args.text_column not in df.columns:
        raise ValueError(f"Missing text column: {args.text_column}")
    logger.info("Loaded {} raw rows", len(df))

    records = []
    raw_rows: list[dict[str, object]] = []
    labels: list[int] = []
    groups: list[str] = []
    weak_labels_used = 0
    reviewed_labels_used = 0
    input_labels_used = 0
    reviewed = load_reviewed_labels(args.reviewed_labels)
    if reviewed:
        logger.info("Loaded {} reviewed labels from {}", len(reviewed), args.reviewed_labels)

    logger.info("[2/5] Building feature records")
    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Building training records"):
        sample_id = str(row[args.id_column]) if args.id_column in df.columns else f"row-{idx:07d}"
        record = build_feature_record(
            sample_id=sample_id,
            text=str(row[args.text_column]),
            parser_backend=args.parser_backend,
        )
        reviewed_entry = reviewed.get(sample_id)
        label = resolve_label(reviewed_entry.get("final_label")) if reviewed_entry else None
        if label is not None:
            reviewed_labels_used += 1
        else:
            label = map_label(row[args.label_column]) if args.label_column in df.columns else None
            if label is not None:
                input_labels_used += 1
        if label is None:
            weak = assign_weak_label(record)
            if weak.label == "unknown":
                if args.log_every and (idx + 1) % args.log_every == 0:
                    logger.debug("Skipping sample_id={} due to unknown weak label", sample_id)
                continue
            label = 1 if weak.label == "suspicious" else 0
            weak_labels_used += 1
        records.append(record)
        raw_rows.append(row.to_dict())
        labels.append(label)
        if args.group_column and args.group_column in df.columns:
            groups.append(str(row[args.group_column]))
        else:
            groups.append(f"row-group-{idx}")
        if args.log_every and (idx + 1) % args.log_every == 0:
            logger.debug(
                "Processed {} rows; latest sample_id={}, label={}, transforms={}, parser_backend={}",
                idx + 1,
                sample_id,
                label,
                record.normalized.transforms,
                record.parsed.backend,
            )

    if len(set(labels)) < 2:
        raise ValueError("Need at least two classes after label preparation.")

    logger.info("[3/5] Splitting dataset")
    if args.split_mode == "group":
        if not args.group_column:
            raise ValueError("--split-mode group requires --group-column")
        unique_groups = set(groups)
        if len(unique_groups) < 2:
            raise ValueError("Group split requires at least two distinct groups.")

        splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=42)
        train_idx, test_idx = next(splitter.split(np.arange(len(records)), labels, groups=groups))
        train_records = [records[i] for i in train_idx]
        test_records = [records[i] for i in test_idx]
        train_y = [labels[i] for i in train_idx]
        test_y = [labels[i] for i in test_idx]
        train_rows = [raw_rows[i] for i in train_idx]
        test_rows = [raw_rows[i] for i in test_idx]
        train_groups = [groups[i] for i in train_idx]
        test_groups = [groups[i] for i in test_idx]
    else:
        split_items = train_test_split(
            records,
            raw_rows,
            labels,
            groups,
            test_size=args.test_size,
            random_state=42,
            stratify=labels,
        )
        train_records, test_records, train_rows, test_rows, train_y, test_y, train_groups, test_groups = split_items

    logger.info(
        "Split summary: train_rows={}, test_rows={}, train_groups={}, test_groups={}, overlap={}",
        len(train_records),
        len(test_records),
        len(set(train_groups)),
        len(set(test_groups)),
        len(set(train_groups) & set(test_groups)),
    )

    logger.info("[4/5] Training model")
    model = HybridPowerShellDetector().fit(train_records, train_y)
    logger.info("[5/5] Evaluating model")
    probs = model.predict_proba(test_records)[:, 1]
    preds = (probs >= 0.5).astype(int)
    explanations = model.explain(test_records, top_k=min(args.top_k, 10))

    logger.info("Prepared {} usable samples", len(records))
    logger.info("Weak labels used: {}", weak_labels_used)
    logger.info("Input labels used: {}", input_labels_used)
    logger.info("Reviewed labels used: {}", reviewed_labels_used)
    logger.info("Split mode: {}", args.split_mode)
    if args.group_column:
        logger.info("Group column: {}", args.group_column)
        logger.info("Unique train groups: {}", len(set(train_groups)))
        logger.info("Unique test groups: {}", len(set(test_groups)))
        logger.info("Group overlap: {}", len(set(train_groups) & set(test_groups)))
    report_text = classification_report(test_y, preds, digits=4)
    logger.info("Classification report:\n{}", report_text)
    logger.info("ROC-AUC: {:.4f}", roc_auc_score(test_y, probs))

    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(args.model_output))
    logger.info("Saved model to {}", args.model_output)

    if args.trace_output or args.report_output:
        trace_rows = []
        for row, record, true_label, pred_label, prob, explanation in zip(
            test_rows, test_records, test_y, preds, probs, explanations
        ):
            weak = assign_weak_label(record)
            trace_rows.append(
                _build_trace_row(
                    row=row,
                    record=record,
                    true_label=int(true_label),
                    pred_label=int(pred_label),
                    probability=float(prob),
                    weak=weak,
                    explanation=explanation,
                )
            )

        if args.trace_output:
            args.trace_output.parent.mkdir(parents=True, exist_ok=True)
            with args.trace_output.open("w", encoding="utf-8") as handle:
                for item in tqdm(trace_rows, total=len(trace_rows), desc="Writing evaluation trace"):
                    handle.write(json.dumps(item, ensure_ascii=True) + "\n")
            logger.info("Saved evaluation trace to {}", args.trace_output)

        if args.report_output:
            args.report_output.parent.mkdir(parents=True, exist_ok=True)
            fp_rows = [item for item in trace_rows if item["true_label"] == "benign" and item["predicted_label"] == "malicious"]
            fn_rows = [item for item in trace_rows if item["true_label"] == "malicious" and item["predicted_label"] == "benign"]
            fp_rows = sorted(fp_rows, key=lambda item: item["malicious_probability"], reverse=True)[: args.top_k]
            fn_rows = sorted(fn_rows, key=lambda item: item["malicious_probability"])[: args.top_k]

            family_counter = Counter(str(item.get(args.group_column, "NA")) for item in test_rows) if args.group_column else {}
            report = {
                "input": str(args.input),
                "rows_loaded": int(len(df)),
                "usable_rows": int(len(records)),
                "weak_labels_used": int(weak_labels_used),
                "input_labels_used": int(input_labels_used),
                "reviewed_labels_used": int(reviewed_labels_used),
                "split_mode": args.split_mode,
                "group_column": args.group_column,
                "train_rows": int(len(train_records)),
                "test_rows": int(len(test_records)),
                "train_label_counts": dict(Counter(_label_name(int(v)) for v in train_y)),
                "test_label_counts": dict(Counter(_label_name(int(v)) for v in test_y)),
                "train_group_count": int(len(set(train_groups))),
                "test_group_count": int(len(set(test_groups))),
                "group_overlap": int(len(set(train_groups) & set(test_groups))),
                "test_group_distribution": dict(family_counter),
                "classification_report": classification_report(
                    test_y, preds, digits=4, output_dict=True
                ),
                "roc_auc": float(roc_auc_score(test_y, probs)),
                "rule_band_counts": {
                    "ge_60": int(sum(item["rule_score"] >= 60 for item in trace_rows)),
                    "ge_40": int(sum(item["rule_score"] >= 40 for item in trace_rows)),
                    "ge_20": int(sum(item["rule_score"] >= 20 for item in trace_rows)),
                },
                "top_false_positives": fp_rows,
                "top_false_negatives": fn_rows,
                "top_scored_examples": sorted(
                    trace_rows, key=lambda item: item["malicious_probability"], reverse=True
                )[: args.top_k],
            }
            with args.report_output.open("w", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, ensure_ascii=True)
            logger.info("Saved training report to {}", args.report_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
