#!/usr/bin/env python3
"""Generate synthetic data, train the baseline detector, score it, and emit a report."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
from tqdm.auto import tqdm


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.features.extract import build_feature_record
from psdetect.generation.synthetic import generate_dataset, write_jsonl
from psdetect.logging_utils import configure_logging, logger
from psdetect.models.baseline import HybridPowerShellDetector
from psdetect.models.weak_labels import assign_weak_label


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the full synthetic evaluation pipeline.")
    parser.add_argument("--total", type=int, default=10000, help="Total synthetic rows.")
    parser.add_argument("--benign-ratio", type=float, default=0.6, help="Benign fraction.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    parser.add_argument(
        "--dataset-output",
        type=Path,
        default=ROOT / "data" / "synthetic" / "synthetic_eval.jsonl",
        help="Synthetic dataset path.",
    )
    parser.add_argument(
        "--model-output",
        type=Path,
        default=ROOT / "models" / "synthetic_eval_detector.joblib",
        help="Trained model output path.",
    )
    parser.add_argument(
        "--scores-output",
        type=Path,
        default=ROOT / "outputs" / "synthetic_eval_scores.jsonl",
        help="Per-row scored output path.",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=ROOT / "reports" / "synthetic_eval_report.json",
        help="Summary report path.",
    )
    parser.add_argument("--top-k", type=int, default=15, help="Top suspicious rows to include in the report.")
    parser.add_argument("--log-level", default="INFO", help="Logging level.")
    parser.add_argument("--log-file", default=None, help="Optional log file path.")
    parser.add_argument("--log-every", type=int, default=5000, help="Emit debug progress every N rows.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(level=args.log_level, log_file=args.log_file)
    logger.info("Starting synthetic evaluation workflow")
    samples = generate_dataset(
        total=args.total,
        benign_ratio=args.benign_ratio,
        seed=args.seed,
        show_progress=True,
        log_every=args.log_every,
    )
    args.dataset_output.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(samples, args.dataset_output, show_progress=True, total=len(samples))

    records = []
    for idx, sample in enumerate(tqdm(samples, total=len(samples), desc="Building feature records")):
        records.append(build_feature_record(sample.sample_id, sample.text))
        if args.log_every and (idx + 1) % args.log_every == 0:
            logger.debug("Built {} feature records in synthetic evaluation", idx + 1)
    labels = [0 if sample.label == "benign" else 1 for sample in samples]
    model = HybridPowerShellDetector().fit(records, labels)
    probabilities = model.predict_proba(records)[:, 1]
    explanations = model.explain(records, top_k=8)
    explanation_by_id = {item["sample_id"]: item for item in explanations}

    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    model.save(str(args.model_output))
    logger.info("Saved model to {}", args.model_output)

    args.scores_output.parent.mkdir(parents=True, exist_ok=True)
    score_rows = []
    logger.info("Writing synthetic evaluation scores to {}", args.scores_output)
    with args.scores_output.open("w", encoding="utf-8") as handle:
        for sample, record, probability in tqdm(
            zip(samples, records, probabilities),
            total=len(samples),
            desc="Writing evaluation scores",
        ):
            weak = assign_weak_label(record)
            payload = {
                "sample_id": sample.sample_id,
                "true_label": sample.label,
                "family": sample.family,
                "text": sample.text,
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
                "malicious_probability": round(float(probability), 6),
                "weak_label": weak.label,
                "weak_confidence": round(weak.confidence, 4),
                "weak_rationale": weak.rationale,
                "top_model_contributions": explanation_by_id[sample.sample_id]["top_model_contributions"],
                "top_numeric_signals": explanation_by_id[sample.sample_id]["top_numeric_signals"],
            }
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
            score_rows.append(payload)

    df = pd.DataFrame(score_rows)
    top_rows = df.sort_values("malicious_probability", ascending=False).head(args.top_k)
    weak_counts = Counter(df["weak_label"])
    family_counts = Counter(df["family"])
    predicted_counts = {
        "ge_0_90": int((df["malicious_probability"] >= 0.90).sum()),
        "ge_0_75": int((df["malicious_probability"] >= 0.75).sum()),
        "ge_0_50": int((df["malicious_probability"] >= 0.50).sum()),
    }

    report = {
        "rows": int(len(df)),
        "benign_ratio": args.benign_ratio,
        "model_output": str(args.model_output),
        "scores_output": str(args.scores_output),
        "weak_label_counts": dict(weak_counts),
        "family_counts": dict(family_counts),
        "prediction_bands": predicted_counts,
        "rule_bands": {
            "ge_60": int((df["rule_score"] >= 60).sum()),
            "ge_40": int((df["rule_score"] >= 40).sum()),
            "ge_20": int((df["rule_score"] >= 20).sum()),
        },
        "top_suspicious_samples": top_rows[
            [
                "sample_id",
                "true_label",
                "family",
                "malicious_probability",
                "rule_score",
                "matched_rule_ids",
                "analysis_text",
                "weak_label",
                "weak_rationale",
                "top_model_contributions",
                "top_numeric_signals",
            ]
        ].to_dict(orient="records"),
    }

    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    with args.report_output.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)

    logger.info("Generated dataset: {}", args.dataset_output)
    logger.info("Saved model: {}", args.model_output)
    logger.info("Saved scores: {}", args.scores_output)
    logger.info("Saved report: {}", args.report_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
