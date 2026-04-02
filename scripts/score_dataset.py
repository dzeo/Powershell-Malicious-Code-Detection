#!/usr/bin/env python3
"""Score a dataset with a trained hybrid detector."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd
from tqdm.auto import tqdm


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.features.extract import build_feature_record
from psdetect.logging_utils import configure_logging, logger
from psdetect.models.baseline import HybridPowerShellDetector
from psdetect.models.weak_labels import assign_weak_label


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score a dataset with the baseline detector.")
    parser.add_argument("--input", type=Path, required=True, help="Input JSONL or CSV dataset.")
    parser.add_argument("--model", type=Path, required=True, help="Trained model path.")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "outputs" / "scored_samples.jsonl",
        help="Destination JSONL file with scores.",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=None,
        help="Optional summary JSON output path.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=10,
        help="Top model contributions and summary rows to keep.",
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
    parser.add_argument("--text-column", default="text", help="Column containing the script text.")
    parser.add_argument("--id-column", default="sample_id", help="Column containing the sample id.")
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


def main() -> int:
    args = parse_args()
    configure_logging(level=args.log_level, log_file=args.log_file)
    logger.info("Loading scoring dataset from {}", args.input)
    df = load_dataframe(args.input)
    logger.info("Loaded {} rows for scoring", len(df))
    model = HybridPowerShellDetector.load(str(args.model))
    logger.info("Loaded model from {}", args.model)

    records = []
    rows = []
    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Building score records"):
        sample_id = str(row[args.id_column]) if args.id_column in df.columns else f"row-{idx:07d}"
        text = str(row[args.text_column])
        record = build_feature_record(sample_id=sample_id, text=text, parser_backend=args.parser_backend)
        records.append(record)
        rows.append(row.to_dict())
        if args.log_every and (idx + 1) % args.log_every == 0:
            logger.debug(
                "Built {} scoring records so far; latest sample_id={}, transforms={}",
                idx + 1,
                sample_id,
                record.normalized.transforms,
            )

    scores = model.predict_proba(records)[:, 1]
    explanations = model.explain(records, top_k=args.top_k)
    explanation_by_id = {item["sample_id"]: item for item in explanations}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    scored_rows = []
    logger.info("Writing scored dataset to {}", args.output)
    with args.output.open("w", encoding="utf-8") as handle:
        for row, record, score in tqdm(
            zip(rows, records, scores),
            total=len(records),
            desc="Writing scored rows",
        ):
            weak = assign_weak_label(record)
            explanation = explanation_by_id[record.sample_id]
            payload = {
                **row,
                "sample_id": record.sample_id,
                "malicious_probability": round(float(score), 6),
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
                "weak_label": weak.label,
                "weak_confidence": round(weak.confidence, 4),
                "weak_rationale": weak.rationale,
                "top_model_contributions": explanation["top_model_contributions"],
                "top_numeric_signals": explanation["top_numeric_signals"],
            }
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
            scored_rows.append(payload)

    logger.info("Scored {} rows and wrote results to {}", len(records), args.output)
    if args.summary_output is not None:
        ranked = sorted(scored_rows, key=lambda item: item["malicious_probability"], reverse=True)
        summary = {
            "rows": len(scored_rows),
            "prediction_bands": {
                "ge_0_90": sum(item["malicious_probability"] >= 0.90 for item in scored_rows),
                "ge_0_75": sum(item["malicious_probability"] >= 0.75 for item in scored_rows),
                "ge_0_50": sum(item["malicious_probability"] >= 0.50 for item in scored_rows),
            },
            "rule_bands": {
                "ge_60": sum(item["rule_score"] >= 60 for item in scored_rows),
                "ge_40": sum(item["rule_score"] >= 40 for item in scored_rows),
                "ge_20": sum(item["rule_score"] >= 20 for item in scored_rows),
            },
            "top_suspicious_samples": ranked[: args.top_k],
        }
        args.summary_output.parent.mkdir(parents=True, exist_ok=True)
        with args.summary_output.open("w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, ensure_ascii=True)
        logger.info("Wrote summary report to {}", args.summary_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
