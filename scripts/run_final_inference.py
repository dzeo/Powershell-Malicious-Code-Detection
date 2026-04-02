#!/usr/bin/env python3
"""Run inference on unknown data using a saved incremental-pipeline artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.logging_utils import configure_logging, logger
from psdetect.pipeline.incremental import run_final_inference


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score unknown data with a saved final pipeline artifact.")
    parser.add_argument("--artifact", type=Path, required=True, help="Path to final_artifact.json.")
    parser.add_argument("--input", type=Path, required=True, help="Input dataset to score (JSONL or CSV).")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "outputs" / "final_inference_scores.jsonl",
        help="Destination JSONL for scored rows.",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=ROOT / "reports" / "final_inference_summary.json",
        help="Destination JSON summary.",
    )
    parser.add_argument(
        "--review-queue-output",
        type=Path,
        default=ROOT / "data" / "review" / "final_inference_queue.jsonl",
        help="Optional review queue export path.",
    )
    parser.add_argument(
        "--review-queue-summary-output",
        type=Path,
        default=ROOT / "data" / "review" / "final_inference_queue_summary.json",
        help="Optional review queue summary export path.",
    )
    parser.add_argument("--text-column", default="text", help="Column containing script text.")
    parser.add_argument("--id-column", default="sample_id", help="Column containing sample id.")
    parser.add_argument("--parser-backend", choices=("auto", "fallback", "native"), default=None)
    parser.add_argument("--top-k", type=int, default=10, help="Top suspicious rows and explanations to retain.")
    parser.add_argument(
        "--explain-top-n",
        type=int,
        default=500,
        help="Generate detailed explanations only for the top N highest-risk rows. Use 0 to disable.",
    )
    parser.add_argument(
        "--explain-all",
        action="store_true",
        help="Generate detailed explanations for every row. This is expensive on large datasets.",
    )
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--log-every", type=int, default=5000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(level=args.log_level, log_file=args.log_file)
    logger.info("Starting final-artifact inference")
    summary = run_final_inference(
        artifact_path=args.artifact,
        input_path=args.input,
        output_path=args.output,
        summary_output=args.summary_output,
        review_queue_output=args.review_queue_output,
        review_queue_summary_output=args.review_queue_summary_output,
        text_column=args.text_column,
        id_column=args.id_column,
        parser_backend=args.parser_backend,
        top_k=args.top_k,
        explain_top_n=args.explain_top_n,
        explain_all=args.explain_all,
        log_every=args.log_every,
    )
    logger.info("Final-artifact inference complete")
    logger.info("Inference summary: {}", json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
