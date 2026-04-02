#!/usr/bin/env python3
"""Export analyst review queues from scored samples."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.logging_utils import configure_logging, logger
from psdetect.review.queue import QueueThresholds, build_review_queue


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export review queues from scored samples.")
    parser.add_argument("--input", type=Path, required=True, help="Scored JSONL or CSV input.")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data" / "review" / "review_queue.jsonl",
        help="Review queue JSONL output.",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=ROOT / "data" / "review" / "review_queue_summary.json",
        help="Summary JSON output.",
    )
    parser.add_argument("--max-per-queue", type=int, default=500, help="Maximum rows per queue.")
    parser.add_argument("--log-level", default="INFO", help="Logging level.")
    parser.add_argument("--log-file", default=None, help="Optional log file path.")
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
    logger.info("Loading scored samples from {}", args.input)
    df = load_dataframe(args.input)
    logger.info("Loaded {} scored rows", len(df))

    queue_df = build_review_queue(df, thresholds=QueueThresholds(), max_per_queue=args.max_per_queue)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    queue_df.to_json(args.output, orient="records", lines=True, force_ascii=True)

    summary = {
        "rows_in": int(len(df)),
        "rows_queued": int(len(queue_df)),
        "queues": queue_df["review_queue"].value_counts(dropna=False).to_dict() if not queue_df.empty else {},
        "reasons": queue_df["review_reason"].value_counts(dropna=False).to_dict() if not queue_df.empty else {},
    }
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    with args.summary_output.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=True)

    logger.info("Wrote review queue to {}", args.output)
    logger.info("Wrote review queue summary to {}", args.summary_output)
    logger.info("Queue summary: {}", json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

