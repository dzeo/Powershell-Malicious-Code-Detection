#!/usr/bin/env python3
"""Prepare a PowerShell corpus for large-scale modeling."""

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

from psdetect.data.prepare import prepare_dataframe
from psdetect.logging_utils import configure_logging, logger


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare a corpus for training and scoring.")
    parser.add_argument("--input", type=Path, required=True, help="Input JSONL or CSV dataset.")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data" / "staging" / "prepared_corpus.jsonl",
        help="Prepared output JSONL file.",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=ROOT / "data" / "staging" / "prepared_manifest.json",
        help="Manifest summary JSON path.",
    )
    parser.add_argument("--text-column", default="text", help="Column containing script text.")
    parser.add_argument("--id-column", default="sample_id", help="Column containing sample id.")
    parser.add_argument(
        "--timestamp-column",
        default=None,
        help="Optional timestamp column for time-aware splitting.",
    )
    parser.add_argument(
        "--metadata-columns",
        nargs="*",
        default=[],
        help="Additional metadata columns to carry through preparation.",
    )
    parser.add_argument(
        "--parser-backend",
        choices=("auto", "fallback", "native"),
        default="auto",
        help="Parser backend selection.",
    )
    parser.add_argument("--log-level", default="INFO", help="Logging level.")
    parser.add_argument("--log-file", default=None, help="Optional log file path.")
    parser.add_argument("--log-every", type=int, default=10000, help="Emit debug progress every N rows.")
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
    logger.info("Loading corpus from {}", args.input)
    df = load_dataframe(args.input)
    prepared, manifest = prepare_dataframe(
        df,
        text_column=args.text_column,
        id_column=args.id_column,
        timestamp_column=args.timestamp_column,
        metadata_columns=args.metadata_columns,
        parser_backend=args.parser_backend,
        show_progress=True,
        log_every=args.log_every,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Writing prepared corpus to {}", args.output)
    prepared.to_json(args.output, orient="records", lines=True, force_ascii=True)

    args.manifest_output.parent.mkdir(parents=True, exist_ok=True)
    with args.manifest_output.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)

    logger.info("Prepared {} rows at {}", manifest["rows_out"], args.output)
    logger.info("Manifest written to {}", args.manifest_output)
    logger.info("Manifest summary: {}", json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
