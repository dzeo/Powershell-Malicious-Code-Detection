#!/usr/bin/env python3
"""Generate safe synthetic PowerShell-like samples for pipeline testing."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.generation.synthetic import generate_dataset, write_csv, write_jsonl
from psdetect.logging_utils import configure_logging, logger


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate safe synthetic PowerShell-like samples. "
            "Suspicious outputs are non-operational surrogates for testing."
        )
    )
    parser.add_argument(
        "--total",
        type=int,
        default=1000,
        help="Total number of samples to generate.",
    )
    parser.add_argument(
        "--benign-ratio",
        type=float,
        default=0.6,
        help="Fraction of benign samples in the output.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed.",
    )
    parser.add_argument(
        "--format",
        choices=("jsonl", "csv"),
        default="jsonl",
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data" / "synthetic" / "synthetic_samples.jsonl",
        help="Destination file path.",
    )
    parser.add_argument("--log-level", default="INFO", help="Logging level.")
    parser.add_argument("--log-file", default=None, help="Optional log file path.")
    parser.add_argument("--log-every", type=int, default=10000, help="Emit debug progress every N rows.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(level=args.log_level, log_file=args.log_file)
    logger.info("Starting synthetic dataset generation")
    samples = generate_dataset(
        total=args.total,
        benign_ratio=args.benign_ratio,
        seed=args.seed,
        show_progress=True,
        log_every=args.log_every,
    )

    if args.format == "csv":
        write_csv(samples, args.output, show_progress=True, total=len(samples))
    else:
        write_jsonl(samples, args.output, show_progress=True, total=len(samples))

    logger.info(
        "Generated {} samples at {} with benign_ratio={:.2f}",
        len(samples),
        args.output,
        args.benign_ratio,
    )
    logger.warning("Suspicious rows are safe surrogates, not deployable malware.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
