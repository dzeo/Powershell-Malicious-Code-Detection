#!/usr/bin/env python3
"""Single-command incremental pipeline runner."""

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
from psdetect.pipeline.incremental import IncrementalPipelineConfig, run_incremental_training


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the full incremental PowerShell detection pipeline.")
    parser.add_argument("--input", type=Path, required=True, help="Input training dataset (JSONL or CSV).")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "runs" / "incremental_pipeline",
        help="Directory where all phase outputs and final artifacts are written.",
    )
    parser.add_argument("--text-column", default="text", help="Column containing script text.")
    parser.add_argument("--id-column", default="sample_id", help="Column containing sample id.")
    parser.add_argument("--label-column", default="label", help="Optional label column.")
    parser.add_argument("--group-column", default=None, help="Optional group column.")
    parser.add_argument("--reviewed-labels", type=Path, default=None, help="Optional reviewed-label store.")
    parser.add_argument("--parser-backend", choices=("auto", "fallback", "native"), default="auto")
    parser.add_argument(
        "--phase-fractions",
        default="0.1,0.5,1.0",
        help="Comma-separated cumulative fractions, e.g. 0.1,0.5,1.0",
    )
    parser.add_argument("--validation-fraction", type=float, default=0.2, help="Validation fraction within each phase.")
    parser.add_argument("--malicious-threshold", type=float, default=0.97, help="Auto-relabel malicious threshold.")
    parser.add_argument("--benign-threshold", type=float, default=0.03, help="Auto-relabel benign threshold.")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--log-every", type=int, default=5000)
    return parser.parse_args()


def _parse_phase_fractions(raw: str) -> tuple[float, ...]:
    fractions = tuple(float(item.strip()) for item in raw.split(",") if item.strip())
    if not fractions:
        raise ValueError("At least one phase fraction is required.")
    for value in fractions:
        if not 0.0 < value <= 1.0:
            raise ValueError(f"Invalid phase fraction: {value}")
    return fractions


def main() -> int:
    args = parse_args()
    configure_logging(level=args.log_level, log_file=args.log_file)
    fractions = _parse_phase_fractions(args.phase_fractions)
    config = IncrementalPipelineConfig(
        input_path=args.input,
        output_dir=args.output_dir,
        text_column=args.text_column,
        id_column=args.id_column,
        label_column=args.label_column,
        group_column=args.group_column,
        reviewed_labels_path=args.reviewed_labels,
        parser_backend=args.parser_backend,
        phase_fractions=fractions,
        validation_fraction=args.validation_fraction,
        malicious_threshold=args.malicious_threshold,
        benign_threshold=args.benign_threshold,
        log_every=args.log_every,
    )
    logger.info("Starting single-command incremental pipeline")
    artifact = run_incremental_training(config)
    logger.info("Incremental pipeline complete")
    logger.info("Final artifact: {}", json.dumps(artifact, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
