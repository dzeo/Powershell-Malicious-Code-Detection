#!/usr/bin/env python3
"""Initialize an empty reviewed-label store."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize an empty reviewed-label store.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/review/reviewed_labels.jsonl"),
        help="Reviewed label store path.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not args.output.exists():
        args.output.write_text("", encoding="utf-8")

    schema = {
        "sample_id": "required stable sample id",
        "final_label": "benign | malicious | unknown",
        "confidence": "high | medium | low",
        "reviewer": "analyst name or id",
        "reviewed_at": "ISO-8601 timestamp",
        "rationale": "short analyst rationale",
        "family_override": "optional attack family label",
        "source": "manual_review | external_truth | incident_response",
    }
    print(f"Initialized reviewed-label store at {args.output}")
    print(json.dumps(schema, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
