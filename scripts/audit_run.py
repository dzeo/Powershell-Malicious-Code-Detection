#!/usr/bin/env python3
"""Audit an incremental pipeline run directory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.eval import audit_run


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit a pipeline run for misleading or low-value results.")
    parser.add_argument("run_dir", type=Path, help="Run directory, for example runs/test_2")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional JSON output path. Defaults to <run_dir>/audit_report.json",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = audit_run(args.run_dir)
    output_path = args.output or (args.run_dir / "audit_report.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)

    print(f"Verdict: {report['overall_verdict']}")
    print(f"Report: {output_path}")
    for finding in report["findings"]:
        print(f"[{finding['severity'].upper()}] {finding['title']}: {finding['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
