"""Reviewed label store helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


LABEL_TO_INT = {
    "benign": 0,
    "clean": 0,
    "normal": 0,
    "malicious": 1,
    "suspicious": 1,
    "anomalous": 1,
}


def load_reviewed_labels(path: Path | None) -> dict[str, dict[str, object]]:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"Reviewed labels file not found: {path}")

    rows: list[dict[str, object]] = []
    if path.suffix.lower() == ".jsonl":
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    elif path.suffix.lower() == ".csv":
        rows = pd.read_csv(path).to_dict(orient="records")
    else:
        raise ValueError(f"Unsupported reviewed label format: {path.suffix}")

    reviewed: dict[str, dict[str, object]] = {}
    for row in rows:
        sample_id = str(row.get("sample_id", "")).strip()
        if not sample_id:
            continue
        reviewed[sample_id] = row
    return reviewed


def resolve_label(value: object) -> int | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    return LABEL_TO_INT.get(normalized)

