from pathlib import Path
import sys

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.data.prepare import prepare_dataframe


def test_prepare_dataframe_deduplicates_decoded_content_and_splits():
    df = pd.DataFrame(
        [
            {
                "sample_id": "a",
                "text": "powershell -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEgAZQBsAGwAbwAnAA==",
                "timestamp": "2026-01-01T00:00:00Z",
            },
            {
                "sample_id": "b",
                "text": "Write-Output 'Hello'",
                "timestamp": "2026-02-01T00:00:00Z",
            },
            {
                "sample_id": "c",
                "text": "Get-Service -Name 'BITS'",
                "timestamp": "2026-03-01T00:00:00Z",
            },
        ]
    )

    prepared, manifest = prepare_dataframe(
        df,
        text_column="text",
        id_column="sample_id",
        timestamp_column="timestamp",
        parser_backend="fallback",
    )

    assert len(prepared) == 3
    assert manifest["rows_in"] == 3
    assert manifest["unique_analysis"] == 2
    assert prepared["is_duplicate_analysis"].sum() == 1
    assert set(prepared["split"]) <= {"train", "validation", "test"}
    assert "fallback" in manifest["parser_backends"]
