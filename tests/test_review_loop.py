from pathlib import Path
import sys

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.review.labels import load_reviewed_labels, resolve_label
from psdetect.review.queue import build_review_queue


def test_review_queue_builds_priority_buckets():
    df = pd.DataFrame(
        [
            {"sample_id": "a", "malicious_probability": 0.99, "rule_score": 45, "matched_rule_ids": ["x"]},
            {"sample_id": "b", "malicious_probability": 0.20, "rule_score": 50, "matched_rule_ids": ["y"]},
            {"sample_id": "c", "malicious_probability": 0.52, "rule_score": 5, "matched_rule_ids": []},
            {"sample_id": "d", "malicious_probability": 0.02, "rule_score": 0, "matched_rule_ids": []},
        ]
    )

    queue = build_review_queue(df, max_per_queue=10)

    assert not queue.empty
    assert set(queue["review_queue"]) >= {"high_priority", "model_rule_disagreement", "uncertain_band", "control_benign"}


def test_reviewed_labels_load_and_resolve(tmp_path: Path):
    path = tmp_path / "reviewed_labels.jsonl"
    path.write_text(
        '{"sample_id":"row-1","final_label":"malicious","reviewer":"a"}\n'
        '{"sample_id":"row-2","final_label":"benign","reviewer":"b"}\n',
        encoding="utf-8",
    )

    labels = load_reviewed_labels(path)

    assert resolve_label(labels["row-1"]["final_label"]) == 1
    assert resolve_label(labels["row-2"]["final_label"]) == 0


def test_review_queue_deduplicates_repeated_content():
    df = pd.DataFrame(
        [
            {
                "sample_id": "a1",
                "analysis_text": "same-text",
                "malicious_probability": 0.99,
                "rule_score": 45,
                "matched_rule_ids": ["x"],
            },
            {
                "sample_id": "a2",
                "analysis_text": "same-text",
                "malicious_probability": 0.98,
                "rule_score": 44,
                "matched_rule_ids": ["x"],
            },
        ]
    )

    queue = build_review_queue(df, max_per_queue=10)

    assert len(queue) == 1
    assert int(queue.iloc[0]["duplicate_count"]) == 2
