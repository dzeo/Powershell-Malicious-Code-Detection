from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psdetect.eval.model_selection import choose_best_model


def test_choose_best_model_prefers_recall_under_recall_first():
    metrics = {
        "logistic": {
            "roc_auc": 0.95,
            "classification_report": {
                "accuracy": 0.90,
                "1": {"precision": 0.80, "recall": 0.70, "f1-score": 0.7467},
            },
        },
        "ensemble_avg": {
            "roc_auc": 0.92,
            "classification_report": {
                "accuracy": 0.88,
                "1": {"precision": 0.60, "recall": 0.95, "f1-score": 0.7355},
            },
        },
    }

    selection = choose_best_model(metrics, objective="recall_first")

    assert selection["winner"] == "ensemble_avg"


def test_choose_best_model_prefers_f1_under_balanced():
    metrics = {
        "logistic": {
            "roc_auc": 0.95,
            "classification_report": {
                "accuracy": 0.90,
                "1": {"precision": 0.80, "recall": 0.70, "f1-score": 0.7467},
            },
        },
        "ensemble_avg": {
            "roc_auc": 0.92,
            "classification_report": {
                "accuracy": 0.88,
                "1": {"precision": 0.60, "recall": 0.95, "f1-score": 0.7355},
            },
        },
    }

    selection = choose_best_model(metrics, objective="balanced")

    assert selection["winner"] == "logistic"
