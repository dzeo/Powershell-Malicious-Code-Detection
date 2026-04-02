"""Helpers for selecting a detector champion from model-suite results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ModelScore:
    model_name: str
    malicious_recall: float
    malicious_precision: float
    malicious_f1: float
    roc_auc: float
    accuracy: float


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def build_model_score(model_name: str, metrics: dict[str, Any]) -> ModelScore:
    report = metrics.get("classification_report", {})
    malicious = report.get("1", {})
    return ModelScore(
        model_name=model_name,
        malicious_recall=_safe_float(malicious.get("recall")),
        malicious_precision=_safe_float(malicious.get("precision")),
        malicious_f1=_safe_float(malicious.get("f1-score")),
        roc_auc=_safe_float(metrics.get("roc_auc")),
        accuracy=_safe_float(report.get("accuracy")),
    )


def choose_best_model(
    metrics_by_model: dict[str, dict[str, Any]],
    *,
    objective: str = "recall_first",
) -> dict[str, Any]:
    if not metrics_by_model:
        raise ValueError("metrics_by_model must not be empty")

    scores = [build_model_score(name, metrics) for name, metrics in metrics_by_model.items()]

    if objective == "recall_first":
        ranked = sorted(
            scores,
            key=lambda score: (
                score.malicious_recall,
                score.malicious_precision,
                score.roc_auc,
                score.malicious_f1,
                score.accuracy,
            ),
            reverse=True,
        )
    elif objective == "balanced":
        ranked = sorted(
            scores,
            key=lambda score: (
                score.malicious_f1,
                score.roc_auc,
                score.malicious_recall,
                score.malicious_precision,
                score.accuracy,
            ),
            reverse=True,
        )
    else:
        raise ValueError(f"Unsupported selection objective: {objective}")

    winner = ranked[0]
    return {
        "objective": objective,
        "winner": winner.model_name,
        "winner_metrics": {
            "malicious_recall": winner.malicious_recall,
            "malicious_precision": winner.malicious_precision,
            "malicious_f1": winner.malicious_f1,
            "roc_auc": winner.roc_auc,
            "accuracy": winner.accuracy,
        },
        "ranking": [
            {
                "model_name": score.model_name,
                "malicious_recall": score.malicious_recall,
                "malicious_precision": score.malicious_precision,
                "malicious_f1": score.malicious_f1,
                "roc_auc": score.roc_auc,
                "accuracy": score.accuracy,
            }
            for score in ranked
        ],
    }
