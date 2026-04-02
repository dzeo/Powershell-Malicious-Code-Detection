"""Non-linear detector on handcrafted numeric and rule features.

Uses LightGBM when available and falls back to sklearn HistGradientBoosting so
the stronger-model stage is runnable even in restricted environments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction import DictVectorizer

from psdetect.features.extract import FeatureRecord
from psdetect.logging_utils import logger


@dataclass
class NumericBoostPowerShellDetector:
    dict_vectorizer: DictVectorizer | None = None
    classifier: Any | None = None
    backend: str = "auto"

    def __post_init__(self) -> None:
        if self.dict_vectorizer is None:
            self.dict_vectorizer = DictVectorizer(sparse=False)
        if self.classifier is None:
            self.classifier, selected_backend = self._build_classifier(self.backend)
            self.backend = selected_backend

    @staticmethod
    def _build_classifier(backend: str) -> tuple[Any, str]:
        if backend in {"auto", "lightgbm"}:
            try:
                from lightgbm import LGBMClassifier

                logger.info("Using LightGBM backend for numeric boost detector")
                return (
                    LGBMClassifier(
                        objective="binary",
                        n_estimators=300,
                        learning_rate=0.05,
                        num_leaves=63,
                        subsample=0.9,
                        colsample_bytree=0.9,
                        class_weight="balanced",
                        random_state=42,
                    ),
                    "lightgbm",
                )
            except ImportError:
                if backend == "lightgbm":
                    raise

        logger.info("Using HistGradientBoosting backend for numeric boost detector")
        return (
            HistGradientBoostingClassifier(
                learning_rate=0.05,
                max_iter=300,
                max_depth=8,
                min_samples_leaf=20,
                l2_regularization=1.0,
                random_state=42,
            ),
            "histgb",
        )

    def _matrix(self, records: list[FeatureRecord], fit: bool) -> np.ndarray:
        dicts = [record.numeric_features for record in records]
        if fit:
            matrix = self.dict_vectorizer.fit_transform(dicts)
        else:
            matrix = self.dict_vectorizer.transform(dicts)
        logger.info(
            "Built numeric feature matrix: rows={}, cols={}, backend={}",
            matrix.shape[0],
            matrix.shape[1],
            self.backend,
        )
        return np.asarray(matrix, dtype=np.float32)

    def fit(self, records: list[FeatureRecord], labels: list[int]) -> "NumericBoostPowerShellDetector":
        matrix = self._matrix(records, fit=True)
        logger.info("Training numeric boost detector with backend={} on matrix {}", self.backend, matrix.shape)
        self.classifier.fit(matrix, labels)
        logger.info("Numeric boost training complete")
        return self

    def predict_proba(self, records: list[FeatureRecord]) -> np.ndarray:
        matrix = self._matrix(records, fit=False)
        if hasattr(self.classifier, "predict_proba"):
            probs = self.classifier.predict_proba(matrix)
        else:  # pragma: no cover
            scores = self.classifier.decision_function(matrix)
            probs_pos = 1.0 / (1.0 + np.exp(-scores))
            probs = np.column_stack([1.0 - probs_pos, probs_pos])
        return probs

    def predict(self, records: list[FeatureRecord]) -> np.ndarray:
        probs = self.predict_proba(records)[:, 1]
        return (probs >= 0.5).astype(int)

    def explain(self, records: list[FeatureRecord], top_k: int = 10) -> list[dict[str, Any]]:
        probs = self.predict_proba(records)[:, 1]
        feature_names = list(self.dict_vectorizer.get_feature_names_out())
        explanations: list[dict[str, Any]] = []

        for record, prob in zip(records, probs):
            ranked = sorted(
                (
                    {"feature": name, "value": round(float(value), 6)}
                    for name, value in record.numeric_features.items()
                    if value
                ),
                key=lambda item: abs(item["value"]),
                reverse=True,
            )[:top_k]
            explanations.append(
                {
                    "sample_id": record.sample_id,
                    "malicious_probability": round(float(prob), 6),
                    "backend": self.backend,
                    "available_features": len(feature_names),
                    "top_numeric_signals": ranked,
                }
            )
        return explanations

    def save(self, path: str) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "NumericBoostPowerShellDetector":
        return joblib.load(path)
