"""Runnable baseline detector built from hybrid text and handcrafted features."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from psdetect.features.extract import FeatureRecord
from psdetect.logging_utils import logger


@dataclass
class HybridPowerShellDetector:
    char_vectorizer: TfidfVectorizer | None = None
    word_vectorizer: TfidfVectorizer | None = None
    dict_vectorizer: DictVectorizer | None = None
    classifier: LogisticRegression | None = None

    def __post_init__(self) -> None:
        if self.char_vectorizer is None:
            self.char_vectorizer = TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                min_df=1,
                lowercase=True,
            )
        if self.word_vectorizer is None:
            self.word_vectorizer = TfidfVectorizer(
                analyzer="word",
                token_pattern=r"(?u)\b[\w\-\.:/\\]+\b",
                ngram_range=(1, 2),
                min_df=1,
                lowercase=True,
            )
        if self.dict_vectorizer is None:
            self.dict_vectorizer = DictVectorizer(sparse=True)
        if self.classifier is None:
            self.classifier = LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                solver="liblinear",
                random_state=42,
            )

    def _combined_matrix(self, records: list[FeatureRecord], fit: bool) -> sparse.csr_matrix:
        texts = [record.normalized.analysis_text for record in records]
        dicts = [record.numeric_features for record in records]

        if fit:
            logger.info("Fitting vectorizers on {} records", len(records))
            char_x = self.char_vectorizer.fit_transform(texts)
            word_x = self.word_vectorizer.fit_transform(texts)
            dict_x = self.dict_vectorizer.fit_transform(dicts)
        else:
            logger.debug("Transforming {} records with existing vectorizers", len(records))
            char_x = self.char_vectorizer.transform(texts)
            word_x = self.word_vectorizer.transform(texts)
            dict_x = self.dict_vectorizer.transform(dicts)

        combined = sparse.hstack([char_x, word_x, dict_x], format="csr")
        logger.info(
            "Built feature matrix: rows={}, cols={}, char_features={}, word_features={}, numeric_features={}",
            combined.shape[0],
            combined.shape[1],
            char_x.shape[1],
            word_x.shape[1],
            dict_x.shape[1],
        )
        return combined

    def fit(self, records: list[FeatureRecord], labels: list[int]) -> "HybridPowerShellDetector":
        matrix = self._combined_matrix(records, fit=True)
        logger.info("Training LogisticRegression classifier on matrix {}", matrix.shape)
        self.classifier.fit(matrix, labels)
        logger.info("Model training complete")
        return self

    def _feature_names(self) -> list[str]:
        char_names = [f"char:{name}" for name in self.char_vectorizer.get_feature_names_out()]
        word_names = [f"word:{name}" for name in self.word_vectorizer.get_feature_names_out()]
        dict_names = [f"feat:{name}" for name in self.dict_vectorizer.get_feature_names_out()]
        return char_names + word_names + dict_names

    def predict(self, records: list[FeatureRecord]) -> np.ndarray:
        matrix = self._combined_matrix(records, fit=False)
        return self.classifier.predict(matrix)

    def predict_proba(self, records: list[FeatureRecord]) -> np.ndarray:
        matrix = self._combined_matrix(records, fit=False)
        logger.info("Scoring {} records", matrix.shape[0])
        return self.classifier.predict_proba(matrix)

    def explain(self, records: list[FeatureRecord], top_k: int = 10) -> list[dict[str, Any]]:
        matrix = self._combined_matrix(records, fit=False)
        probabilities = self.classifier.predict_proba(matrix)[:, 1]
        feature_names = self._feature_names()
        coefs = self.classifier.coef_[0]
        explanations: list[dict[str, Any]] = []
        logger.info("Generating model explanations for {} records", len(records))

        for row_index, (record, probability) in enumerate(zip(records, probabilities)):
            row = matrix.getrow(row_index)
            contributions = row.multiply(coefs).toarray().ravel()
            nonzero_indices = row.indices.tolist()
            ranked = sorted(
                (
                    {
                        "feature": feature_names[idx],
                        "feature_value": round(float(row[0, idx]), 6),
                        "coefficient": round(float(coefs[idx]), 6),
                        "contribution": round(float(contributions[idx]), 6),
                    }
                    for idx in nonzero_indices
                ),
                key=lambda item: abs(item["contribution"]),
                reverse=True,
            )

            numeric_snapshot = sorted(
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
                    "malicious_probability": round(float(probability), 6),
                    "top_model_contributions": ranked[:top_k],
                    "top_numeric_signals": numeric_snapshot,
                }
            )

        return explanations

    def save(self, path: str) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "HybridPowerShellDetector":
        return joblib.load(path)
