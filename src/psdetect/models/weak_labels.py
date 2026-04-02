"""Weak labeling helpers for unlabeled PowerShell-like samples."""

from __future__ import annotations

from dataclasses import dataclass

from psdetect.features.extract import FeatureRecord


@dataclass
class WeakLabel:
    label: str
    confidence: float
    rationale: list[str]


def assign_weak_label(record: FeatureRecord) -> WeakLabel:
    feats = record.numeric_features
    rationale: list[str] = []
    suspicious_score = 0.0
    benign_score = 0.0

    if record.rules.matches:
        suspicious_score += min(0.5, record.rules.total_weight / 8.0)
        rationale.extend(f"rule:{match.rule_id}" for match in record.rules.matches[:5])
        if record.rules.max_level >= 3:
            suspicious_score += 0.15
        if record.rules.risk_score >= 40:
            suspicious_score += 0.10

    if feats["flag_encoded_cmd"]:
        suspicious_score += 0.30
        rationale.append("encoded_command")
    if feats["flag_iex"]:
        suspicious_score += 0.25
        rationale.append("invoke_expression")
    if feats["flag_download"]:
        suspicious_score += 0.20
        rationale.append("download_primitive")
    if feats["flag_hidden"]:
        suspicious_score += 0.15
        rationale.append("hidden_window")
    if feats["flag_reflection"] or feats["flag_amsi_ref"]:
        suspicious_score += 0.20
        rationale.append("dotnet_reflection_or_amsi")
    if feats["decoded_base64_blob"] or feats["decoded_hex_blob"]:
        suspicious_score += 0.10
        rationale.append("decoded_obfuscation")
    if feats["collapsed_string_concat"]:
        suspicious_score += 0.10
        rationale.append("string_concat_obfuscation")
    if feats["flag_persistence"] or feats["flag_registry"]:
        suspicious_score += 0.10
        rationale.append("persistence_signal")

    if feats["command_count"] >= 1 and not feats["flag_iex"] and not feats["flag_encoded_cmd"]:
        benign_score += 0.10
    if feats["flag_download"] and "health" in record.normalized.decoded_text.lower():
        benign_score += 0.15
        rationale.append("benign_healthcheck_pattern")
    if "get-service" in record.normalized.decoded_text.lower():
        benign_score += 0.20
        rationale.append("benign_service_query")
    if "export-csv" in record.normalized.decoded_text.lower():
        benign_score += 0.15
        rationale.append("benign_reporting_pattern")

    if suspicious_score >= 0.45 and suspicious_score > benign_score:
        return WeakLabel("suspicious", min(0.99, suspicious_score), rationale)
    if benign_score >= 0.20 and benign_score >= suspicious_score:
        return WeakLabel("benign", min(0.95, benign_score), rationale)
    return WeakLabel("unknown", max(suspicious_score, benign_score), rationale)
