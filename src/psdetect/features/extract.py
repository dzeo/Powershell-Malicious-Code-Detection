"""Hybrid feature extraction for PowerShell-like samples."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from psdetect.normalize.canonicalize import NormalizedSample, canonicalize_text
from psdetect.parse.parser import ParseArtifacts, parse_text
from psdetect.rules.engine import RuleEngineResult, evaluate_attack_patterns, rule_features


SUSPICIOUS_PATTERNS = {
    "flag_bypass": r"(?i)-executionpolicy\s+bypass",
    "flag_unrestricted": r"(?i)-executionpolicy\s+unrestricted",
    "flag_noprofile": r"(?i)-noprofile",
    "flag_noninteractive": r"(?i)-noninteractive",
    "flag_hidden": r"(?i)-windowstyle\s+hidden",
    "flag_encoded_cmd": r"(?i)-encodedcommand|-encoded\b",
    "flag_temp_path": r"(?i)\\temp\\|appdata\\local\\temp|\$env:temp",
    "flag_iex": r"(?i)\biex\b|invoke-expression",
    "flag_download": r"(?i)downloadstring|webclient|invoke-webrequest|\biwr\b|wget|curl",
    "flag_reflection": r"(?i)\[reflection\.|assembly::load",
    "flag_registry": r"(?i)hklm:|hkcu:|registry::",
    "flag_wmi": r"(?i)get-wmiobject|invoke-wmimethod|wmic",
    "flag_net_connection": r"(?i)new-object\s+net\.webclient|tcpclient|udpclient|http",
    "flag_b64_blob": r"[A-Za-z0-9+/]{40,}={0,2}",
    "flag_hex_blob": r"(?:0x[0-9a-fA-F]{8,}|[0-9a-fA-F]{20,})",
    "flag_compress": r"(?i)gzip|deflate|decompress|io\.compression",
    "flag_amsi_ref": r"(?i)amsi|system\.management\.automation",
    "flag_persistence": r"(?i)\\run\\|scheduledtask|new-service|startup",
}

SUSPICIOUS_TOKENS = {
    "powershell",
    "bypass",
    "encodedcommand",
    "invoke-expression",
    "iex",
    "downloadstring",
    "webclient",
    "reflection.assembly",
    "frombase64string",
    "virtualalloc",
    "createthread",
    "marshal",
    "amsi",
}


@dataclass
class FeatureRecord:
    sample_id: str
    text: str
    normalized: NormalizedSample
    parsed: ParseArtifacts
    rules: RuleEngineResult
    numeric_features: dict[str, float]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _lexical_features(text: str) -> dict[str, float]:
    stripped = re.sub(r"\s+", "", text)
    non_alpha = sum(1 for char in text if not char.isalpha() and not char.isspace())
    total = max(len(text), 1)
    upper = sum(1 for char in text if char.isupper())
    digits = sum(1 for char in text if char.isdigit())
    return {
        "entropy_full": _shannon_entropy(text),
        "entropy_compact": _shannon_entropy(stripped),
        "text_length": len(text),
        "text_length_log": math.log1p(len(text)),
        "non_alpha_ratio": non_alpha / total,
        "upper_ratio": upper / total,
        "digit_ratio": digits / total,
        "backtick_count": text.count("`"),
        "pipe_count": text.count("|"),
        "semicolon_count": text.count(";"),
    }


def _pattern_features(text: str) -> dict[str, float]:
    return {name: float(bool(re.search(pattern, text))) for name, pattern in SUSPICIOUS_PATTERNS.items()}


def _token_features(parsed: ParseArtifacts) -> dict[str, float]:
    tokens = parsed.tokens
    lower_tokens = [token.lower() for token in tokens]
    total = len(tokens) or 1
    suspicious_hits = sum(1 for token in lower_tokens if token in SUSPICIOUS_TOKENS)
    avg_len = sum(len(token) for token in tokens) / total
    return {
        "token_count": float(total),
        "token_unique_ratio": len(set(lower_tokens)) / total,
        "token_avg_len": avg_len,
        "token_suspicious_count": float(suspicious_hits),
        "token_suspicious_ratio": suspicious_hits / total,
        "command_count": float(len(parsed.commands)),
        "parameter_count": float(len(parsed.parameters)),
        "alias_count": float(len(parsed.aliases)),
    }


def _transform_features(normalized: NormalizedSample) -> dict[str, float]:
    transforms = Counter(normalized.transforms)
    return {
        "transform_count": float(len(normalized.transforms)),
        "decoded_encoded_command": float(
            any(item.startswith("decoded_encoded_command") for item in normalized.transforms)
        ),
        "decoded_base64_blob": float(
            any(item.startswith("decoded_base64_blob") for item in normalized.transforms)
        ),
        "decoded_hex_blob": float(
            any(item.startswith("decoded_hex_blob") for item in normalized.transforms)
        ),
        "collapsed_backticks": float("collapsed_backticks" in transforms),
        "collapsed_string_concat": float("collapsed_string_concat" in transforms),
    }


def _structural_features(parsed: ParseArtifacts) -> dict[str, float]:
    features: dict[str, float] = {}
    for key, value in parsed.ast_like_counts.items():
        features[f"ast_{key}"] = float(value)
    for key, value in parsed.parse_quality.items():
        features[f"parse_{key}"] = float(value)
    features["parser_backend_native"] = float(parsed.backend == "pwsh_native")
    return features


def build_feature_record(sample_id: str, text: str, parser_backend: str = "auto") -> FeatureRecord:
    normalized = canonicalize_text(text)
    # Parse and score the analysis view instead of the raw wrapper so features
    # are driven by the most semantically useful representation available.
    parsed = parse_text(normalized.analysis_text, backend=parser_backend)
    rules = evaluate_attack_patterns(normalized.analysis_text)
    numeric_features: dict[str, float] = {}
    numeric_features.update(_lexical_features(normalized.analysis_text))
    numeric_features.update(_pattern_features(normalized.analysis_text))
    numeric_features.update(_token_features(parsed))
    numeric_features.update(_transform_features(normalized))
    numeric_features.update(_structural_features(parsed))
    numeric_features.update(rule_features(rules))
    return FeatureRecord(
        sample_id=sample_id,
        text=text,
        normalized=normalized,
        parsed=parsed,
        rules=rules,
        numeric_features=numeric_features,
    )
