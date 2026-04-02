"""Normalization and safe deobfuscation helpers for PowerShell-like text."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field


_ENCODED_COMMAND_RE = re.compile(
    r"(?i)-[Ee]nco(?:dedCommand|ded|d)?\s+([A-Za-z0-9+/=]{16,})"
)
_BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_BLOB_RE = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?([0-9A-Fa-f]{20,})(?![0-9A-Fa-f])")
_BACKTICK_ESCAPE_RE = re.compile(r"`([^\r\n])")
_STRING_CONCAT_RE = re.compile(r"(['\"])([^'\"]*)\1\s*\+\s*(['\"])([^'\"]*)\3")


@dataclass
class NormalizedSample:
    raw_text: str
    normalized_text: str
    decoded_text: str
    analysis_text: str
    transforms: list[str] = field(default_factory=list)


def _try_decode_base64(blob: str, strict: bool = True) -> tuple[str | None, str | None]:
    padded = blob + ("=" * ((4 - len(blob) % 4) % 4))
    try:
        data = base64.b64decode(padded, validate=False)
    except (ValueError, binascii.Error):
        return None, None

    for encoding in ("utf-16-le", "utf-8", "latin-1"):
        try:
            text = data.decode(encoding, errors="ignore").strip("\x00")
        except Exception:
            continue
        if len(text) < 4 or not any(ch.isalpha() for ch in text):
            continue
        printable = sum(ch.isprintable() and ch not in "\x0b\x0c" for ch in text)
        printable_ratio = printable / max(len(text), 1)
        ascii_ratio = sum(ord(ch) < 128 for ch in text) / max(len(text), 1)
        if printable_ratio < 0.85:
            continue
        if strict and ascii_ratio < 0.70:
            continue
        if sum(ch.isalpha() for ch in text) / max(len(text), 1) < 0.20:
            continue
        if strict and re.search(r"[\u4e00-\u9fff\u3400-\u4dbf\ue000-\uf8ff]", text):
            continue
        if "[DECODED]" in text or "[B64_DECODED]" in text or "[HEX_DECODED]" in text:
            continue
        if len(set(text)) < 4:
            continue
        return text, encoding
    return None, None


def _decode_encoded_command(text: str) -> tuple[str, list[str]]:
    transforms: list[str] = []

    def replace(match: re.Match[str]) -> str:
        blob = match.group(1)
        decoded, encoding = _try_decode_base64(blob, strict=False)
        if decoded is None:
            return match.group(0)
        transforms.append(f"decoded_encoded_command:{encoding}")
        return f"{match.group(0)} [DECODED] {decoded}"

    return _ENCODED_COMMAND_RE.sub(replace, text), transforms


def _decode_base64_blobs(text: str) -> tuple[str, list[str]]:
    transforms: list[str] = []

    def replace(match: re.Match[str]) -> str:
        blob = match.group(1)
        if len(blob) % 2 == 0 and set(blob) <= set("0123456789abcdefABCDEF"):
            return match.group(0)
        decoded, encoding = _try_decode_base64(blob, strict=True)
        if decoded is None:
            return match.group(0)
        transforms.append(f"decoded_base64_blob:{encoding}")
        return f"{match.group(0)} [B64_DECODED] {decoded}"

    return _BASE64_BLOB_RE.sub(replace, text), transforms


def _decode_hex_blobs(text: str) -> tuple[str, list[str]]:
    transforms: list[str] = []

    def replace(match: re.Match[str]) -> str:
        blob = match.group(1)
        if len(blob) % 2 != 0:
            return match.group(0)
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", errors="ignore")
        except ValueError:
            return match.group(0)
        if len(decoded) < 4 or not any(ch.isalpha() for ch in decoded):
            return match.group(0)
        transforms.append("decoded_hex_blob:utf-8")
        return f"{match.group(0)} [HEX_DECODED] {decoded}"

    return _HEX_BLOB_RE.sub(replace, text), transforms


def _collapse_backticks(text: str) -> tuple[str, list[str]]:
    updated = _BACKTICK_ESCAPE_RE.sub(r"\1", text)
    transforms = ["collapsed_backticks"] if updated != text else []
    return updated, transforms


def _collapse_string_concats(text: str, max_passes: int = 8) -> tuple[str, list[str]]:
    transforms: list[str] = []
    updated = text
    for _ in range(max_passes):
        next_text, count = _STRING_CONCAT_RE.subn(
            lambda m: f"{m.group(1)}{m.group(2)}{m.group(4)}{m.group(1)}",
            updated,
        )
        if count == 0:
            break
        transforms.append("collapsed_string_concat")
        updated = next_text
    return updated, transforms


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _derive_analysis_text(normalized_text: str, decoded_text: str, transforms: list[str]) -> str:
    if not transforms:
        return normalized_text

    # The model should score the semantically expanded content rather than the
    # wrapper plus decode markers; this also makes deduplication more stable for
    # encoded/plaintext equivalents of the same command.
    segments = re.findall(r"\[(?:DECODED|B64_DECODED|HEX_DECODED)\]\s*(.*?)(?=\s*\[(?:DECODED|B64_DECODED|HEX_DECODED)\]|$)", decoded_text)
    cleaned_segments = [normalize_whitespace(segment) for segment in segments if normalize_whitespace(segment)]
    unique_segments: list[str] = []
    seen: set[str] = set()
    for segment in cleaned_segments:
        if segment not in seen:
            unique_segments.append(segment)
            seen.add(segment)
    if unique_segments:
        return " ".join(unique_segments)
    return decoded_text


def canonicalize_text(text: str, max_decode_passes: int = 3) -> NormalizedSample:
    raw_text = text or ""
    normalized = normalize_whitespace(raw_text)
    decoded = normalized
    transforms: list[str] = []

    # Apply lightweight decode/collapse passes repeatedly so layered wrappers
    # such as encoded-command -> base64 blob -> string concat can unfold into a
    # cleaner representation for rules and models.
    for _ in range(max_decode_passes):
        changed = False
        for step in (
            _decode_encoded_command,
            _decode_base64_blobs,
            _decode_hex_blobs,
            _collapse_backticks,
            _collapse_string_concats,
        ):
            next_text, step_transforms = step(decoded)
            if step_transforms:
                transforms.extend(step_transforms)
            if next_text != decoded:
                changed = True
                decoded = next_text
        decoded = normalize_whitespace(decoded)
        if not changed:
            break

    analysis_text = _derive_analysis_text(normalized, decoded, transforms)

    return NormalizedSample(
        raw_text=raw_text,
        normalized_text=normalized,
        decoded_text=decoded,
        analysis_text=analysis_text,
        transforms=transforms,
    )
