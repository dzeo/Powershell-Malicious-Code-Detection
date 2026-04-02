"""Dataset preparation for large PowerShell corpora."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

import pandas as pd
from tqdm.auto import tqdm
from psdetect.features.extract import build_feature_record
from psdetect.logging_utils import logger
from psdetect.models.weak_labels import assign_weak_label


@dataclass
class PreparedCorpusRow:
    sample_id: str
    raw_text: str
    normalized_text: str
    decoded_text: str
    analysis_text: str
    parser_backend: str
    raw_sha256: str
    decoded_sha256: str
    analysis_sha256: str
    transforms: list[str]
    split: str
    weak_label: str
    weak_confidence: float
    weak_rationale: list[str]
    metadata: dict[str, object]


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _deterministic_split(sample_id: str, decoded_sha256: str) -> str:
    bucket = int(hashlib.md5(f"{sample_id}:{decoded_sha256}".encode("utf-8")).hexdigest(), 16) % 100
    if bucket < 80:
        return "train"
    if bucket < 90:
        return "validation"
    return "test"


def prepare_dataframe(
    df: pd.DataFrame,
    *,
    text_column: str = "text",
    id_column: str = "sample_id",
    timestamp_column: str | None = None,
    metadata_columns: list[str] | None = None,
    parser_backend: str = "auto",
    show_progress: bool = False,
    log_every: int = 10000,
) -> tuple[pd.DataFrame, dict[str, object]]:
    if text_column not in df.columns:
        raise ValueError(f"Missing text column: {text_column}")

    metadata_columns = metadata_columns or []
    working = df.copy()
    logger.info(
        "Preparing dataframe with {} rows, parser_backend={}, timestamp_column={}",
        len(working),
        parser_backend,
        timestamp_column,
    )
    if timestamp_column and timestamp_column in working.columns:
        working["__parsed_ts"] = pd.to_datetime(working[timestamp_column], errors="coerce", utc=True)
        working = working.sort_values("__parsed_ts", na_position="last").reset_index(drop=True)

    rows: list[PreparedCorpusRow] = []
    iterator = working.iterrows()
    if show_progress:
        iterator = tqdm(iterator, total=len(working), desc="Preparing corpus rows")
    for idx, row in iterator:
        sample_id = str(row[id_column]) if id_column in working.columns else f"row-{idx:09d}"
        text = str(row[text_column])
        record = build_feature_record(sample_id=sample_id, text=text, parser_backend=parser_backend)
        weak = assign_weak_label(record)

        metadata = {column: row[column] for column in metadata_columns if column in working.columns}
        if timestamp_column and timestamp_column in working.columns:
            metadata[timestamp_column] = row[timestamp_column]

        rows.append(
            PreparedCorpusRow(
                sample_id=sample_id,
                raw_text=record.normalized.raw_text,
                normalized_text=record.normalized.normalized_text,
                decoded_text=record.normalized.decoded_text,
                analysis_text=record.normalized.analysis_text,
                parser_backend=record.parsed.backend,
                raw_sha256=_sha256(record.normalized.raw_text),
                decoded_sha256=_sha256(record.normalized.decoded_text),
                analysis_sha256=_sha256(record.normalized.analysis_text),
                transforms=record.normalized.transforms,
                split="pending",
                weak_label=weak.label,
                weak_confidence=weak.confidence,
                weak_rationale=weak.rationale,
                metadata=metadata,
            )
        )
        if log_every and (idx + 1) % log_every == 0:
            logger.debug(
                "Prepared {} rows so far; latest sample_id={}, weak_label={}, transforms={}",
                idx + 1,
                sample_id,
                weak.label,
                record.normalized.transforms,
            )

    prepared = pd.DataFrame(asdict(row) for row in rows)
    prepared["is_duplicate_raw"] = prepared.duplicated("raw_sha256", keep="first")
    prepared["is_duplicate_decoded"] = prepared.duplicated("decoded_sha256", keep="first")
    prepared["is_duplicate_analysis"] = prepared.duplicated("analysis_sha256", keep="first")
    prepared["is_unique_for_training"] = ~(prepared["is_duplicate_analysis"])

    if timestamp_column and timestamp_column in working.columns and "__parsed_ts" in working.columns:
        timestamps = working["__parsed_ts"].reset_index(drop=True)
        valid_mask = timestamps.notna()
        prepared["split"] = "train"
        if valid_mask.any():
            valid_ts = timestamps[valid_mask]
            val_cutoff = valid_ts.quantile(0.8)
            test_cutoff = valid_ts.quantile(0.9)
            prepared.loc[valid_mask & (timestamps >= val_cutoff), "split"] = "validation"
            prepared.loc[valid_mask & (timestamps >= test_cutoff), "split"] = "test"
            prepared.loc[~valid_mask, "split"] = prepared.loc[~valid_mask].apply(
                lambda item: _deterministic_split(item["sample_id"], item["decoded_sha256"]),
                axis=1,
            )
        else:
            prepared["split"] = prepared.apply(
                lambda item: _deterministic_split(item["sample_id"], item["decoded_sha256"]),
                axis=1,
            )
    else:
        prepared["split"] = prepared.apply(
            lambda item: _deterministic_split(item["sample_id"], item["decoded_sha256"]),
            axis=1,
        )

    manifest = {
        "rows_in": int(len(df)),
        "rows_out": int(len(prepared)),
        "unique_raw": int((~prepared["is_duplicate_raw"]).sum()),
        "unique_decoded": int((~prepared["is_duplicate_decoded"]).sum()),
        "unique_analysis": int((~prepared["is_duplicate_analysis"]).sum()),
        "weak_label_counts": prepared["weak_label"].value_counts(dropna=False).to_dict(),
        "split_counts": prepared["split"].value_counts(dropna=False).to_dict(),
        "parser_backends": prepared["parser_backend"].value_counts(dropna=False).to_dict(),
    }
    logger.info(
        "Prepared corpus complete: rows_out={}, unique_analysis={}, duplicates_removed={}",
        manifest["rows_out"],
        manifest["unique_analysis"],
        manifest["rows_out"] - manifest["unique_analysis"],
    )
    return prepared, manifest
