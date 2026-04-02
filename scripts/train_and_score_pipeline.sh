#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <input_data.jsonl|csv> [run_name]"
  echo
  echo "Example:"
  echo "  $0 data/my_samples.jsonl first_real_run"
  exit 1
fi

INPUT_DATA="$1"
RUN_NAME="${2:-run_$(date +%Y%m%d_%H%M%S)}"
OUTPUT_DIR="${ROOT_DIR}/runs/${RUN_NAME}"
LOG_FILE="${OUTPUT_DIR}/pipeline.log"

TEXT_COLUMN="${TEXT_COLUMN:-text}"
ID_COLUMN="${ID_COLUMN:-sample_id}"
LABEL_COLUMN="${LABEL_COLUMN:-label}"
GROUP_COLUMN="${GROUP_COLUMN:-family}"
PHASE_FRACTIONS="${PHASE_FRACTIONS:-0.1,0.5,1.0}"
VALIDATION_FRACTION="${VALIDATION_FRACTION:-0.2}"
PARSER_BACKEND="${PARSER_BACKEND:-auto}"
REVIEWED_LABELS="${REVIEWED_LABELS:-}"
LOG_LEVEL="${LOG_LEVEL:-DEBUG}"
LOG_EVERY="${LOG_EVERY:-1000}"
TOP_K="${TOP_K:-25}"
RUN_INFERENCE_AFTER_TRAIN="${RUN_INFERENCE_AFTER_TRAIN:-0}"
INFERENCE_DATA="${INFERENCE_DATA:-}"
EXPLAIN_TOP_N="${EXPLAIN_TOP_N:-250}"

if [[ -n "${INFERENCE_DATA}" ]]; then
  RUN_INFERENCE_AFTER_TRAIN=1
fi

SCORES_OUTPUT="${OUTPUT_DIR}/final/inference_scores.jsonl"
SUMMARY_OUTPUT="${OUTPUT_DIR}/final/inference_summary.json"
QUEUE_OUTPUT="${OUTPUT_DIR}/final/inference_review_queue.jsonl"
QUEUE_SUMMARY_OUTPUT="${OUTPUT_DIR}/final/inference_review_queue_summary.json"

mkdir -p "${OUTPUT_DIR}"

echo "============================================================"
echo "PowerShell Detection Pipeline"
echo "============================================================"
echo "Input data:          ${INPUT_DATA}"
echo "Run name:            ${RUN_NAME}"
echo "Output dir:          ${OUTPUT_DIR}"
echo "Text column:         ${TEXT_COLUMN}"
echo "ID column:           ${ID_COLUMN}"
echo "Label column:        ${LABEL_COLUMN}"
echo "Group column:        ${GROUP_COLUMN}"
echo "Phase fractions:     ${PHASE_FRACTIONS}"
echo "Validation fraction: ${VALIDATION_FRACTION}"
echo "Parser backend:      ${PARSER_BACKEND}"
echo "Log level:           ${LOG_LEVEL}"
echo "Run inference:       ${RUN_INFERENCE_AFTER_TRAIN}"
if [[ "${RUN_INFERENCE_AFTER_TRAIN}" == "1" ]]; then
  echo "Inference data:      ${INFERENCE_DATA:-${INPUT_DATA}}"
  echo "Explain top N:       ${EXPLAIN_TOP_N}"
fi
echo "============================================================"

TRAIN_CMD=(
  python3 "${ROOT_DIR}/scripts/run_incremental_pipeline.py"
  --input "${INPUT_DATA}"
  --output-dir "${OUTPUT_DIR}"
  --text-column "${TEXT_COLUMN}"
  --id-column "${ID_COLUMN}"
  --label-column "${LABEL_COLUMN}"
  --phase-fractions "${PHASE_FRACTIONS}"
  --validation-fraction "${VALIDATION_FRACTION}"
  --parser-backend "${PARSER_BACKEND}"
  --log-level "${LOG_LEVEL}"
  --log-file "${LOG_FILE}"
  --log-every "${LOG_EVERY}"
)

if [[ -n "${GROUP_COLUMN}" ]]; then
  TRAIN_CMD+=(--group-column "${GROUP_COLUMN}")
fi

if [[ -n "${REVIEWED_LABELS}" ]]; then
  TRAIN_CMD+=(--reviewed-labels "${REVIEWED_LABELS}")
fi

echo
echo "[1/2] Training incremental pipeline"
"${TRAIN_CMD[@]}"

ARTIFACT_PATH="${OUTPUT_DIR}/final/final_artifact.json"

echo
echo "Training completed."
echo "Phase 1 scores:      ${OUTPUT_DIR}/phase_1_10pct/scores.jsonl"
echo "Phase 2 scores:      ${OUTPUT_DIR}/phase_2_50pct/scores.jsonl"
echo "Phase 3 scores:      ${OUTPUT_DIR}/phase_3_100pct/scores.jsonl"
echo "Phase 3 review:      ${OUTPUT_DIR}/phase_3_100pct/review_queue.jsonl"

if [[ "${RUN_INFERENCE_AFTER_TRAIN}" == "1" ]]; then
  TARGET_INFERENCE_DATA="${INFERENCE_DATA:-${INPUT_DATA}}"
  echo
  echo "[2/2] Running final-artifact inference"
  python3 "${ROOT_DIR}/scripts/run_final_inference.py" \
    --artifact "${ARTIFACT_PATH}" \
    --input "${TARGET_INFERENCE_DATA}" \
    --output "${SCORES_OUTPUT}" \
    --summary-output "${SUMMARY_OUTPUT}" \
    --review-queue-output "${QUEUE_OUTPUT}" \
    --review-queue-summary-output "${QUEUE_SUMMARY_OUTPUT}" \
    --text-column "${TEXT_COLUMN}" \
    --id-column "${ID_COLUMN}" \
    --parser-backend "${PARSER_BACKEND}" \
    --top-k "${TOP_K}" \
    --explain-top-n "${EXPLAIN_TOP_N}" \
    --log-level "${LOG_LEVEL}" \
    --log-file "${LOG_FILE}"
fi

echo
echo "Completed."
echo "Final artifact:      ${ARTIFACT_PATH}"
if [[ "${RUN_INFERENCE_AFTER_TRAIN}" == "1" ]]; then
  echo "Inference scores:    ${SCORES_OUTPUT}"
  echo "Inference summary:   ${SUMMARY_OUTPUT}"
  echo "Inference queue:     ${QUEUE_OUTPUT}"
  echo "Queue summary:       ${QUEUE_SUMMARY_OUTPUT}"
fi
echo "Log file:            ${LOG_FILE}"
