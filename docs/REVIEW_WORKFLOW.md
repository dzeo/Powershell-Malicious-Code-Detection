# Review Workflow

This project improves incrementally through a review loop.

## Flow

1. Score a dataset with the current model and rule engine.
2. Export a review queue from the scored output.
3. Analysts review the queued samples and save final labels.
4. Retrain with reviewed labels overriding weak labels.
5. Compare errors and repeat.

## Files

- scored dataset:
  - `outputs/*.jsonl`
- review queue:
  - `data/review/review_queue.jsonl`
- review queue summary:
  - `data/review/review_queue_summary.json`
- reviewed label store:
  - `data/review/reviewed_labels.jsonl`

## Initialize Label Store

```bash
python3 scripts/init_review_labels.py --output data/review/reviewed_labels.jsonl
```

## Export Review Queue

```bash
python3 scripts/export_review_queue.py \
  --input outputs/external_scores.jsonl \
  --output data/review/review_queue.jsonl \
  --summary-output data/review/review_queue_summary.json
```

## Reviewed Label Schema

Each line in `reviewed_labels.jsonl` should look like:

```json
{
  "sample_id": "row-0000123",
  "final_label": "malicious",
  "confidence": "high",
  "reviewer": "analyst-1",
  "reviewed_at": "2026-04-02T12:00:00Z",
  "rationale": "download cradle plus encoded execution",
  "family_override": "download_cradle",
  "source": "manual_review"
}
```

## Retrain With Reviewed Labels

```bash
python3 scripts/train_baseline.py \
  --input data/your_training_data.jsonl \
  --reviewed-labels data/review/reviewed_labels.jsonl \
  --model-output models/hybrid_detector_v2.joblib \
  --report-output reports/hybrid_detector_v2_report.json \
  --trace-output outputs/hybrid_detector_v2_trace.jsonl
```

## Train Stronger Model Suite

```bash
python3 scripts/train_model_suite.py \
  --input data/your_training_data.jsonl \
  --reviewed-labels data/review/reviewed_labels.jsonl \
  --group-column family \
  --split-mode group \
  --suite-output reports/model_suite_report.json \
  --trace-output outputs/model_suite_trace.jsonl
```

## Label Precedence

The training pipeline resolves labels in this order:

1. reviewed labels
2. input dataset labels
3. weak labels

That makes the analyst review loop authoritative.
