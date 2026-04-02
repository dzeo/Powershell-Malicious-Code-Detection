# Single-Command Incremental Pipeline

This pipeline runs the full staged workflow in one command:

1. load input data
2. build feature records
3. train models on the first phase
4. score and correct using second-pass rule inspection
5. export review queues
6. auto-relabel high-confidence rows
7. repeat on larger cumulative phases
8. save final models and final artifact

## Run

```bash
python3 scripts/run_incremental_pipeline.py \
  --input data/your_training_data.jsonl \
  --output-dir runs/incremental_run_001 \
  --group-column family \
  --reviewed-labels data/review/reviewed_labels.jsonl \
  --phase-fractions 0.1,0.5,1.0 \
  --log-level DEBUG \
  --log-file runs/incremental_run_001/pipeline.log
```

## What Gets Saved

For each phase:

- `scores.jsonl`
- `review_queue.jsonl`
- `auto_pseudo_labels.jsonl`
- `summary.json`
- `logistic.joblib`
- `numeric_boost.joblib`

Final outputs:

- `final/logistic_final.joblib`
- `final/numeric_boost_final.joblib`
- `final/auto_pseudo_labels_all.jsonl`
- `final/final_artifact.json`

## Inference On Unknown Data

Once training finishes, use the saved artifact to score fresh data:

```bash
python3 scripts/run_final_inference.py \
  --artifact runs/incremental_run_001/final/final_artifact.json \
  --input data/unknown_samples.jsonl \
  --output outputs/unknown_scores.jsonl \
  --summary-output reports/unknown_summary.json \
  --review-queue-output data/review/unknown_review_queue.jsonl \
  --review-queue-summary-output data/review/unknown_review_queue_summary.json \
  --log-level DEBUG
```

This uses the saved final weights plus the logistic, numeric-boost, and second-pass rule stages from the final pipeline run.

## Calibration Logic

Each phase:

1. trains logistic and numeric-boost models on the current cumulative label set
2. validates on a held-out validation slice
3. derives weights from validation ROC-AUC for:
   - logistic model
   - numeric boost model
   - rule engine
4. applies a second-pass correction using decoded/raw rule inspection

This makes weak or failing model stages contribute less automatically.
