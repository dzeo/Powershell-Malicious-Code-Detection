# PowerShell Malicious Code Detection
https://allegro.pl/produkt/opel-astra-h-1-4-2004-2010-hatchback-coupe-uklad-wydechowy-5eecdf5f-cfdc-4acf-8047-3db60c49fe03?offerId=7523573960

Recall-first PowerShell detection pipeline for large corpora, including partially labeled and unlabeled datasets.

The repository is built around four ideas:

- normalize and safely deobfuscate PowerShell text
- combine known-pattern detection with learned models
- train incrementally with reviewed and pseudo labels
- export analyst review queues instead of pretending a single threshold solves everything

## Primary Way to Run It

The main way to use this repository is the single shell wrapper:

```bash
conda activate power_mal
./scripts/train_and_score_pipeline.sh data/raw/your_corpus.jsonl real_run_001
```

This is the default end-to-end entrypoint for the project. It runs the complete training pipeline, writes all phase outputs, saves the final model artifact, and logs the run to `runs/<run_name>/pipeline.log`.

Use the Python scripts directly only when you want to run one part of the system manually.

## What This Repo Contains

Core pipeline:

- normalization and deobfuscation
- lightweight parsing with optional native PowerShell backend
- staged attack-pattern rules with MITRE mappings
- hybrid baseline model using TF-IDF plus handcrafted features
- numeric boosting model using `LightGBM` when available
- incremental multi-phase training
- review queue generation
- final artifact-based inference on unknown data

Main docs:

- [Project Handoff Report](docs/PROJECT_HANDOFF_REPORT.md)
- [Implementation Plan](docs/IMPLEMENTATION.md)
- [Attack Patterns](docs/ATTACK_PATTERNS.md)
- [Incremental Pipeline](docs/INCREMENTAL_PIPELINE.md)
- [Model Selection](docs/MODEL_SELECTION.md)
- [Review Workflow](docs/REVIEW_WORKFLOW.md)
- [Run Audit](docs/RUN_AUDIT.md)

## Repository Layout

```text
.
├── data/
├── docs/
├── models/
├── outputs/
├── reports/
├── runs/
├── scripts/
├── src/psdetect/
└── tests/
```

Important modules:

- `src/psdetect/normalize/canonicalize.py`
- `src/psdetect/parse/parser.py`
- `src/psdetect/rules/taxonomy.py`
- `src/psdetect/rules/engine.py`
- `src/psdetect/features/extract.py`
- `src/psdetect/models/baseline.py`
- `src/psdetect/models/numeric_boost.py`
- `src/psdetect/pipeline/incremental.py`

## Environment Setup

Recommended environment:

```bash
conda activate power_mal
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Current requirements include:

- `scikit-learn`
- `pandas`
- `numpy`
- `tqdm`
- `joblib`
- `loguru`
- `lightgbm`
- `xgboost`
- `catboost`

## Input Data Format

Supported formats:

- `JSONL`
- `CSV`

Minimum required field:

- a text column containing the PowerShell command or script block

Recommended fields:

- `sample_id`
- `text`
- `label`
- `family`
- `timestamp`

Recommended JSONL example:

```json
{"sample_id":"row-000001","text":"powershell.exe -NoProfile -Command \"Get-Service\"","label":"benign","family":"admin_job","timestamp":"2026-03-31T10:15:00Z"}
{"sample_id":"row-000002","text":"powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQAuAC4ALgA=","family":"unknown","timestamp":"2026-03-31T10:16:00Z"}
```

Recommended CSV header:

```text
sample_id,text,label,family,timestamp
```

For very large datasets such as 30M samples:

- prefer `JSONL`
- keep one sample per row
- use stable `sample_id` values
- leave `label` empty when unlabeled
- include `family` if you have campaign/template/source grouping
- include `timestamp` if you want time-aware preparation

## Prepare a Corpus

Use corpus preparation before large-scale training:

```bash
conda activate power_mal
python scripts/prepare_corpus.py \
  --input data/raw/your_corpus.jsonl \
  --output data/staging/your_corpus_prepared.jsonl \
  --manifest-output data/staging/your_corpus_manifest.json \
  --text-column text \
  --id-column sample_id \
  --timestamp-column timestamp \
  --metadata-columns source host user process_parent \
  --parser-backend auto \
  --log-level INFO
```

This writes:

- prepared corpus rows
- duplicate hashes
- weak labels
- split hints
- a manifest summary

## Train the Pipeline

Primary complete-pipeline command:

```bash
conda activate power_mal
./scripts/train_and_score_pipeline.sh data/raw/your_corpus.jsonl real_run_001
```

This single command handles the normal workflow:

- load the dataset
- build normalized and parsed feature records
- run cumulative phases such as `10% -> 50% -> 100%`
- train the baseline and boosting models
- calibrate the final combined score
- write phase summaries and review queues
- save the final inference artifact

With custom column names:

```bash
conda activate power_mal
TEXT_COLUMN=script \
ID_COLUMN=sample_id \
LABEL_COLUMN=label \
GROUP_COLUMN=family \
./scripts/train_and_score_pipeline.sh data/raw/your_samples.csv run_csv_demo
```

Optional advanced/manual entrypoint:

```bash
conda activate power_mal
python scripts/run_incremental_pipeline.py \
  --input data/raw/your_corpus.jsonl \
  --output-dir runs/real_run_001 \
  --text-column text \
  --id-column sample_id \
  --label-column label \
  --group-column family \
  --phase-fractions 0.1,0.5,1.0 \
  --validation-fraction 0.2 \
  --parser-backend auto \
  --log-level INFO
```

## Run Inference on Unknown Data

If you already trained a run with the shell wrapper, the saved artifact can be used on unseen data:

```bash
conda activate power_mal
python scripts/run_final_inference.py \
  --artifact runs/real_run_001/final/final_artifact.json \
  --input data/raw/unknown_samples.jsonl \
  --output outputs/unknown_scores.jsonl \
  --summary-output reports/unknown_summary.json \
  --review-queue-output data/review/unknown_review_queue.jsonl \
  --review-queue-summary-output data/review/unknown_review_queue_summary.json \
  --text-column text \
  --id-column sample_id \
  --top-k 25 \
  --explain-top-n 250 \
  --log-level INFO
```

## Compare Models

This is an advanced evaluation command, not the normal project entrypoint.

```bash
conda activate power_mal
python scripts/train_model_suite.py \
  --input data/raw/your_corpus.jsonl \
  --group-column family \
  --split-mode group \
  --selection-objective recall_first
```

This compares:

- rule engine
- hybrid logistic baseline
- numeric boost model
- ensemble

## Audit a Run

This is also an advanced validation command.

```bash
conda activate power_mal
python scripts/audit_run.py runs/real_run_001
```

Use this before trusting headline metrics.

## How to Read the Outputs

Per phase under `runs/<run_name>/phase_*`:

- `scores.jsonl`: scored rows for the full cumulative phase slice
- `review_queue.jsonl`: analyst review queue from those scores
- `validation_scores.jsonl`: holdout-only evaluation rows
- `validation_review_queue.jsonl`: holdout review queue
- `summary.json`: phase metrics, queues, and model weights

Final artifact under `runs/<run_name>/final/`:

- `logistic_final.joblib`
- `numeric_boost_final.joblib`
- `auto_pseudo_labels_all.jsonl`
- `final_artifact.json`

Most important score fields:

- `malicious_probability`
- `malicious_probability_logistic`
- `malicious_probability_boost`
- `second_pass_rule_probability`
- `correction_delta`
- `rule_score`
- `matched_rule_ids`
- `matched_techniques`

Recommended interpretation bands:

- `>= 0.95`: urgent suspicious
- `0.60 - 0.95`: review
- `0.40 - 0.60`: uncertain
- `< 0.40`: lower priority

## Current Position of the Project

What is implemented:

- staged rule coverage for major known PowerShell abuse patterns
- hybrid baseline training
- boosting model stage
- incremental training and pseudo-label flow
- review queue export
- run audit and model-selection tooling

What is not finished yet:

- full deep-learning track
- native AST everywhere by default
- production-grade precision on real enterprise corpora
- `xgboost` and `catboost` backends wired into the active boost model

## Recommended Reading Order

1. [README](README.md)
2. [Project Handoff Report](docs/PROJECT_HANDOFF_REPORT.md)
3. [Implementation Plan](docs/IMPLEMENTATION.md)
4. [Incremental Pipeline](docs/INCREMENTAL_PIPELINE.md)
5. [Attack Patterns](docs/ATTACK_PATTERNS.md)

## Validation

Run tests with:

```bash
pytest -q
```
