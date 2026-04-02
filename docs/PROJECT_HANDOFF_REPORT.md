# PowerShell Detection System Handoff Report

## 1. Project Purpose

This repository implements a staged PowerShell detection pipeline for large corpora, including partially labeled or fully unlabeled collections.

The design goal is not "one model that magically solves 30 million rows." The design goal is:

- normalize and deobfuscate raw PowerShell text safely
- extract reusable structural, lexical, and rule-based features
- train interpretable high-recall baselines first
- score large datasets incrementally
- export review queues for human validation
- fold reviewed and pseudo labels back into later training phases

The current system is best understood as a recall-first analyst-support pipeline, not a finished production detector.

## 2. Architecture Summary

The pipeline is built as layered modules:

1. `normalize`
   - canonicalizes raw text
   - decodes `-EncodedCommand`, base64, and hex blobs
   - collapses backtick escapes and simple string concatenation
   - keeps `raw_text`, `normalized_text`, `decoded_text`, and `analysis_text`

2. `parse`
   - extracts a lightweight token/command/parameter structure
   - uses a native PowerShell backend if `pwsh` is available
   - otherwise falls back to a dependency-free parser

3. `rules`
   - maps known malicious PowerShell patterns into staged rules
   - produces rule matches, MITRE techniques, and a risk score

4. `features`
   - combines lexical signals, suspicious regex flags, parser artifacts, transforms, and rule-derived features into a single `FeatureRecord`

5. `models`
   - `baseline.py`: hybrid `LogisticRegression` over text TF-IDF plus numeric features
   - `numeric_boost.py`: numeric-only non-linear booster, preferring `LightGBM` when available
   - `weak_labels.py`: assigns weak labels from rules and feature signals when trusted labels are missing

6. `review`
   - stores reviewed labels
   - builds prioritized review queues from scored output

7. `pipeline`
   - orchestrates cumulative multi-phase training, validation, pseudo-labeling, artifact saving, and final inference

8. `eval`
   - chooses the current champion model
   - audits runs for misleading metrics or weak review value

## 3. Code Map

This section is the short explanation of what each important file is responsible for.

### Core package

- `src/psdetect/normalize/canonicalize.py`
  - text canonicalization and safe deobfuscation
  - produces the normalized views used everywhere else

- `src/psdetect/parse/parser.py`
  - parser abstraction
  - prefers native PowerShell parsing when available, falls back otherwise

- `src/psdetect/rules/taxonomy.py`
  - defines known PowerShell attack-pattern rules and MITRE mappings
  - rules are staged by level to support gradual coverage growth

- `src/psdetect/rules/engine.py`
  - evaluates rule matches for a sample
  - returns matched rules, risk score, max severity level, and rule features

- `src/psdetect/features/extract.py`
  - builds the unified `FeatureRecord`
  - this is the bridge between normalization, parsing, rules, and modeling

- `src/psdetect/models/weak_labels.py`
  - turns strong heuristic evidence into provisional labels when no trusted label exists

- `src/psdetect/models/baseline.py`
  - hybrid baseline model
  - uses:
    - character TF-IDF
    - word TF-IDF
    - numeric handcrafted features
  - classifier: `LogisticRegression`
  - also provides explanation output via coefficient contributions

- `src/psdetect/models/numeric_boost.py`
  - non-linear model over only numeric features
  - uses `LightGBM` when installed; otherwise falls back to sklearn `HistGradientBoosting`

- `src/psdetect/review/labels.py`
  - loads and resolves reviewed labels
  - reviewed labels have highest precedence during training

- `src/psdetect/review/queue.py`
  - selects high-priority, disagreement, uncertain, elevated, and control cases for review
  - deduplicates repeated analysis text before exporting queues

- `src/psdetect/data/prepare.py`
  - prepares large corpora for staging
  - computes hashes, duplicates, deterministic splits, weak labels, and metadata carry-through

- `src/psdetect/pipeline/incremental.py`
  - main orchestration logic
  - builds features once
  - trains over cumulative phases
  - calibrates ensemble weights from validation
  - applies second-pass rule correction
  - generates pseudo labels for unlabeled rows
  - saves final inference artifact

- `src/psdetect/eval/model_selection.py`
  - ranks candidate models by `recall_first` or `balanced` objectives

- `src/psdetect/eval/run_audit.py`
  - audits completed runs for leakage, saturated queues, weak holdouts, and overstated metrics

- `src/psdetect/logging_utils.py`
  - shared `loguru` logging setup

### Main scripts

- `scripts/prepare_corpus.py`
  - preprocesses a raw CSV or JSONL corpus into a staging dataset and manifest

- `scripts/run_incremental_pipeline.py`
  - runs the end-to-end phased training pipeline

- `scripts/run_final_inference.py`
  - scores new data with a saved `final_artifact.json`

- `scripts/train_and_score_pipeline.sh`
  - convenience wrapper for one-command training
  - can also optionally run inference after training

- `scripts/train_model_suite.py`
  - compares `rule_engine`, `logistic`, `numeric_boost`, and `ensemble`
  - writes a recommendation for the current champion

- `scripts/audit_run.py`
  - inspects whether a past run is scientifically credible

- `scripts/export_review_queue.py`
  - exports review queues from a scored dataset

- `scripts/init_review_labels.py`
  - creates an empty reviewed-label store

- `scripts/generate_synthetic_dataset.py`
  - creates safe synthetic surrogates for pipeline testing
  - useful for smoke tests, not real-world proof

## 4. Implementation Principles

The repository is based on the following principles.

### Preserve multiple views of the same sample

Never discard the original text. The system preserves:

- `raw_text`: the original input
- `normalized_text`: whitespace-normalized version
- `decoded_text`: expanded content with decode markers retained
- `analysis_text`: the semantically useful text used by rules and models

This matters because forensic review, deduplication, and modeling need different views of the same sample.

### Separate known-pattern detection from learned detection

The rule engine captures known malicious behaviors explicitly. The models then learn broader statistical patterns around them.

This prevents the system from depending entirely on:

- brittle rules
- opaque machine learning

### Optimize for high recall first

The current system is intentionally conservative. Missing real malicious PowerShell is usually more damaging than creating a moderate review queue.

That is why the pipeline supports:

- probability bands
- disagreement queues
- second-pass rule correction
- review-driven retraining

### Treat unlabeled data as a labeling workflow, not as direct supervised training

The 30M-corpus path is:

1. prepare and deduplicate
2. weak-label where possible
3. train on trusted labels plus reviewed labels plus extreme-confidence pseudo labels
4. score the wider corpus
5. review the top-risk and disagreement slices
6. retrain

## 5. Current Model Strategy

### Baseline models in the repository

The current scoring stack uses three channels:

1. Rule engine
   - explicit known-pattern coverage

2. Hybrid logistic baseline
   - sparse text features plus numeric features
   - current default champion in most runs

3. Numeric boosting model
   - numeric-only non-linear detector
   - uses `LightGBM` in the `power_mal` environment

The final score is a corrected weighted combination of these signals, with validation AUCs used to derive the phase weights.

### Why logistic regression is still present

The logistic baseline is not a toy. It is useful because it is:

- fast
- interpretable
- stable
- easy to debug when feature engineering changes

It is the right first model for a system that still depends on evolving labels and review feedback.

### If deep learning is added later

Deep learning should be the next modeling track, not the first dependency.

Recommended upgrade path:

1. keep current rule + baseline pipeline as the reference
2. add a character/subword encoder on `analysis_text`
3. use the deep model first for:
   - embeddings
   - novelty detection
   - second-stage reranking
4. only promote it to the main classifier if it outperforms the calibrated classical stack on real reviewed data

Good deep-learning candidates:

- character CNN or Transformer over `analysis_text`
- token model over normalized command text
- dual-encoder or late-fusion text + AST model when native PowerShell AST is available

## 6. Requirements and Environment Setup

### Option A: Conda environment

The recommended environment in this project is `power_mal`.

```bash
conda activate power_mal
python --version
```

### Option B: Install from requirements

```bash
pip install -r requirements.txt
```

Current `requirements.txt` includes:

- `scikit-learn`
- `pandas`
- `numpy`
- `tqdm`
- `joblib`
- `loguru`
- `lightgbm`
- `xgboost`
- `catboost`

Important note:

- the current `numeric_boost.py` explicitly uses `LightGBM` when available
- `xgboost` and `catboost` are installed candidates, but they are not yet wired in as selectable backends

## 7. Data Format for a Custom 30M Corpus

The pipeline accepts `CSV` and `JSONL`.

### Minimum required fields

- text column

Recommended fields:

- `sample_id`
- `text`
- `label` if any trusted labels exist
- `family` if you have family/campaign or source grouping
- `timestamp` if you want time-aware preparation

### Recommended JSONL format

```json
{"sample_id":"row-000001","text":"powershell.exe -NoProfile -Command \"Get-Service\"","label":"benign","family":"admin_job","timestamp":"2026-03-31T10:15:00Z"}
{"sample_id":"row-000002","text":"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAuAC4ALgApAA==","family":"unknown","timestamp":"2026-03-31T10:16:00Z"}
```

### Recommended CSV columns

```text
sample_id,text,label,family,timestamp
```

### Formatting rules for large corpora

- Keep one sample per row.
- Put the full command or script block in a single text field.
- Use stable `sample_id` values if possible.
- Keep `label` empty if the sample is unlabeled rather than inventing a placeholder class.
- Use `family` for grouping when samples come from the same alert, campaign, template, or source bucket.
- Include timestamps if you want preparation and validation to respect time ordering.

### Strong recommendation for 30M rows

Use `JSONL` rather than a single giant CSV where possible.

Reason:

- better append behavior
- easier sharding
- easier recovery after interruptions
- easier downstream streaming and chunked processing

## 8. Preparing a 30M Dataset

Before full training, stage the corpus first.

Example:

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

What this does:

- builds normalized and decoded views
- computes raw/decoded/analysis hashes
- marks duplicates
- computes weak labels
- creates train/validation/test split hints
- writes a manifest summary

## 9. Running the Pipeline

### Simplest training command

```bash
conda activate power_mal
./scripts/train_and_score_pipeline.sh data/raw/your_corpus.jsonl real_run_001
```

This wrapper runs:

- incremental phase training
- validation per phase
- review-queue export per phase
- final artifact creation

By default it does not rescore the training data after training.

### Training with custom column names

```bash
conda activate power_mal
TEXT_COLUMN=script \
ID_COLUMN=sample_id \
LABEL_COLUMN=label \
GROUP_COLUMN=family \
./scripts/train_and_score_pipeline.sh data/raw/ps_samples_50.csv sample_demo
```

### Direct incremental runner

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

### Inference on new unknown data

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

### Model-suite comparison

```bash
conda activate power_mal
python scripts/train_model_suite.py \
  --input data/raw/your_corpus.jsonl \
  --group-column family \
  --split-mode group \
  --selection-objective recall_first
```

### Audit a run

```bash
conda activate power_mal
python scripts/audit_run.py runs/real_run_001
```

## 10. What the Pipeline Writes

For each phase such as `runs/real_run_001/phase_3_100pct/`:

- `scores.jsonl`
  - operational scores for the whole cumulative slice

- `review_queue.jsonl`
  - analyst queue built from `scores.jsonl`

- `validation_scores.jsonl`
  - holdout-only evaluation rows

- `validation_review_queue.jsonl`
  - holdout review subset

- `auto_pseudo_labels.jsonl`
  - pseudo labels created in that phase

- `summary.json`
  - the most important per-phase report

Final output in `runs/real_run_001/final/`:

- `logistic_final.joblib`
- `numeric_boost_final.joblib`
- `auto_pseudo_labels_all.jsonl`
- `final_artifact.json`

## 11. How to Interpret the Results

### Main score fields

In scored outputs, the most important columns are:

- `malicious_probability`
  - final corrected probability

- `malicious_probability_logistic`
  - probability from the hybrid logistic model

- `malicious_probability_boost`
  - probability from the numeric boosting model

- `second_pass_rule_probability`
  - probability derived from the decoded/rule pass

- `correction_delta`
  - how much the corrected score differs from the logistic channel

- `rule_score`
  - known-pattern risk score from the rule engine

- `matched_rule_ids`
  - rule IDs that fired

- `matched_techniques`
  - mapped MITRE techniques

### Recommended operating bands

Use probability bands instead of a single hard threshold:

- `>= 0.95`
  - urgent suspicious

- `0.60 - 0.95`
  - review queue

- `0.40 - 0.60`
  - uncertain, good candidates for second-pass review or labeling

- `< 0.40`
  - lower priority, but still sample a small fraction for control review

### What good results should look like

On real data, a credible run should show:

- low or zero group overlap in holdout splits
- meaningful holdout diversity
- strong malicious recall
- review queues that are not dominated by one template
- some pseudo-label activity on unlabeled data
- audit results that do not flag the run as `overstated`

### What not to trust

Do not trust:

- perfect metrics on synthetic-only data
- phase scores interpreted as holdout evaluation
- review queues saturated by one template family
- any single threshold without analyst feedback

## 12. How Reviewed Labels Fit Back Into Training

The label precedence in the pipeline is:

1. reviewed labels
2. input labels
3. pseudo labels
4. weak labels

This is intentional.

It ensures the system improves with human feedback instead of becoming trapped by synthetic or heuristic labels.

## 13. Present Limitations

The project is in a strong prototype state, but these limitations still matter:

- native PowerShell AST is only used when `pwsh` is available
- the current deep-learning path is planned, not implemented
- current model quality is stronger on recall than precision
- synthetic corpora are useful for testing, not for proving real-world robustness
- `xgboost` and `catboost` are installed candidates but not yet active backends in `numeric_boost.py`

## 14. Recommended Next Steps

1. Run the fixed pipeline on the real external corpus, not only on synthetic data.
2. Build a reviewed-label store from the first review queues.
3. Re-run model selection under the `power_mal` environment using `LightGBM`.
4. Add backend selection for `xgboost` and `catboost`.
5. Add a deep text encoder only after the reviewed-label pool is large enough to compare it honestly.

## 15. Minimum Handoff Checklist

Before handing this to another engineer or analyst, they should be given:

- this report
- `docs/IMPLEMENTATION.md`
- `docs/ATTACK_PATTERNS.md`
- `docs/INCREMENTAL_PIPELINE.md`
- `docs/MODEL_SELECTION.md`
- `docs/REVIEW_WORKFLOW.md`
- a sample training run directory under `runs/`
- one known inference output and review queue

That is enough for an experienced reader to:

- understand the code structure
- prepare their own corpus
- execute the training pipeline
- run inference on unknown data
- interpret the resulting outputs
