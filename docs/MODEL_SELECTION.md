# Model Selection

## Current Models

The pipeline currently uses three detector stages:

1. `rule_engine`
   Known-pattern detection from the staged PowerShell taxonomy.

2. `logistic`
   Implemented in `HybridPowerShellDetector`.
   This is a linear model over:
   - character n-grams
   - word n-grams
   - handcrafted numeric and rule features

3. `numeric_boost`
   Implemented in `NumericBoostPowerShellDetector`.
   This uses:
   - `LightGBM` if installed
   - otherwise sklearn `HistGradientBoosting`

The suite also compares:

4. `ensemble_avg`
   Simple average of logistic and numeric-boost probabilities.

## What We Use Right Now

The main production-style path currently relies most on the hybrid logistic model plus rule correction.

Why:

- it is fast
- it is interpretable
- it gives per-feature explanations
- it has been more stable than the current fallback boost backend

## Are We Using Boosting?

Yes.

The repo already has a boosting stage in `src/psdetect/models/numeric_boost.py`.

Important caveat:

- in this environment, `LightGBM` is not installed
- so the code falls back to `HistGradientBoosting`
- that fallback is useful for experimentation, but it is not the final strong booster we want

For serious large-scale use, the intended boosting backend is `LightGBM`.

## How We Choose The Best Model

Use:

```bash
python3 scripts/train_model_suite.py \
  --input data/your_data.jsonl \
  --group-column family \
  --split-mode group \
  --selection-objective recall_first
```

The suite now writes a `selection` block in the report.

Selection objectives:

- `recall_first`
  Best when missing malicious samples is the main risk.
  Ranking priority:
  - malicious recall
  - malicious precision
  - ROC-AUC
  - malicious F1
  - accuracy

- `balanced`
  Best when you want a more even precision/recall tradeoff.
  Ranking priority:
  - malicious F1
  - ROC-AUC
  - malicious recall
  - malicious precision
  - accuracy

## What A Good Champion Looks Like

For this project, a good champion should:

- keep malicious recall high
- avoid extreme false positive inflation on benign enterprise automation
- remain stable across held-out families
- still rank suspicious samples above benign wrappers

That means model choice is not just:

- highest ROC-AUC

It is:

- highest useful recall at an acceptable analyst load

## Deep Learning Plan

Deep learning is not the first dependency here. It is the second-stage upgrade after labels improve.

Recommended order:

1. Strong classical baseline
   - hybrid logistic
   - LightGBM
   - calibrated ensemble

2. Better labels
   - reviewed false positives and true positives
   - weak labels
   - external corpora

3. Deep models

Recommended deep-learning tracks:

- char-level model
  Best for:
  - obfuscation
  - encoded fragments
  - strange lexical structure

- token/subword Transformer
  Best for:
  - PowerShell semantics
  - command/parameter interactions
  - long wrapper patterns

- AST-aware model
  Best later, after stable native parsing is available.

- embedding model for novelty detection
  Best for:
  - clustering suspicious tails
  - finding unseen families
  - nearest-neighbor analyst triage

## How Deep Learning Would Enter This Repo

The practical path would be:

1. keep the current feature pipeline
2. add a deep text encoder that consumes `analysis_text`
3. train it on reviewed + weak labels
4. use its output in one of two ways:
   - standalone classifier
   - embedding features added to LightGBM / logistic / ensemble

The safer first deep-learning version is:

- char/subword encoder for embeddings
- use embeddings as extra features or for reranking

That is lower-risk than replacing the current interpretable baseline immediately.
