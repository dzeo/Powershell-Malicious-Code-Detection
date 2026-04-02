# PowerShell Detection System Implementation Plan

## Objective

Build a research-grade PowerShell detection system that can score very large corpora, tolerate heavy obfuscation, and remain useful even when the raw 30M-sample dataset does not include a trusted target variable.

The system should support three separate outcomes:

1. High-confidence malicious detection.
2. Novelty detection for previously unseen families.
3. Analyst triage and family discovery on the suspicious tail.

## Short Answer: Are We Using Deep Learning?

Yes, but not as the first dependency for the project.

Recommended order:

1. Start with a hybrid-feature baseline using classical ML.
2. Add weak supervision and confident pseudo-labels.
3. Add deep learning only after the baseline and data pipeline are stable.

Reason:

- With no trusted labels, deep learning is easy to overfit and hard to calibrate.
- A hybrid gradient-boosted baseline is easier to debug, faster to train, and easier to explain to analysts.
- Deep models become useful later for sequence understanding, AST representation learning, and embedding-based novelty detection.

## Proposed System

### Layer 1: Ingestion and Canonicalization

Input formats:

- CSV / JSONL / text dumps
- AMSI captures
- Script block logs
- PowerShell command lines

Transformations:

- Preserve `raw_text`
- Normalize whitespace and casing where appropriate
- Recursively decode:
  - `-EncodedCommand`
  - Base64 blobs
  - hex blobs
  - gzip / deflate wrappers
  - backtick escapes
  - simple string concatenation
  - `[char]`-style character construction
- Preserve both `normalized_text` and `decoded_text`

Important design rule:

Never overwrite the original sample. The detector should retain raw, normalized, and decoded views for both modeling and forensic review.

### Layer 2: Structural Parsing

Parse with the PowerShell AST and token stream.

Core extracted artifacts:

- AST node histogram
- command names
- parameter names
- string literal statistics
- parse errors
- alias usage
- subtree motifs
- token sequence

Why:

Regex-only features are too brittle for obfuscated PowerShell. AST structure gives a stronger signal for intent and is harder to evade with simple string tricks.

### Layer 3: Multi-View Features

The feature store should combine:

- lexical features
  - character entropy
  - length features
  - non-alphanumeric ratios
  - base64 / hex indicators
- token features
  - command n-grams
  - parameter n-grams
  - subword features
  - alias-to-canonical ratios
- AST features
  - node counts
  - subtree signatures
  - control-flow patterns
  - reflection / dynamic invocation motifs
- behavioral heuristics
  - download / execution chaining
  - encoded invocation
  - hidden or noninteractive execution
  - persistence paths
  - registry modification motifs
  - AMSI tampering references
- context features
  - process lineage if available
  - host role
  - user / service context
  - time-of-day patterns

### Layer 4: Modeling Strategy

#### Phase A: Baseline Classifier

Primary baseline:

- LightGBM or XGBoost on hybrid features

Why this is first:

- strong tabular performance
- good with mixed dense and sparse features
- easier feature inspection
- fast iteration over millions of rows

#### Phase B: Novelty Detection

Apply novelty detection on either:

- calibrated classifier residuals, or
- learned embeddings from the deep model

Recommended use:

- one-class model or Isolation Forest on the suspicious tail
- only after the main classifier is stable

This is where anomaly detection belongs in the design.

#### Phase C: Deep Learning

Deep learning becomes the second modeling track, not the first.

Recommended candidates:

- character CNN / BiLSTM / Transformer on normalized command text
- token Transformer on command and AST token streams
- dual-encoder or late-fusion model combining text and AST representations

Recommended initial role:

- embedding generation
- reranking the suspicious tail
- robustness to obfuscation variants

Do not make the entire project depend on a deep model at the start.

### Layer 5: Clustering for Analyst Triage

Use clustering only on a reduced suspicious subset.

Recommended flow:

1. Score entire corpus.
2. Keep top suspicious fraction.
3. Build embeddings for that subset.
4. Cluster for family discovery and sample review.

Do not run UMAP/HDBSCAN on all 30M rows.

## What We Do Without Ground-Truth Labels

The absence of a target variable changes the project, but it does not block it.

Recommended labeling strategy:

1. Weak labels
   - high-confidence suspicious rules
   - threat intel matches
   - known admin allowlists
   - known internal automation repositories
2. Analyst-reviewed seed set
   - manually review a few thousand diverse samples
3. Positive-unlabeled learning or confident-learning style cleanup
4. Time-based validation
   - train on older data
   - validate on newer data

Synthetic data can help only with:

- pipeline testing
- parser hardening
- regression tests
- controlled obfuscation experiments

Synthetic labels are not a replacement for real-world validation.

## Evaluation Plan

Primary metrics:

- precision at top-k
- recall at fixed low false-positive rates
- AUROC and AUPRC on reviewed subsets
- family coverage on clustered suspicious samples
- robustness under obfuscation transforms

Operational metrics:

- analyst review rate
- duplicate collapse rate
- scoring throughput
- percent of samples that fail parsing

Failure tests:

- encoded benign admin scripts
- compressed payload wrappers
- partially corrupted base64
- rare but legitimate enterprise automation

## Implementation Phases

### Phase 0: Repo Foundation

- package layout
- docs
- synthetic safe sample generation
- logging and config

### Phase 1: Data Pipeline

- ingestion readers
- normalization
- recursive decoding
- deduplication
- metadata capture

### Phase 2: Feature Extraction

- lexical features
- token features
- AST features
- heuristic signals

### Phase 3: Baseline Models

- hybrid tabular baseline
- score calibration
- thresholding
- score serialization

### Phase 4: Deep Representation Track

- character or token encoder
- embedding export
- novelty scoring on embeddings

### Phase 5: Analyst Triage

- suspicious-tail clustering
- sample surfacing
- cluster summaries

## Proposed Repository Layout

```text
Powershell Malicious Code Detection/
├── data/
│   ├── raw/
│   ├── staging/
│   ├── synthetic/
│   └── features/
├── docs/
│   └── IMPLEMENTATION.md
├── models/
├── outputs/
├── reports/
├── scripts/
│   └── generate_synthetic_dataset.py
├── src/
│   └── psdetect/
│       ├── __init__.py
│       ├── generation/
│       │   ├── __init__.py
│       │   └── synthetic.py
│       ├── normalize/
│       ├── parse/
│       ├── features/
│       ├── models/
│       └── eval/
├── tests/
├── requirements.txt
└── sample_code.py
```

## Decisions For This Repo Right Now

Immediate build decisions:

- Keep `sample_code.py` as a prototype reference for now.
- Build the new implementation under `src/psdetect`.
- Use synthetic safe-surrogate samples for early testing.
- Treat deep learning as a planned second track, not the first deliverable.

## Preview Of The Next Deliverables

1. Safe synthetic sample generator.
2. Canonicalization module.
3. AST parsing module.
4. Feature extraction module.
5. Baseline training pipeline.
6. Weak-labeling and evaluation workflow.
