# Run Audit

Use the audit script after a pipeline run to decide whether the result is genuinely informative or just an easy synthetic win.

## Run

```bash
python3 scripts/audit_run.py runs/test_2
```

This writes `audit_report.json` into the run directory.

## What It Flags

- group leakage
- suspiciously perfect metrics
- too few held-out groups
- review queue saturation
- queues dominated by one family
- no pseudo-label activity
- runs trained only on input labels
- large rule-stage instability across phases

## Interpretation

- `promising`
  The run has no major audit warnings, but it still does not replace real-data evaluation.
- `needs_real_data`
  The run is structurally valid but still too synthetic, too narrow, or too review-light to trust.
- `overstated`
  The metrics are likely flattering the model and should not be treated as evidence of real robustness.
- `invalid`
  The split or run structure is broken enough that the result should not be used.
