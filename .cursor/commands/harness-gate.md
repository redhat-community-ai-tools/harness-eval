# Harness Gate

Gate the agent setup on corpus-validated rules (gating tier). Fast, no LLM, exits nonzero on any finding. Suitable for CI and pre-commit.

## Instructions

1. Run the gate command on the current project:

```bash
uvx --from harness-eval harness-eval harness-gate .
```

This runs only the gating-tier rules (validated at >=97% precision on re-derived corpus findings) and exits 1 on any finding.

Useful flags:
- `--include-provisional` — also run provisional-tier rules.
- `--format json` or `--format sarif` — machine-readable output.
- `--baseline <file>` — suppress findings recorded in a baseline.

If `uvx` is not available, fall back to `pip install harness-eval` and use `harness-eval` directly.

2. Report each finding as: rule id, file, and message. If there are no findings, report that the gate passed.
