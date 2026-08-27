---
description: "Gate the agent setup on corpus-validated rules (gating tier). Fast, no LLM, exits nonzero on any finding — suitable for CI and pre-commit"
---

# Harness Gate

Run the validated gate on the current project:

```bash
harness-eval harness-gate .
```

This runs only the gating-tier rules (validated at >=97% precision on re-derived corpus findings; see `docs/rule-taxonomy.md`) and exits 1 on any finding.

Useful flags:
- `--include-provisional` — also run provisional-tier rules.
- `--format json` or `--format sarif` — machine-readable output.
- `--baseline <file>` — suppress findings recorded in a baseline.

If `harness-eval` is not installed, run it with `uvx --from harness-eval harness-eval harness-gate .`.

Report each finding as: rule id, file, and message.
