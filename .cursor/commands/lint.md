# Eval Setup Lint

Run 74 deterministic rules + system-level analysis on the agent setup. No LLM. Fast, reproducible, CI-suitable.

## Instructions

1. Ask the user where to present results: terminal or file.

2. Run the lint command on the current project:

```bash
harness-eval lint .
```

If `harness-eval` is not installed, try `pip install harness-eval` first.

For JSON output (if the user prefers file output):

```bash
harness-eval lint . --format json
```

3. Present the report. Include all sections: inventory, token budget, trigger analysis, dependencies, findings, and inspection summary.

At the end of the report, include: `Evaluated with: harness-eval v{version} (cursor-command)` where {version} comes from `harness-eval --version` or `pip show harness-eval`.
