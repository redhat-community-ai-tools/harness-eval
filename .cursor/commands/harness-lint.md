<!-- evaluator-ignore: command/references-nonexistent-skill -->
# Eval Setup Lint

Run 96 deterministic rules + system-level analysis on the agent setup. No LLM. Fast, reproducible, CI-suitable.

## Instructions

1. Ask the user where to present results: terminal or file.

2. Run the lint command on the current project:

```bash
uvx --from harness-eval harness-eval harness-lint .
```

For JSON output (if the user prefers file output):

```bash
uvx --from harness-eval harness-eval harness-lint . --format json
```

If `uvx` is not available, fall back to `pip install harness-eval` and use `harness-eval` directly.

3. Present the report. Include all sections: inventory, token budget, trigger analysis, dependencies, findings, and inspection summary.

At the end of the report, include: `Evaluated with: harness-eval v{version} (cursor-command)` where {version} comes from `uvx --from harness-eval harness-eval --version` or `pip show harness-eval`.
