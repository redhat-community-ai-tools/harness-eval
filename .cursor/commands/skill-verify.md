<!-- evaluator-ignore: command/references-nonexistent-skill -->
# Skill Verify

Vet a skill or setup before installing. Combines lint + security checks in one pass.

## Instructions

1. Ask the user for the path to the skill or setup directory to verify.

2. Run the scan command:

```bash
uvx --from harness-eval harness-eval skill-verify <path>
```

For JSON output:

```bash
uvx --from harness-eval harness-eval skill-verify <path> --format json
```

If `uvx` is not available, fall back to `pip install harness-eval` and use `harness-eval` directly.

3. Present the verdict (SAFE / CAUTION / UNSAFE) and any findings with fix suggestions.

At the end of the report, include: `Evaluated with: harness-eval v{version} (cursor-command)` where {version} comes from `uvx --from harness-eval harness-eval --version` or `pip show harness-eval`.
