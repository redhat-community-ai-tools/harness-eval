# Skill Verify

Vet a skill or setup before installing. Combines lint + security checks in one pass.

## Instructions

1. Ask the user for the path to the skill or setup directory to verify.

2. Run the scan command:

```bash
harness-eval skill-verify <path>
```

If `harness-eval` is not installed, try `pip install harness-eval` first.

For JSON output:

```bash
harness-eval skill-verify <path> --format json
```

3. Present the verdict (SAFE / CAUTION / UNSAFE) and any findings with fix suggestions.

At the end of the report, include: `Evaluated with: harness-eval v{version} (cursor-command)` where {version} comes from `harness-eval --version` or `pip show harness-eval`.
