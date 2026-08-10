---
name: skill-verify
description: Vet a skill or setup before installing. Combines lint + security in one pass. SAFE/CAUTION/UNSAFE verdict. Use when the user wants to check if a downloaded or cloned skill is safe to install.
allowed-tools:
  - Bash
  - Read
---
<!-- evaluator-ignore: content/allowed-tools-auto-approve -->

# Skill Verify

Vet a skill or setup for security and quality issues before installing.

## Hard Rules

1. **Run the CLI command.** Do not skip the scan.
2. **Report the verdict clearly.** SAFE, CAUTION, or UNSAFE.
3. **Show all findings with fix suggestions.**

## Step 1: Get the Path

Ask the user for the path to the skill or setup directory to verify. If they provide a URL, clone it first:

```bash
git clone --depth 1 <url> /tmp/skill-to-verify
```

## Step 2: Run the Scan

```bash
harness-eval skill-verify <path> --format json
```

If `harness-eval` is not installed, install it first: `pip install harness-eval`

Read the JSON output.

## Step 3: Present the Results

Report the verdict prominently: **SAFE**, **CAUTION**, or **UNSAFE**.

List all findings with their severity, rule, message, and fix suggestion.

If UNSAFE, tell the user not to install without addressing the findings.
If CAUTION, tell the user to review the warnings before installing.
If SAFE, tell the user it's safe to install.
