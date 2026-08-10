---
name: lint
description: Run deterministic static analysis on the full agent setup (CLAUDE.md, skills, commands, hooks, agents, MCP configs). 92 rules + system-level analysis (token budget, trigger overlaps, dependencies). No LLM. Use when the user wants a fast lint check, CI gate, or structural health report.
allowed-tools:
  - Bash
  - Read
---
<!-- evaluator-ignore: content/broken-references, security/mcp-least-privilege, security/ast-behavioral, content/allowed-tools-auto-approve -->

# Lint Setup

Run 92 deterministic rules + system-level analysis on the user's agent setup. No LLM involved. Fast, reproducible, CI-suitable.

## Hard Rules

1. **This skill does NOT read files qualitatively.** It does NOT apply rubrics. It does NOT run cross-type checks. For that, use `/review`.
2. **Present the data, don't judge.** Report findings as-is. Don't add qualitative commentary.
3. **If everything passes, say so clearly.** Don't manufacture problems.

## Step 1: Ask Output Preference

Before doing anything else, ask the user:

> Where should i present the results?
> 1. **Terminal** - print the report here in the conversation
> 2. **File** - write a markdown report to a file (you'll choose the path)

Wait for their answer before proceeding.

## Step 2: Run Static Analysis

Determine the setup path. If the user doesn't specify one, use the current working directory.

```bash
harness-eval harness-lint <setup-path> --format json
```

If `harness-eval` is not installed, install it first: `pip install harness-eval`

Read the JSON output.

## Step 3: Present the Report

Read `report-format.md` and format the results following that structure.

Include all sections: inventory, token budget, context utilization, trigger analysis, dependencies, findings, and inspection summary.

At the very end of the report, include the exact timing:

```
Evaluated with: harness-eval v{version} (claude-code-plugin)
Duration: [X minutes Y seconds]
```

Get `{version}` by running: `harness-eval --version`

Record the timestamp of your first tool call in Step 2 and compute the exact difference when you finish.

**If the user chose terminal:** print the report in the conversation.

**If the user chose file:** write the report as markdown to the path they specified (or suggest `lint-report.md` in the current directory). Tell them the file path when done.
