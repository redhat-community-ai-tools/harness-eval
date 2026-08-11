---
name: review
description: Full qualitative review of the agent setup. Reads every file, applies per-component rubrics, runs 21 cross-type optimization checks, and produces KEEP/REVIEW/REMOVE verdicts. Use when the user wants a deep review, redundancy check, or quality assessment of their setup.
allowed-tools:
  - Bash
  - Read
---
<!-- evaluator-ignore: content/broken-references, content/allowed-tools-auto-approve -->

# Review Setup

Full qualitative review of the user's agent setup. Claude reads every file and evaluates quality, redundancy, coherence, and optimization opportunities.

## Hard Rules

1. **Never give a verdict without reading the files.** Lint counts are input data, not the verdict. A component with warnings can still be healthy.
2. **Read before you judge.** Read every file's actual content before assessing.
3. **Don't manufacture problems.** If the setup is good, say so.
4. **Always end with the evidence-based summary.**
5. **Record the exact start time** (note the timestamp from your first tool call in Step 2) and compute the exact duration at the end.

## Step 1: Ask Output Preference

Before doing anything else, ask the user:

> Where should i present the results?
> 1. **Terminal** - print the report here in the conversation
> 2. **File** - write a markdown report to a file (you'll choose the path)

Wait for their answer before proceeding.

## Step 2: Run Lint for Context

Determine the setup path. If the user doesn't specify one, use the current working directory.

```bash
uvx --from harness-eval harness-eval harness-lint <setup-path> --format json
```

Read the JSON output. This gives you per-component diagnostics, token budget, trigger overlaps, and dependency findings.

Do NOT present the lint report separately. Use it as context for the qualitative review.

## Step 3: Read Actual Files

Read the actual content of every component: SKILL.md files (including reference files in subdirectories), command files, agent files, CLAUDE.md, and settings.json for hooks.

## Step 4: Analyze Each Component

For each component, provide:
- Lint results: list each rule that failed and explain WHY it failed in one sentence
- A 2-3 sentence qualitative assessment (what it does, whether it adds value, whether it's well-built)
- Issues found, citing specific content
- Per-component verdict: KEEP, REVIEW, or REMOVE

For lint failures, use this format:
```
Lint: 3 failures
  FAIL  broken-references — 5 referenced files don't exist in this directory (scripts/foo.sh, etc.)
  FAIL  token-budget — SKILL.md is 915 lines, 3.6x over the 500-line recommendation
  FAIL  mcp-least-privilege — allowed-tools declares Bash but no script uses shell commands
```

Use the per-component rubric files for detailed criteria:
- Skills: read `rubric/skills-rubric.md`
- CLAUDE.md: read `rubric/claude-md-rubric.md`
- Commands: read `rubric/commands-rubric.md`
- Agents: read `rubric/agents-rubric.md`
- Hooks: read `rubric/hooks-rubric.md`

## Step 5: Cross-Type Optimization

Read `rubric/cross-type-checks.md` and answer all 21 checks with YES/NO and a one-line explanation. These check whether components should be transformed (skill to hook?), merged, or removed.

## Step 6: Produce the Report

Read `report-format.md` for the full report structure. The report sections must appear in this order:
1. What this evaluation checks (hardcoded intro)
2. Inventory table
3. Token budget breakdown
4. Evaluation summary (the headline verdict)
5. Cross-type optimization (21 checks)
6. Numbered suggestions
7. Per-component analysis (lint + qualitative review)

At the very end of the report, include the exact timing:

```
Evaluated with: harness-eval v{version} (claude-code-plugin)
Duration: [X minutes Y seconds]
```

Get `{version}` by running: `uvx --from harness-eval harness-eval --version`

Compute this from the timestamp of your first tool call in Step 2 to the timestamp when you finish writing the report.

**If the user chose terminal:** print the report in the conversation.

**If the user chose file:** write the report as markdown to the path they specified (or suggest `review-report.md` in the current directory). Tell them the file path when done.
