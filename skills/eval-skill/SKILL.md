---
name: eval-skill
description: Deep-evaluate a single skill with static analysis and qualitative issue detection, both individually and in context of the full setup. Use when the user wants to check if a specific skill is worth keeping, well-built, or redundant.
allowed-tools:
  - Bash
  - Read
---
<!-- evaluator-ignore: content/broken-references, content/allowed-tools-auto-approve -->

# Evaluate Skill

Deep-evaluate a single skill using lint (deterministic rules) and qualitative review, both individually and in context of the full setup.

## Hard Rules

1. **Never give a verdict without running the checks.** Read the actual file content and check all rubric categories before assigning a verdict.
2. **Every category must be checked.** Both the individual rubric AND the contextual analysis must be fully evaluated.
3. **Read before you judge.** Read the actual SKILL.md content (and reference files if they exist).
4. **Don't manufacture problems.** If the skill is good, say so. Only report real issues.
5. **Always end with a short summary.**
6. **Record the exact start time** and compute the exact duration at the end.

## Step 1: Ask Output Preference

Before doing anything else, ask the user:

> Where should i present the results?
> 1. **Terminal** - print the report here in the conversation
> 2. **File** - write a markdown report to a file (you'll choose the path)

Wait for their answer before proceeding.

## Step 2: Select the Skill

Determine the skill path. If the user says a skill name, find it under `skills/<name>/SKILL.md`.

## Step 3: Run Lint (Static Analysis)

Determine the setup context path (usually the current working directory).

```bash
uvx --from harness-eval harness-eval skill-review <skill-path> --context <context-path> --format json

If `uvx` is not available, fall back to `pip install harness-eval` and use `harness-eval` directly.
```

If no context path, omit the `--context` flag.

Read the JSON output. It contains diagnostics, token count, and contextual findings. This runs the recommended preset (quality + structural rules). For full security vetting, use `/skill-verify` instead.

## Step 4: Read Actual Files

Read the skill's actual content:
1. The SKILL.md file
2. All files in the skill's subdirectories (reference files). Check the COMBINED content.
3. The skill's guidelines.md (if it exists)

Also read for context (don't check these, they're context for evaluating the target skill):
4. All OTHER skill SKILL.md files in the workspace
5. CLAUDE.md
6. Hooks in .claude/settings.json

## Step 5: Individual Rubric (Qualitative Review)

Read `rubric/skills-rubric.md` for the issue categories and what to flag.

Check the skill against all categories. For each issue found, cite specific evidence from the content.

Verdict: **KEEP** (no issues or minor only), **REVIEW** (multiple issues), **REMOVE** (fundamentally broken/redundant)

## Step 6: Contextual Analysis

Read `rubric/contextual-analysis.md` and evaluate all 5 contextual dimensions.

Check redundancy against three sources:
- Claude's default behavior (generic advice = redundant)
- Other skills in the workspace (overlap = partially redundant)
- CLAUDE.md content (duplication = wasted tokens)

## Step 7: Produce the Report

Read `report-format.md` for the full report structure.

The report must include:
- Lint results: each failed rule with WHY it failed
- Qualitative review issues (by category)
- Contextual analysis
- +/!/x sections (good, improve, broken)
- Final verdict with suggestions

At the very end:

```
Evaluated with: harness-eval v{version} (claude-code-plugin)
Duration: [X minutes Y seconds]
```

Get `{version}` by running: `uvx --from harness-eval harness-eval --version`

**If the user chose terminal:** print the report in the conversation.

**If the user chose file:** write the report as markdown to the path they specified (or suggest `skill-report.md` in the current directory). Tell them the file path when done.
