<!-- evaluator-ignore: command/references-nonexistent-skill -->
# Eval Skill

Deep-evaluate a single skill with static analysis and qualitative review, both individually and in context of the full setup.

## Arguments

$ARGUMENTS should be the skill name or path to the skill directory.

## Hard Rules

1. Never give a verdict without running the checks and reading the actual content.
2. Every rubric category must be checked.
3. Don't manufacture problems. If the skill is good, say so.

## Step 1: Ask Output Preference

Ask the user: print the report in conversation, or write to a file?

## Step 2: Select the Skill

Determine the skill path from $ARGUMENTS. If the user says a skill name, find it under `skills/<name>/SKILL.md` or `.cursor/skills/<name>/SKILL.md`.

## Step 3: Run Lint

```bash
uvx --from harness-eval harness-eval skill-review <skill-path> --context .
```

If `uvx` is not available, fall back to `pip install harness-eval` and use `harness-eval` directly.

Read the output for diagnostics, token count, and contextual findings.

## Step 4: Read Actual Files

Read:
1. The skill's SKILL.md file
2. All files in the skill's subdirectories (reference files)
3. All OTHER skill SKILL.md files in the workspace (for context)
4. System instructions (.cursor/rules/*.mdc, .cursorrules, CLAUDE.md)

## Step 5: Qualitative Review

Evaluate the skill against these categories:
- **Specificity**: vague platitudes vs actionable patterns
- **Redundancy**: duplicates the AI's default behavior?
- **Trigger quality**: description missing/broad/narrow?
- **Token efficiency**: over 500 lines? Should be split?
- **Instruction clarity**: contradictions, vague language, hedging?
- **Content quality**: no structure, no examples, missing edge cases?

For each issue found, cite specific evidence from the content.

## Step 6: Contextual Analysis

Check redundancy against three sources:
- The AI's default behavior (generic advice = redundant)
- Other skills in the workspace (overlap = partially redundant)
- System instructions content (duplication = wasted tokens)

## Step 7: Produce the Report

Include:
- Lint results: each failed rule with WHY it failed
- Qualitative review issues (by category)
- Contextual analysis
- What's good / what needs improvement / what's broken
- Final verdict: **KEEP**, **REVIEW**, or **REMOVE**

At the end of the report, include: `Evaluated with: harness-eval v{version} (cursor-command)` where {version} comes from `uvx --from harness-eval harness-eval --version` or `pip show harness-eval`.
