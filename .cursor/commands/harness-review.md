# Eval Setup Review

Full qualitative review of the agent setup. Read every file, evaluate quality, redundancy, and optimization opportunities. Produce KEEP/REVIEW/REMOVE verdicts per component.

## Hard Rules

1. Never give a verdict without reading the files.
2. Read before you judge. Read every file's actual content before assessing.
3. Don't manufacture problems. If the setup is good, say so.

## Step 1: Ask Output Preference

Ask the user: print the report in conversation, or write to a file?

## Step 2: Run Lint for Context

Run the deterministic scan first to get structural data:

```bash
harness-eval lint . --format json
```

If `harness-eval` is not installed, try `pip install harness-eval` first.

Read the JSON output. Use it as context for the qualitative review. Do NOT present the lint report separately.

## Step 3: Read Actual Files

Read the actual content of every component discovered: `.cursor/rules/*.mdc` files, `.cursorrules`, `.cursor/commands/*.md`, skill SKILL.md files (including reference files in subdirectories), and `.cursor/hooks.json`.

## Step 4: Evaluate Each Component

For each component, provide:
- Lint results: list each rule that failed and explain WHY it failed in one sentence
- A 2-3 sentence qualitative assessment (what it does, whether it adds value, whether it's well-built)
- Issues found, citing specific content
- Verdict: **KEEP**, **REVIEW**, or **REMOVE**

Evaluate across these areas:
- **Specificity**: does each component add value the AI doesn't already have? Would deleting it change behavior?
- **Redundancy**: does it duplicate content from other components or the AI's default behavior?
- **Trigger quality**: are descriptions specific enough to route correctly? Any overlapping triggers?
- **Token efficiency**: are components under 500 lines? Is content split between main file and references?
- **Instruction clarity**: contradictions, vague language, buried rules, orphaned conditionals?
- **Impact**: for each issue, what will go wrong at runtime if this isn't fixed?

## Step 5: Cross-Component Optimization

Check whether components should be transformed, merged, or removed:
- Should any rule/skill be a hook instead?
- Are two components redundant with each other?
- Does any component duplicate what the AI already does by default?

## Step 6: Produce the Report

Include:
1. Inventory table (component name, type, tokens)
2. Token budget breakdown (always-loaded vs on-demand)
3. Evaluation summary (headline verdict)
4. Per-component analysis (lint + qualitative review + verdict)
5. Numbered improvement suggestions

At the end of the report, include: `Evaluated with: harness-eval v{version} (cursor-command)` where {version} comes from `harness-eval --version` or `pip show harness-eval`.
