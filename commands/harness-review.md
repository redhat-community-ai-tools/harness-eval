---
description: "Full qualitative review of the agent setup. Read every file, evaluate quality, redundancy, and optimization opportunities. Produce KEEP/REVIEW/REMOVE verdicts per component"
---

# Eval Setup Review

Use the Skill tool to invoke `review` explicitly.

Pass through any arguments from $ARGUMENTS (e.g., a specific path to evaluate).

If the Skill tool is not available or the skill is not found, tell the user:
- Check that `skills/review/SKILL.md` exists in the workspace
- If not, reinstall the harness-eval plugin
