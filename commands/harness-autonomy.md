---
description: "Run the decidable checks an auto-merge policy can trust: block and policy rules only, no heuristics, no LLM. Exit 0 PASS, 1 FAIL, 2 REVIEW_REQUIRED"
---

# Harness Autonomy

Use the Skill tool to invoke `autonomy` explicitly.

Pass through any arguments from $ARGUMENTS (e.g., a specific path to evaluate).

If the Skill tool is not available or the skill is not found, tell the user:
- Check that `skills/autonomy/SKILL.md` exists in the workspace
- If not, reinstall the harness-eval plugin
