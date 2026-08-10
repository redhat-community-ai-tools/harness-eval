---
description: "Deep-evaluate a single skill with static analysis and qualitative review, both individually and in context of the full setup"
---

# Eval Skill

Use the Skill tool to invoke `eval-skill` explicitly.

Pass through any arguments from $ARGUMENTS (e.g., a specific path to evaluate).

If the Skill tool is not available or the skill is not found, tell the user:
- Check that `skills/eval-skill/SKILL.md` exists in the workspace
- If not, reinstall the harness-eval plugin
