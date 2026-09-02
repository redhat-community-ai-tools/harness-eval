---
description: "Run 108 deterministic rules + system-level analysis on the agent setup. No LLM. Fast, reproducible, CI-suitable"
---

# Eval Setup Lint

Use the Skill tool to invoke `lint` explicitly.

Pass through any arguments from $ARGUMENTS (e.g., a specific path to evaluate).

If the Skill tool is not available or the skill is not found, tell the user:
- Check that `skills/lint/SKILL.md` exists in the workspace
- If not, reinstall the harness-eval plugin
