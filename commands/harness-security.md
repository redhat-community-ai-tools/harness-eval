---
description: "Deep security audit of the agent setup. Combines deterministic scanning with semantic security review"
---

# Eval Setup Security

Use the Skill tool to invoke `security` explicitly.

Pass through any arguments from $ARGUMENTS (e.g., a specific path to evaluate).

If the Skill tool is not available or the skill is not found, tell the user:
- Check that `skills/security/SKILL.md` exists in the workspace
- If not, reinstall the harness-eval plugin
