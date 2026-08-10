---
description: "Vet a skill or setup before installing. Combines lint + security checks in one pass."
---

# Skill Verify

Use the Skill tool to invoke `skill-verify` explicitly.

Pass through any arguments from $ARGUMENTS (e.g., a specific path to verify).

If the Skill tool is not available or the skill is not found, tell the user:
- Check that `skills/skill-verify/SKILL.md` exists in the workspace
- If not, reinstall the harness-eval plugin
