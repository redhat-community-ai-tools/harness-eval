---
description: "Gate the agent setup on corpus-validated rules (gating tier). Fast, no LLM, exits nonzero on any finding. Suitable for CI and pre-commit"
---

# Harness Gate

Use the Skill tool to invoke `harness-gate` explicitly.

Pass through any arguments from $ARGUMENTS (e.g., a specific path to evaluate).

If the Skill tool is not available or the skill is not found, tell the user:
- Check that `skills/harness-gate/SKILL.md` exists in the workspace
- If not, reinstall the harness-eval plugin
