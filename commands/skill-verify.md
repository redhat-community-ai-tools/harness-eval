---
description: "Vet a skill or setup before installing. Combines lint + security checks in one pass."
---

# Skill Verify

Run `harness-eval skill-verify` on the path provided in $ARGUMENTS.

```bash
harness-eval skill-verify $ARGUMENTS
```

If `harness-eval` is not installed, tell the user to run `pip install harness-eval` first.

Present the verdict (SAFE / CAUTION / UNSAFE) and any findings with fix suggestions.
