---
name: autonomy
description: Run the decidable checks an auto-merge policy can trust on the agent setup (harness-eval harness-autonomy). Block and policy rules only, no heuristics, no LLM. Exit 0 PASS, 1 FAIL, 2 REVIEW_REQUIRED. Use when the user asks whether a configuration change is safe to merge without a human, or wants the evidence block for a merge decision.
allowed-tools: Bash Read
---
<!-- evaluator-ignore: content/allowed-tools-auto-approve, content/broken-references -->

# Autonomy Check

Run only the rules whose finding is a fact about the configuration: block rules (a decidable defect) and policy rules (a decidable fact that needs a trust decision). Heuristic and quality rules never take part, so nothing here is a pattern match.

## Hard Rules

1. **Run the command; do not reason about the setup yourself.** The point of this check is that it is deterministic and reproducible.
2. **Report the verdict as computed.** PASS, FAIL or REVIEW_REQUIRED, with the findings that produced it. Do not soften a FAIL or upgrade a REVIEW_REQUIRED.
3. **Never edit a policy file to make a run pass.** A policy file is a trust decision owned by the repository's security owners.

## Step 1: Run the Check

Determine the setup path. If the user doesn't specify one, use the current working directory.

```bash
uvx --from harness-eval harness-eval harness-autonomy <setup-path> --format json
```

If a trusted policy file exists (ask the user; a common location is `.harness-eval/autonomy-policy.yaml` protected by CODEOWNERS), add `--policy <file>`.

If `uvx` is not available, fall back to `pip install harness-eval` and use `harness-eval` directly.

## Step 2: Present the Result

Report, in this order:

1. **Verdict** and exit code (0 PASS, 1 FAIL, 2 REVIEW_REQUIRED).
2. **Blocking findings**: rule id, file, message. Each one is a configuration defect to fix.
3. **Policy findings**: rule id, file, message. Each one needs a person (or the policy file) to accept it. Say what accepting it would mean.
4. **Waived findings**: what the policy file accepted and the reason it recorded.
5. **Coverage**: components scanned, rules that ran, rules that did not apply and why, anything skipped (for example a composed harness layer whose references resolve elsewhere), baseline suppressions.
6. **Evidence**: setup fingerprint, git revision, rules digest, config digest. These bind the verdict to exactly what was scanned.

At the very end, include:
```
Evaluated with: harness-eval v{version} (claude-code-plugin)
```

Get `{version}` by running: `uvx --from harness-eval harness-eval --version`
