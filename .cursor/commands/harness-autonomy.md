# Harness Autonomy

Run the decidable checks an auto-merge policy can trust: block and policy rules only, no heuristics, no LLM. Exit 0 PASS, 1 FAIL, 2 REVIEW_REQUIRED.

## Instructions

1. Run the check on the current project:

```bash
uvx --from harness-eval harness-eval harness-autonomy . --format json
```

If a trusted policy file exists (commonly `.harness-eval/autonomy-policy.yaml`, protected by CODEOWNERS), add `--policy <file>`. Never edit that file to make a run pass.

If `uvx` is not available, fall back to `pip install harness-eval` and use `harness-eval` directly.

2. Report, in order: the verdict and exit code; blocking findings (defects to fix); policy findings (facts a person or the policy file must accept); waived findings and their recorded reasons; coverage (components, rules run, rules not applicable and why, skipped layers, baseline suppressions); and the evidence block (fingerprint, revision, rules digest, config digest).

3. Do not soften a FAIL or upgrade a REVIEW_REQUIRED. The value of this check is that it is reproducible.
