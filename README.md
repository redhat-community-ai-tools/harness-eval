# harness-eval

[![CI](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml/badge.svg)](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/harness-eval)](https://pypi.org/project/harness-eval/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Rules](https://img.shields.io/badge/rules-92-blue)](https://github.com/redhat-community-ai-tools/harness-eval#rules)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

Deterministic checks for the configuration that AI coding agents run with:
instruction files, skills, commands, hooks, MCP configs, agent definitions and
pipeline harnesses. It auto-detects the tools a repository uses (Claude Code,
Cursor, Copilot, Gemini CLI, Codex, OpenCode, Windsurf, Cline, fullsend),
builds one component graph across them, and runs 92 deterministic rules
against it. No LLM, no network, same answer every run.

Every rule declares what a finding **means**, and that is the only thing the
commands select on:

| Effect | Meaning | Example |
|--------|---------|---------|
| `block` | A defect. The configuration cannot do what it says. | a hook runs a script that does not exist; a frontmatter key is misspelt so the client ignores it; a secret file is committed |
| `policy` | A fact that needs a trust decision. | permission prompts disabled; a wildcard `Bash` grant; a floating `image: ...:latest` |
| `signal` | A heuristic match. A claim for a reader, not a verdict. | an injection phrase in a prompt; a taint path from `$1` to `eval` |
| `advice` | Quality. Nothing gates on it. | a vague description; redundant guidance; token budget |

## Four commands

| Command | Asks | Runs | Exit code |
|---------|------|------|-----------|
| `harness-autonomy` | Can this change merge without a person? | `block` + `policy` rules that have passed the corpus. Never a heuristic. | 0 PASS, 1 FAIL, 2 REVIEW_REQUIRED |
| `harness-gate` | Is the configuration broken? | `block` rules at gating tier (`--include-provisional` adds the rest) | 1 on any error or warning |
| `harness-security` | What should a security reviewer read? | `policy` + `signal` rules, security `block` rules, YARA, optional OSV lookup and LLM review | 0 unless `--fail-on-*` |
| `harness-lint` | How healthy is the setup? | `advice` rules plus system analysis (token budget, triggers, dependencies). `--all` runs every rule. | 0 unless `--fail-on-*` |

Plus `harness-review` (LLM rubric review; Gemini, Anthropic or any
OpenAI-compatible endpoint), `rules` (list and filter the catalog),
`baseline` and `doctor`.

## Quick start

```bash
pip install harness-eval
harness-eval harness-autonomy .     # the merge decision
harness-eval harness-security .     # the security read
harness-eval harness-lint .         # the quality report
harness-eval rules --effect block   # what counts as a defect
```

```
harness-autonomy: my-repo
Verdict: REVIEW_REQUIRED

Policy (needs a decision) (1):
  hooks/permission-prompt-disabled	.claude/settings.json	permissions.defaultMode is 'bypassPermissions' ...

Coverage:
  components: 1 claude_md, 2 command, 1 hooks, 1 mcp_config, 3 skill
  rules: 41 ran of 47 selected
  not applicable (no agent component in the setup): agent/description-required, ...

Evidence:
  fingerprint: 3f9c...   revision: 7b1e2d...   rules digest: a41c...
```

Also available as a [GitHub Action, Tekton Task, Claude Code plugin, Cursor
commands and pre-commit hook](docs/INSTALL.md).

## Using it in an auto-merge policy (ADLC)

An agent-driven development lifecycle merges some changes without a human in
the loop. The policy that decides which ones needs evidence it can trust, and
a configuration check is one of three kinds of deterministic evidence it
should have:

| Evidence | Question | Who produces it |
|----------|----------|-----------------|
| Repository preconditions | Does this repo have branch protection, required checks, CODEOWNERS? | the forge, checked once |
| Facts about the change | Is CI green on this exact SHA? Does the diff touch a protected path? Is a reviewer thread still open? | the CI system, every change |
| **Configuration health** | **Does the agent configuration this change ships actually work, and did the change widen any trust boundary?** | **`harness-autonomy`, every change** |

`harness-autonomy` is built to be that third input, and nothing more:

- **Only facts.** It runs `block` and `policy` rules at gating or provisional
  tier. A pattern match, a taint path or a style judgment never enters it. The
  exact list is generated into
  [`docs/rules-reference.md`](docs/rules-reference.md#rules-harness-autonomy-runs)
  and changes only when a rule changes its own declaration.
- **About the change, not the history.** With `--compare <checkout of the base
  revision>` only findings the change introduced decide the verdict; the rest
  are listed under `pre_existing`. The GitHub Action does this on pull requests
  by default.
- **Three outcomes.** `PASS` (exit 0): no defect, no unaccepted policy fact.
  `FAIL` (exit 1): a defect; the change is wrong. `REVIEW_REQUIRED` (exit 2):
  the change introduces a policy fact that a person has not accepted yet.
- **Accept once, not every time.** A repository records the policy facts it
  accepts in a file kept out of the scanned tree or protected by CODEOWNERS.
  Accepted findings appear as `waived` with the recorded reason; they are never
  hidden, and a `block` rule cannot be accepted.

  ```yaml
  # .harness-eval/autonomy-policy.yaml
  accept:
    - rule: harness/image-unpinned
      file: harness/*.yaml          # optional glob, relative to the scan root
      reason: platform images float by design; tracked in SEC-42
  ```

- **Bound to what was scanned.** The JSON and SARIF output carry `coverage`
  (which rules ran, which did not apply and why, skipped composed layers,
  baseline suppressions) and `evidence` (setup fingerprint, git revision,
  digests of the rule catalog, the severity configuration and the policy file).
  Two runs with the same fingerprint, revision and digests are the same
  evaluation, which is what a policy engine needs to cache or audit a verdict.
- **Quiet where its facts do not apply.** An agent or skill that a pipeline
  harness runs lives in that harness's sandbox, so Claude Code permission facts
  (`tools`, `allowed-tools`) are not reported for it.

A minimal wiring, as a GitHub Actions step:

```yaml
- uses: redhat-community-ai-tools/harness-eval/.github/actions/harness-eval@main
  with:
    autonomy-policy: .harness-eval/autonomy-policy.yaml   # optional
    autonomy-allow-review: "false"   # REVIEW_REQUIRED fails the step; set "true" to let a human gate it instead
```

The step's `autonomy-verdict` output is `PASS`, `FAIL` or `REVIEW_REQUIRED`;
a policy engine (for example a Gemara control evaluated by ComplyTime) reads
it together with the JSON evidence block. What this check does **not** decide:
whether the PR itself is safe to merge. That is the first two rows of the
table above.

## What it checks

| Assistant | What it discovers |
|-----------|------------------|
| Claude Code | `CLAUDE.md`, `skills/`, `commands/`, `.claude/agents/`, `agents/*.md`, `.claude/settings.json`, `.mcp.json` |
| Cursor | `.cursor/rules/*.mdc`, `.cursorrules`, `.cursor/commands/`, `.cursor/skills/`, `.cursor/hooks.json`, `.cursor/mcp.json` |
| Windsurf | `.windsurfrules`, `.windsurf/rules/*.md` (linted as instruction files) |
| Cline | `.clinerules` (file or directory of `*.md`) (linted as instruction files) |
| Copilot | `.github/copilot-instructions.md`, `.github/skills/`, `.github/prompts/`, `.github/agents/`, `.vscode/mcp.json` |
| Gemini CLI | `GEMINI.md`, `.gemini/commands/` (`.md` and `.toml` linted), `.gemini/settings.json` (MCP) |
| OpenCode | `AGENTS.md`, `.opencode/commands/`, `.opencode/agents/`, `opencode.json` (MCP) |
| Codex CLI | `AGENTS.md`, `.codex/instructions.md`, `.codex/setup.sh`, `codex.json` |
| fullsend | `harness/*.yaml` pipeline agent harnesses: agent prompt, model, image, policy, scripts, skills, plugins, host files, output contract, per-forge overrides |
| Third-party modules | `.lola/modules/` (skills, commands, agents installed via package managers) |

Because every component lands in one graph, rules can see across files: a
hook that reads credentials and passes them to a skill that forwards them to a
network-capable MCP server; a command whose `allowed-tools` does not cover
what its instructions use; a `permissions.deny` that blocks a tool `CLAUDE.md`
tells the agent to use; a harness that declares an output contract its agent
prompt never mentions. A per-file linter cannot see any of these.

## Rules

92 deterministic rules across 13 categories. Three axes, all recorded on
the rule itself and all generated into the docs by
`scripts/gen_rules_reference.py` (see [`docs/rule-taxonomy.md`](docs/rule-taxonomy.md)):

- **Effect** (above) is what the commands select on.
- **Tier** is the evidence class: `gating` (corpus-validated at >=97%
  precision, or a decidable integrity fact), `provisional` (no observed false
  positives, fewer than 50 findings), `advisory` (every heuristic). Signal and
  advice rules are always advisory; block and policy rules are gating or
  provisional, so the autonomy set is "decidable and corpus-passed" by
  construction.
- **Scope** is how much of the setup a rule must see: `FILE`, `FILE_FS`,
  `PAIRWISE`, `SETUP`.

<!-- BEGIN GENERATED: effect-counts -->
| Effect | Rules | Run by |
|--------|-------|--------|
| block | 34 | `harness-gate`, `harness-autonomy`, `harness-security` (security category) |
| policy | 13 | `harness-autonomy` (REVIEW_REQUIRED), `harness-security` |
| signal | 21 | `harness-security` |
| advice | 24 | `harness-lint` |
<!-- END GENERATED: effect-counts -->

<!-- BEGIN GENERATED: tier-counts -->
| Tier | Rules |
|------|-------|
| gating | 22 |
| provisional | 25 |
| advisory | 45 |
<!-- END GENERATED: tier-counts -->

<!-- BEGIN GENERATED: scope-counts -->
| Scope | Rules |
|-------|-------|
| FILE | 66 |
| FILE_FS | 12 |
| PAIRWISE | 9 |
| SETUP | 5 |
<!-- END GENERATED: scope-counts -->

Severity presets `recommended` (default) and `strict` change how loud a
finding is, never which rules run. The full catalog with examples, detection
techniques and OWASP / MITRE ATLAS mappings is in
[`docs/rules-reference.md`](docs/rules-reference.md).

## Handling findings

- **Fix it.** Most `block` findings name the file and the line.
- **Accept it once** (policy facts): the autonomy policy file above.
- **Suppress in place**: `<!-- evaluator-ignore: rule/id -->` for a file,
  `<!-- evaluator-ignore-next-line: rule/id -->` for one line. Removed rule
  ids keep working as aliases.
- **Adopt incrementally**: `harness-eval baseline . --output .harness-eval-baseline.json`,
  then `--baseline` on any command. `harness-autonomy` counts suppressed
  findings in its coverage block instead of hiding them.
- **Exclude files**: `--exclude "vendor/**"` (repeatable). `.env`,
  `credentials` paths and `*.pem` / `*.key` / `id_rsa` are excluded by default.
- **Report without failing**: `--enforce advisory` on lint and security.

## How it stays trustworthy

- **Offline by default.** `harness-autonomy`, `harness-gate`, `harness-lint`
  and `harness-security` make no network calls. `harness-security --cve`
  (OSV lookup) and any LLM review are opt-in, and likely secrets are redacted
  before a prompt leaves the machine.
- **Nothing from the scanned tree executes.** Project YAML rules are
  declarative regexes, load only into `harness-lint --rules-from-target`, and
  carry effect `signal`, so they can never enter a gate. Python rule providers
  come only from the installed `harness_eval.rules` entry point.
- **Bounded.** Scans read agent-setup files only, with limits (10 MB per file,
  250 MB total, 100,000 files, depth 50) adjustable per command.
- **One inventory.** Discovery, fingerprinting and watch mode share the same
  file inventory, so nothing is linted by one path and missed by another.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and
[`docs/how-can-you-know-its-safe-to-use-this-tool.md`](docs/how-can-you-know-its-safe-to-use-this-tool.md).

## Custom YAML rules

Drop a `.yaml` file in `.harness-eval/rules/` and pass `--rules-from-target`
to `harness-lint`:

```yaml
id: custom/no-sudo
severity: error
description: Flag sudo usage in skills
suggestion: Remove sudo; skills should not require root access.
target: skill
category: security
patterns:
  - label: sudo command
    regex: '\bsudo\b'
message: "Found '{{label}}' on line {{line}}"
```

Patterns are case-insensitive. Regexes longer than 256 characters or with
nested unbounded quantifiers are skipped. For anything beyond a regex, write a
Python rule (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).

## Contributing and history

[`CONTRIBUTING.md`](CONTRIBUTING.md) covers adding a rule (declare its effect
and tier; the commands pick it up from there), the corpus, and PRs.
[`CHANGELOG.md`](CHANGELOG.md) has the release history; 8.0 is the release that
introduced the effect axis and `harness-autonomy`, with migration notes.
