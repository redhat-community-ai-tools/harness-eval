# harness-eval

[![CI](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml/badge.svg)](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/harness-eval)](https://pypi.org/project/harness-eval/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Rules](https://img.shields.io/badge/rules-92-blue)](https://github.com/redhat-community-ai-tools/harness-eval#inspection-rules)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

A linter for AI code agent setups, not for code. It auto-detects which AI tools a project uses (Codex, Claude Code, Cursor, GitHub Copilot, Gemini CLI, Windsurf/Devin, Cline, OpenCode, and fullsend pipeline harnesses), builds a component graph across them, and runs 92 deterministic rules. Each rule declares what a finding means (block, policy, signal or advice), and four commands select on that one axis: a merge-safe autonomy check, a validated gate, a security audit and a quality lint. It catches client-specific schema problems plus cross-component failures such as disabled skills, unreachable MCP servers, ambiguous duplicate skill IDs, and explicit credential-to-network paths.

Most tools test whether a skill produces correct output. This one checks the setup itself: CLAUDE.md, GEMINI.md, AGENTS.md, skills, commands, hooks, MCP configs, agents, `.cursor/rules/*.mdc`, `.cursorrules`, `.github/prompts/`, `.opencode/`, `.codex/`.

## Quick start

```bash
pip install harness-eval
harness-eval harness-autonomy .   # decidable checks only; exit 0 PASS, 1 FAIL, 2 REVIEW_REQUIRED
harness-eval harness-gate .       # validated block rules; exits 1 on errors and warnings
harness-eval harness-security .   # policy + heuristic security rules, YARA, optional LLM review
harness-eval harness-lint .       # quality lint (advice rules + system analysis); --all for every rule
```

Example output:

```
harness-autonomy: my-repo
Verdict: REVIEW_REQUIRED

Policy (needs a decision) (1):
  hooks/permission-prompt-disabled	.claude/settings.json	permissions.defaultMode is 'bypassPermissions' ...

Coverage:
  components: 1 claude_md, 2 command, 1 hooks, 1 mcp_config, 3 skill
  rules: 41 ran of 50 selected
  not applicable (no agent component in the setup): agent/description-required, ...

Evidence:
  fingerprint: 3f9c...
  revision: 7b1e2d...
  rules digest: a41c...
```

See [`docs/INSTALL.md`](docs/INSTALL.md) for all installation options and configuration.

## How to use it

Available as a **CLI tool**, a **GitHub Action**, a **Tekton Task** (OpenShift Pipelines), a **Claude Code plugin**, **Cursor commands**, and a **pre-commit hook**. Each is documented in [`docs/INSTALL.md`](docs/INSTALL.md).

## Suppressing findings

Not every finding is a real problem. Four ways to handle false positives:

**Inline suppression** (per-file or per-line):
```markdown
<!-- evaluator-ignore: rule/id-1, rule/id-2 -->       file-wide
<!-- evaluator-ignore-next-line: rule/id -->            next line only
```

**Baseline** (incremental adoption):
```bash
harness-eval baseline . --output .harness-eval-baseline.json
harness-eval harness-lint . --all --baseline .harness-eval-baseline.json   # suppresses known findings
```
`harness-autonomy --baseline` counts suppressed findings in its coverage block instead of hiding them.

**Exclude files**: `--exclude "vendor/**" --exclude ".git/**"` (repeatable).

**Advisory mode**: `--enforce advisory` reports findings without failing CI.

See [`docs/rules-reference.md`](docs/rules-reference.md) for what each rule's effect means (block, policy, signal, advice).

| Command | Rules it runs | Exit code | LLM needed? |
|---------|---------------|-----------|-------------|
| `harness-autonomy` | **block** and **policy** rules at gating or provisional tier: every finding is a decidable fact about the configuration. No heuristics, no target YAML, no network. Reports coverage (what did and did not run, and why) and an evidence block. | 0 PASS, 1 FAIL (a block finding), 2 REVIEW_REQUIRED (policy findings nobody accepted). `--policy <trusted file>` turns accepted policy findings into visible `waived` entries. | No |
| `harness-gate` | **block** rules at gating tier (add `--include-provisional`). | 1 on any error or warning; info is printed and does not fail. | No |
| `harness-security` | **policy** and **signal** rules plus the security-category block rules, YARA, opt-in OSV lookup (`--cve`), optional LLM adjudication and semantic review (`--review`). SAFE/CAUTION/UNSAFE. Signal findings are claims to read, not verdicts. | 0 unless `--fail-on-error`/`--fail-on-warning`/`--enforce`. | Default: no. `--cve` and `--review`: yes. |
| `harness-lint` | **advice** rules plus system analysis (token budget, trigger overlaps, dependencies). `--all` runs every rule. `--preset strict` raises severities. Supports `--format sarif`, `--watch`, `--fix`; target YAML loads only with `--rules-from-target`. | 0 unless `--fail-on-error`/`--fail-on-warning`/`--enforce`. | No |
| `harness-review` | LLM rubric review per component with scoring and KEEP/REVIEW/REMOVE verdicts. `--provider gemini\|anthropic\|openai`; `openai` talks to any OpenAI-compatible endpoint (`--base-url` or `OPENAI_BASE_URL`). | 0 | CLI: `[llm]` extra. Plugin/Cursor: in-session. |
| `rules` | List all rules. Filter by `--effect`, `--tier`, `--category`, `--target`, `--scope`. | 0 | No |
| `baseline`, `doctor` | Snapshot current findings; check installed extras and keys. | 0 | No |

### The autonomy check

`harness-autonomy` is the command a merge policy can trust. It runs only rules
whose finding is a fact (effect `block` or `policy`) that have passed the
corpus (tier `gating` or `provisional`). A pattern match, a taint path or a
style judgment never enters it, so a PASS means "no decidable defect and no
unaccepted policy fact", not "no heuristic fired".

Policy findings are facts that need a trust decision: permission prompts
disabled, a wildcard Bash grant, a floating container image. A repository
records the ones it accepts in a policy file kept out of the scanned tree or
protected by CODEOWNERS:

```yaml
# .harness-eval/autonomy-policy.yaml
accept:
  - rule: harness/image-unpinned
    file: harness/*.yaml          # optional glob, relative to the scan root
    reason: platform images float by design; tracked in SEC-42
```

```bash
harness-eval harness-autonomy . --policy .harness-eval/autonomy-policy.yaml --format json
```

Accepted findings appear under `waived` with the recorded reason; they are
never hidden. Only `policy` rules can be accepted; an entry naming a `block`
rule is reported and ignored. The JSON output carries the verdict, the three
finding lists, `coverage` (components, rules run, rules not applicable and
why, skipped harness layers, baseline suppressions) and `evidence`
(fingerprint, revision, rules and config digests, policy file digest), so a
downstream policy engine can bind the verdict to exactly what was scanned.

## Cross-component analysis

This is the core differentiator. Most linters check files in isolation. harness-eval builds a component graph that traces data flows across skills, agents, hooks, and MCP servers, then runs cross-component rules against it. This catches classes of issues that per-file analysis cannot:

- A hook reads credentials from env, passes them to a skill, which forwards them to an MCP server with broad network access
- A command's `allowed_tools` list doesn't cover the tools its instructions actually use
- Settings.json `permissions.deny` blocks a tool that CLAUDE.md instructs the agent to use
- Two assistants' instruction files (CLAUDE.md and GEMINI.md) have drifted apart
- A skill is defined but never referenced from any instruction file (orphan)

Multi-tool projects are fully supported. When a project uses both Claude Code and Cursor, all components are evaluated together.

## Supported AI tools

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
| fullsend | `harness/*.yaml` pipeline agent harnesses (agent prompt, model, pre/post scripts, skills, plugins, host files, output contract) |
| Third-party modules | `.lola/modules/` (skills, commands, agents installed via package managers) |

## Inspection rules

92 deterministic rules across 13 categories: structural, frontmatter, content, quality, security, cross-component, commands, instruction files, configuration, MCP, hooks, agents, and harness definitions. Two severity presets, `recommended` (default) and `strict`. Which rules a command runs is not a preset: it is derived from each rule's declared **effect**.

**Effect.** `block` is a decidable defect; `policy` is a decidable fact that needs a trust decision; `signal` is a heuristic match; `advice` is quality. The commands select on this axis, so a rule changes what gates a merge only by changing its own declaration. **Tier** is the evidence class: `gating` (corpus-validated at >=97% precision, or a decidable integrity fact), `provisional` (no observed false positives, fewer than 50 findings), `advisory` (every heuristic). Signal and advice rules are always advisory; block and policy rules are gating or provisional. Rules are also tagged by analysis scope (`FILE`, `FILE_FS`, `PAIRWISE`, `SETUP`); the last two are findings a per-file linter structurally cannot see. See [`docs/rule-taxonomy.md`](docs/rule-taxonomy.md).

Rules by effect:

<!-- BEGIN GENERATED: effect-counts -->
| Effect | Rules | Run by |
|--------|-------|--------|
| block | 35 | `harness-gate`, `harness-autonomy`, `harness-security` (security category) |
| policy | 12 | `harness-autonomy` (REVIEW_REQUIRED), `harness-security` |
| signal | 21 | `harness-security` |
| advice | 24 | `harness-lint` |
<!-- END GENERATED: effect-counts -->

Rules by tier:

<!-- BEGIN GENERATED: tier-counts -->
| Tier | Rules |
|------|-------|
| gating | 22 |
| provisional | 25 |
| advisory | 45 |
<!-- END GENERATED: tier-counts -->

Rules by scope:

<!-- BEGIN GENERATED: scope-counts -->
| Scope | Rules |
|-------|-------|
| FILE | 66 |
| FILE_FS | 12 |
| PAIRWISE | 9 |
| SETUP | 5 |
<!-- END GENERATED: scope-counts -->

For the complete rule list with examples, detection techniques, and framework mappings (OWASP, MITRE ATLAS), and the exact table of rules `harness-autonomy` runs, see [`docs/rules-reference.md`](docs/rules-reference.md).

## Scan architecture and safety

Each scan builds a canonical inventory from the registered assistant
discoverers. The same inventory drives component discovery, fingerprints, and
watch mode, so a file cannot be linted by one path while being missed by
another. Components are parsed once into a typed setup view, then shared scan
artifacts—such as the component graph and component index—are passed to rules.

Rules run from a scan-local catalog. Project-provided YAML rules are opt-in and
remain declarative; they cannot import or execute Python from the scanned tree.
Trusted Python rule providers may be installed by the application through the
`harness_eval.rules` entry-point group. See [`CONTRIBUTING.md`](CONTRIBUTING.md)
for the extension contract.

Scans enforce resource limits on the agent-setup files they read (never on
unrelated repository content): 10 MB per file, 250 MB total, 100,000 files,
and depth 50 by default. Every command that discovers a setup accepts
`--max-file-bytes`, `--max-total-bytes`, `--max-files`, and `--max-depth`;
an exceeded limit is reported as a one-line error.

### Scan evidence

A result that will be consumed by something other than a person (a merge
policy, a compliance record) has to say what it was computed from.
`harness-lint --format json` carries that under `metadata.evidence`, and
`harness-lint`/`harness-gate`/`harness-autonomy --format sarif` under `runs[0].properties` plus
`runs[0].versionControlProvenance`:

- `setup_fingerprint`: hash of the scanned inventory (the same one watch mode uses)
- `vcs.revision`: HEAD of the enclosing git checkout, read from `.git` without a subprocess
- `rules.digest` / `rules.count` / `rules.target_rules_loaded`: the rule catalog in force
- `config.preset` / `config.digest`: the severities in force
- `baseline.digest` / `baseline.suppressed`: what a `--baseline` hid, counted rather than dropped silently
- `inventory.files` / `inventory.excludes` / `inventory.limits`: what was and was not read

Two runs with the same fingerprint, revision, rules digest and config digest
are the same evaluation.

## Privacy

`harness-autonomy`, `harness-gate`, `harness-lint` and default `harness-security` are fully offline. OSV lookup (`harness-security --cve`) and **LLM review are opt-in:**
`harness-review` and `harness-security --review` send snippets to a remote
provider (Gemini, Anthropic, or any OpenAI-compatible endpoint via `--provider openai --base-url`, or in-session as a plugin/command).

Before any remote LLM call, likely secrets (tokens, PEM keys, `API_KEY=` assignments,
known prefix patterns) are replaced with `[REDACTED]` (HE-2). Scans also skip `.env`,
`credentials` paths, and `*.pem` / `*.key` / `id_rsa` globs by default (HE-3); add
more with `--exclude`.

See [`docs/how-can-you-know-its-safe-to-use-this-tool.md`](docs/how-can-you-know-its-safe-to-use-this-tool.md) for details.

## Custom YAML rules

Add your own rules without writing Python. Drop a `.yaml` file in `.harness-eval/rules/` in your project:

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

YAML rules support regex pattern matching on component content. Patterns are case-insensitive by default. Custom rules run at their declared severity under both presets and carry effect `signal`, so they appear in `harness-lint --all` and never in `harness-autonomy` or `harness-gate`. Remove the rule file to disable it.

`harness-lint` loads YAML from the scanned tree only with `--rules-from-target`. `harness-autonomy`, `harness-gate` and `harness-security` never load them: regexes from an audited tree run in-process. Target YAML rules are held in a scan-local catalog and cannot leak into another scan. Regexes longer than 256 characters or with nested unbounded quantifiers are skipped.

Scans enforce resource limits on the agent-setup files they read (`10 MB` per file,
`250 MB` total, `100,000` files, depth `50`). CI jobs with unusually large setups can
adjust these with `--max-file-bytes`, `--max-total-bytes`, `--max-files`, and `--max-depth`.

For complex logic (AST analysis, cross-component checks), use Python rules instead.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for adding rules and submitting PRs.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for release history.

## Roadmap

See [open issues](https://github.com/redhat-community-ai-tools/harness-eval/issues) for planned improvements and feature requests.
