# harness-eval

[![CI](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml/badge.svg)](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/harness-eval)](https://pypi.org/project/harness-eval/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Rules](https://img.shields.io/badge/rules-107-blue)](https://github.com/redhat-community-ai-tools/harness-eval#inspection-rules)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

A linter for AI code agent setups, not for code. It auto-detects which AI tools a project uses (Claude Code, Cursor, Windsurf, Cline, Copilot, Gemini CLI, OpenCode, Codex CLI), builds a component graph across all of them, and runs 107 deterministic rules to catch issues that per-file linters miss: credential exfiltration chains, confused deputy attacks, skill/hook conflicts, and token budget blowouts.

Most tools test whether a skill produces correct output. This one checks the setup itself: CLAUDE.md, GEMINI.md, AGENTS.md, skills, commands, hooks, MCP configs, agents, `.cursor/rules/*.mdc`, `.cursorrules`, `.github/prompts/`, `.opencode/`, `.codex/`.

## Quick start

```bash
pip install harness-eval
harness-eval harness-lint .                    # 107 deterministic rules, fully offline
harness-eval harness-gate .                     # validated (gating-tier) rules only; exits 1 on any finding, no LLM
harness-eval harness-security .                # security scan
harness-eval skill-verify ./downloaded-skill   # SAFE / CAUTION / UNSAFE before you install
```

Example output:

```
FAIL     no-credential-access: References sensitive path '~/.aws/credentials' at line 10
             Fix: Use a secret manager or environment variable injection instead of hardcoded paths.
WARNING  orphan-skills: Skill 'creds-skill' is not referenced by any command, CLAUDE.md, or agent
             Fix: Reference the skill from a command, CLAUDE.md, or agent, or remove it.

Verdict: UNSAFE
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
harness-eval harness-lint . --format json --output .harness-eval-baseline.json
harness-eval harness-lint . --baseline .harness-eval-baseline.json   # suppresses known findings
```

**Exclude files**: `--exclude "vendor/**" --exclude ".git/**"` (repeatable).

**Advisory mode**: `--enforce advisory` reports findings without failing CI.

See [`docs/rules-reference.md`](docs/rules-reference.md) for rule confidence tiers (exact, heuristic, advisory).

| Command | What it does | LLM needed? |
|---------|-------------|-------------|
| `harness-lint` | 107 deterministic rules + system analysis (token budget, trigger overlaps, dependencies). Fast, CI-suitable. Supports `--format sarif`. | No |
| `harness-security` | All security rules + YARA + CVE lookups + optional semantic review. SAFE/CAUTION/UNSAFE. | Scan: no. `--review`: `[llm]` extra or in-session. |
| `harness-review` | Per-component rubric review with scoring, 21 cross-type checks, KEEP/REVIEW/REMOVE verdicts. | CLI: `[llm]` extra. Plugin/Cursor: in-session. |
| `skill-verify` | Vet a skill or setup before installing. Combines lint + security in one pass. SAFE/CAUTION/UNSAFE verdict. | No |
| `skill-review` | Deep-evaluate one skill individually and in context of the full setup. | Lint: no. `--rubric`: `[llm]` extra or in-session. |
| `skill-submission-scan`* | Scan a skill submission for CI pipelines. Splits findings into security and quality JSON files. | No |
| `rules` | List all rules. Filter by `--category` or `--target`. | No |

\* `skill-verify` and `skill-submission-scan` both vet skills, but for different audiences. `skill-verify` is for developers checking a downloaded skill ("is this safe to install?"). `skill-submission-scan` is for CI pipelines that gate skill submissions, producing structured JSON with `--output-security` and `--output-quality` for downstream automation.

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
| Claude Code | `CLAUDE.md`, `skills/`, `commands/`, `.claude/agents/`, `.claude/settings.json`, `.mcp.json` |
| Cursor | `.cursor/rules/*.mdc`, `.cursorrules`, `.cursor/commands/`, `.cursor/skills/`, `.cursor/hooks.json`, `.cursor/mcp.json` |
| Windsurf | `.windsurfrules`, `.windsurf/rules/*.md` (discovery only) |
| Cline | `.clinerules` (file or directory of `*.md`) (discovery only) |
| Copilot | `.github/copilot-instructions.md`, `.github/skills/`, `.github/prompts/`, `.github/agents/` |
| Gemini CLI | `GEMINI.md`, `.gemini/commands/` (`.md` linted; `.toml` discovered but not yet linted), `.gemini/settings.json` (MCP) |
| OpenCode | `AGENTS.md`, `.opencode/commands/`, `.opencode/agents/`, `opencode.json` (MCP) |
| Codex CLI | `AGENTS.md`, `.codex/instructions.md`, `.codex/setup.sh`, `codex.json` |
| Third-party modules | `.lola/modules/` (skills, commands, agents installed via package managers) |

## Inspection rules

107 deterministic rules across 12 categories: structural, frontmatter, content, quality, security, cross-component, commands, CLAUDE.md, MCP, hooks, agents, and submission. Six presets: `recommended` (default), `strict`, `security`, `pre-workflow`, `skill-submission`, and `gate`.

**Rule tiers.** Each rule carries an evidence tier. **Gating** rules are structural checks validated at >=97% precision on the corpus and are safe to block a build on; `harness-gate` runs exactly these. **Provisional** rules have no observed false positives but too few findings to promote yet. **Advisory** rules (including every heuristic, prose-judgment rule) are reported but never gate. Rules are also tagged by analysis scope (`FILE`, `FILE_FS`, `PAIRWISE`, `SETUP`) — the last two are findings a per-file linter structurally cannot see. See [`docs/rule-taxonomy.md`](docs/rule-taxonomy.md).

Rules by tier:

<!-- BEGIN GENERATED: tier-counts -->
| Tier | Rules |
|------|-------|
| gating | 6 |
| provisional | 4 |
| advisory | 97 |
<!-- END GENERATED: tier-counts -->

Rules by scope:

<!-- BEGIN GENERATED: scope-counts -->
| Scope | Rules |
|-------|-------|
| FILE | 83 |
| FILE_FS | 8 |
| PAIRWISE | 9 |
| SETUP | 7 |
<!-- END GENERATED: scope-counts -->

For the complete rule list with examples, detection techniques, and framework mappings (OWASP, MITRE ATLAS), see [`docs/rules-reference.md`](docs/rules-reference.md).

## Privacy

`harness-lint` and `harness-security` (without `--review`) are fully offline. **LLM review is opt-in:**
only `harness-review`, `harness-security --review`, and `skill-review --rubric` send snippets to a remote
provider (Gemini or Anthropic via CLI, or in-session as a plugin/command).

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

YAML rules support regex pattern matching on component content. Patterns are case-insensitive by default. Custom rules run at their declared severity under every preset. Remove the rule file to disable it. For complex logic (AST analysis, cross-component checks), use Python rules instead.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for adding rules and submitting PRs.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for release history.

## Roadmap

See [open issues](https://github.com/redhat-community-ai-tools/harness-eval/issues) for planned improvements and feature requests.
