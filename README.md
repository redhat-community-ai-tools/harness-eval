# harness-eval

[![CI](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml/badge.svg)](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/harness-eval)](https://pypi.org/project/harness-eval/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Rules](https://img.shields.io/badge/rules-84-blue)](https://github.com/redhat-community-ai-tools/harness-eval#inspection-rules)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

Evaluate AI code agent setups for best practices, redundancy, security, and cross-component issues.

Most tools test whether a skill produces correct output. This tool checks the setup itself: CLAUDE.md, GEMINI.md, AGENTS.md, skills, commands, hooks, MCP configs, agents, `.cursor/rules/*.mdc`, `.cursorrules`, `.github/prompts/`, `.opencode/`.

## Quick start

```bash
pip install harness-eval
harness-eval lint .          # 84 deterministic rules, fully offline
harness-eval security .      # security scan (18 rules)
```

See [`docs/INSTALL.md`](docs/INSTALL.md) for all installation options and configuration.

## How to use it

Available as a **CLI tool**, a **GitHub Action**, a **Tekton Task** (OpenShift Pipelines), a **Claude Code plugin**, and **Cursor commands**. Each is documented in [`docs/INSTALL.md`](docs/INSTALL.md).

| Command | What it does | LLM needed? |
|---------|-------------|-------------|
| `lint` | 84 deterministic rules + system analysis (token budget, trigger overlaps, dependencies). Fast, CI-suitable. Supports `--format sarif`. | No |
| `review` | Per-component rubric review with scoring, 21 cross-type checks, KEEP/REVIEW/REMOVE verdicts. | CLI: `[llm]` extra. Plugin/Cursor: in-session. |
| `security` | All security rules + YARA + CVE lookups + optional semantic review. SAFE/CAUTION/UNSAFE. | Scan: no. `--review`: `[llm]` extra or in-session. |
| `skill` | Deep-evaluate one skill individually and in context of the full setup. | Lint: no. `--rubric`: `[llm]` extra or in-session. |
| `rules` | List all rules. Filter by `--category` or `--target`. | No |

## Supported AI tools

Auto-detects which tool(s) a project uses and evaluates all discovered components together. Multi-tool projects are fully supported.

| Assistant | What it discovers |
|-----------|------------------|
| Claude Code | `CLAUDE.md`, `skills/`, `commands/`, `.claude/agents/`, `.claude/settings.json`, `.mcp.json` |
| Cursor | `.cursor/rules/*.mdc`, `.cursorrules`, `.cursor/commands/`, `.cursor/skills/`, `.cursor/hooks.json`, `.cursor/mcp.json` |
| Copilot | `.github/skills/`, `.github/prompts/`, `.github/agents/` |
| Gemini CLI | `GEMINI.md`, `.gemini/commands/` |
| OpenCode | `AGENTS.md`, `.opencode/commands/`, `.opencode/agents/` |
| Third-party modules | `.lola/modules/` (skills, commands, agents installed via package managers) |

## Inspection rules

84 deterministic rules across 11 categories: structural, frontmatter, content, quality, security, cross-component, commands, CLAUDE.md, MCP, hooks, and agents. Four presets: `recommended` (default), `strict`, `security`, `pre-workflow`.

Cross-component analysis is the core differentiator. Most linters check files in isolation; harness-eval builds a component graph that traces data flows across skills, agents, hooks, and MCP servers. This catches threats like credential exfiltration chains and confused deputy attacks.

For the complete rule list with examples, detection techniques, and framework mappings (OWASP, MITRE ATLAS), see [`docs/rules-reference.md`](docs/rules-reference.md).

## Privacy

`lint` and `security` (without `--review`) are fully offline. **LLM review is opt-in:**
only `review`, `security --review`, and `skill --rubric` send snippets to a remote
provider (Gemini or Anthropic via CLI, or in-session as a plugin/command).

Before any remote LLM call, likely secrets (tokens, PEM keys, `API_KEY=` assignments,
known prefix patterns) are replaced with `[REDACTED]` (HE-2). Scans also skip `.env`,
`credentials` paths, and `*.pem` / `*.key` / `id_rsa` globs by default (HE-3); add
more with `--exclude`.

See [`docs/how-can-you-know-its-safe-to-use-this-tool.md`](docs/how-can-you-know-its-safe-to-use-this-tool.md) for details.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for adding rules and submitting PRs.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for release history.

## Roadmap

See [open issues](https://github.com/redhat-community-ai-tools/harness-eval/issues) for planned improvements and feature requests.
