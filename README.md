# harness-eval

[![CI](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml/badge.svg)](https://github.com/redhat-community-ai-tools/harness-eval/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/harness-eval)](https://pypi.org/project/harness-eval/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Rules](https://img.shields.io/badge/rules-81-blue)](https://github.com/redhat-community-ai-tools/harness-eval#inspection-rules-81)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

Evaluate AI code agent setups for best practices, redundancy, security, and cross-component issues.

Available as a **CLI tool**, a **GitHub Action**, a **Tekton Task** (OpenShift Pipelines), a **Claude Code plugin**, and **Cursor commands**.

Supports Claude Code, Cursor, Copilot, Gemini CLI, and OpenCode projects. Auto-detects which tool(s) a project uses. Also discovers third-party modules installed via package managers.

## What it does

Most tools test whether a skill produces correct output. This tool checks the setup itself: CLAUDE.md, GEMINI.md, AGENTS.md, skills, commands, hooks, MCP configs, agents, `.cursor/rules/*.mdc`, `.cursorrules`, `.github/prompts/`, `.opencode/`.

### Security

Cross-component analysis is the core differentiator. Most linters check files in isolation; harness-eval builds a component graph that traces data flows across skills, agents, hooks, and MCP servers. This catches threats like credential exfiltration chains (one skill reads secrets, another has network access) and confused deputy attacks (an agent disallows a tool but references a skill that uses the equivalent capability).

Beyond cross-component analysis, the security engine includes Python taint tracking, bash taint analysis, YARA signature scanning, CVE lookups via OSV.dev, and optional LLM-based semantic review.

Six commands, same engine:

| Command | What it does | LLM in CLI | LLM in Claude Code / Cursor |
|---------|-------------|-----------|----------------------------|
| `lint` | 81 deterministic rules + system analysis (token budget, trigger overlaps, dependencies). Fast, CI-suitable. Supports `--format sarif` for GitHub code scanning. | No | No |
| `review` | Per-component rubric review with 0-3 scoring per dimension, 21 cross-type checks. KEEP/REVIEW/REMOVE verdicts. | Yes (`[llm]` extra + API key) | Yes (in-session) |
| `security` | All security rules + YARA + CVE lookups + semantic review. SAFE/CAUTION/UNSAFE. | Scan: no. `--review`: yes (`[llm]` extra) | Yes (in-session) |
| `scan` | Vet a skill or setup from a git URL or local path before installing. Runs security + structural rules. SAFE/CAUTION/UNSAFE. | No | No |
| `skill` | Deep-evaluate one skill individually and in context of the full setup. | Lint: no. `--rubric`: yes (`[llm]` extra) | Yes (in-session) |
| `rules` | List all available rules with ID, severity, target type, and description. Filter by `--category` or `--target`. | No | No |

## Supported AI Assistants

Auto-detects which tool(s) a project uses and evaluates all discovered components.

| Assistant | What it discovers |
|-----------|------------------|
| Claude Code | `CLAUDE.md`, `skills/`, `commands/`, `.claude/agents/`, `.claude/settings.json`, `.mcp.json` |
| Cursor | `.cursor/rules/*.mdc`, `.cursorrules`, `.cursor/commands/`, `.cursor/skills/`, `.cursor/hooks.json`, `.cursor/mcp.json` |
| Copilot | `.github/skills/`, `.github/prompts/`, `.github/agents/` |
| Gemini CLI | `GEMINI.md`, `.gemini/commands/` |
| OpenCode | `AGENTS.md`, `.opencode/commands/`, `.opencode/agents/` |
| Third-party modules | `.lola/modules/` (skills, commands, agents installed via package managers) |

Multi-tool projects are fully supported. When a project contains files for multiple assistants, all are discovered, deduplicated, and evaluated together.

## Install

See [`docs/INSTALL.md`](docs/INSTALL.md) for all installation options, CI integration, and configuration (Available as a **CLI tool**, **GitHub Action**, **Tekton Task**, **Claude Code plugin**, and **Cursor commands**)

## Inspection Rules (81)

| Category | Rules | What they check |
|----------|-------|-----------------|
| Structural | 1 | SKILL.md exists |
| Frontmatter | 3 | Description required/quality, format valid |
| Content | 9 | Duplicate detection (TF-IDF), broken references, circular references, token budget, orphan skills, MCP-skill alignment, total context budget, permission escalation, hardcoded machine paths |
| Quality | 8 | Imprecise instructions, redundant guidance, unfinished content, example gap, stale references, negative-only prohibitions, scope overreach, trigger manipulation |
| Security | 15 | Credential access, prompt injection, data exfiltration, obfuscation, reverse shells, AST analysis, Python taint tracking, bash taint tracking, MCP least-privilege, tool poisoning, coercive override, stealth persistence, prompt exfiltration, memory-write-unscoped, unbounded-delegation |
| Security (opt-in) | 2 | YARA signatures, CVE lookups via OSV.dev |
| Cross-component | 3 | Cross-component exfiltration chains, confused deputy attacks, phantom MCP tool references, config-instruction conflicts, multi-assistant drift |
| Commands | 12 | Description, script exists, duplicates, credentials, injection, exfiltration, obfuscation, reverse shells, skill overlap, shadows built-in, references nonexistent skill, allowed-tools coverage |
| CLAUDE.md | 3 | Exists, skill duplication, generic advice detection |
| MCP | 6 | Configuration structure, duplicate servers, suspicious endpoints (localhost/private IPs), wildcard tool exposure, plaintext secrets, unpinned packages |
| Hooks | 6 | Structure validation, script boundary, dangerous commands, env variable leakage, network access, matcher-matches-no-tool |
| Agents | 13 | Description, model specified, skills exist, tool format, constraint matching, credentials, injection, exfiltration, obfuscation, reverse shells, excessive-permissions, memory-write-unscoped, unbounded-delegation |

Four presets: `recommended` (default), `strict`, `security`, `pre-workflow`. For a complete reference with examples, detection techniques, framework mappings, and AI tool coverage per rule, see [`docs/rules-reference.md`](docs/rules-reference.md).

### Frameworks

Rules are mapped to industry security frameworks where applicable:

- **OWASP LLM Top 10** (2025): coverage across LLM01 (prompt injection), LLM02 (sensitive data), LLM06 (excessive agency), and others
- **OWASP Agentic Security**: AG04 (data exfiltration), AG05 (credential access), and related controls
- **MITRE ATLAS**: AML.T0054 (LLM prompt injection) and related techniques

## Security

For a full overview of how this tool protects your code, your credentials, and your supply chain, see [`docs/how-can-you-know-its-safe-to-use-this-tool.md`](docs/how-can-you-know-its-safe-to-use-this-tool.md).

## Privacy and Data Handling

`harness-eval` reads files from your project directory to analyze your AI agent setup. Here is what happens with your data in each mode:

| Command | Sends data externally? | What is sent | Where |
|---------|----------------------|--------------|-------|
| `lint` | No | Nothing. Fully offline. | N/A |
| `review` | Yes (CLI only, requires `[llm]` extra) | Code snippets from your setup files | Gemini or Anthropic API (your choice via `--provider`) |
| `security` | Scan: No. `--review`: Yes (CLI only, requires `[llm]` extra) | Code snippets from flagged files | Gemini or Anthropic API |
| `skill` | Lint: No. `--rubric`: Yes (CLI only, requires `[llm]` extra) | The skill content being evaluated | Gemini or Anthropic API |

When used as a **Claude Code plugin**, review/security/skill commands use the existing Claude session. No additional API calls are made.

When used as **Cursor commands**, the evaluation happens in the Cursor session. No additional API calls are made.

**File access:** The tool only reads files within the project directory you point it at. Path traversal protections prevent reading files outside the project boundary.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for adding rules and submitting PRs.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for release history.

## Roadmap

See [open issues](https://github.com/redhat-community-ai-tools/harness-eval/issues) for planned improvements and feature requests.
