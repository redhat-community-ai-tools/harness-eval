# Agent harness modernization audit (2026-10-04)

This audit reviewed every deterministic rule present in v7.16.1, the discovery and parsing architecture, cross-component graph, presets, LLM review, tests, and documentation. Decisions favor configuration-backed evidence and low false-positive rates over rule count.

The review used current primary documentation for [Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference), [Codex AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md), [Claude Code settings](https://code.claude.com/docs/en/settings), [Claude Code hooks](https://code.claude.com/docs/en/hooks), [Cursor customization](https://prod.cursor.com/docs/customize-cursor), [GitHub Copilot customization](https://docs.github.com/en/copilot/reference/customization-cheat-sheet), [Gemini CLI configuration](https://geminicli.com/docs/reference/configuration/), [Windsurf/Devin configuration](https://docs.windsurf.com/llms.txt), [Cline customization](https://docs.cline.bot/llms.txt), [OpenCode V2 permissions](https://opencode.ai/v2/docs/permissions), [Agent Skills](https://agentskills.io/specification), and the [Model Context Protocol](https://modelcontextprotocol.io/specification/).

## Keep unchanged (64)

These rules still test configuration-backed properties and did not encode an obsolete client format:

`agent/data-exfiltration`, `agent/description-required`, `agent/memory-write-unscoped`, `agent/no-credential-access`, `agent/no-prompt-injection`, `agent/obfuscation`, `agent/referenced-skills-exist`, `agent/reverse-shell`, `agent/unbounded-delegation`, `claude-md/generic-advice`, `claude-md/include-exists`, `claude-md/skill-duplication`, `command/data-exfiltration`, `command/duplicate-detection`, `command/no-credential-access`, `command/no-prompt-injection`, `command/obfuscation`, `command/references-nonexistent-skill`, `command/reverse-shell`, `command/script-exists`, `command/shadows-builtin`, `command/skill-overlap`, `content/broken-references`, `content/circular-references`, `content/description-length`, `content/duplicate-detection`, `content/hardcoded-machine-path`, `content/token-budget`, `content/total-description-budget`, `cross/config-instruction-conflict`, `frontmatter/description-required`, `hooks/command-script-exists`, `hooks/dangerous-command`, `hooks/env-leakage`, `hooks/json-duplicate-keys`, `hooks/network-access`, `hooks/script-boundary`, `hooks/silent-failure-masking`, `mcp/json-duplicate-keys`, `quality/example-gap`, `quality/imprecise-instruction`, `quality/negative-only`, `quality/redundant-guidance`, `quality/unfinished-content`, `security/ast-behavioral`, `security/bash-taint-flow`, `security/coercive-override`, `security/credential-file-present`, `security/cve-lookup`, `security/data-exfiltration`, `security/mcp-tool-poisoning`, `security/memory-write-unscoped`, `security/no-credential-access`, `security/no-prompt-injection`, `security/obfuscation`, `security/prompt-exfiltration`, `security/reverse-shell`, `security/stealth-persistence`, `security/taint-flow`, `security/unbounded-delegation`, `security/yara-signatures`, `structural/skill-md-exists`, `structural/symlink-escape`, `submission/file-completeness`.

`security/cve-lookup` remains available, but is now explicitly networked and opt-in (`harness-security --cve`) so the default deterministic workflows remain offline.

## Modify (30)

| Rules | Change and reason |
|---|---|
| `frontmatter/format-valid`, `frontmatter/description-quality` | Align with the portable Agent Skills name, description, compatibility, metadata, and experimental `allowed-tools` schema. Remove English-style and arbitrary minimum-length heuristics. |
| `agent/constraint-body-match`, `agent/disallowed-tools-parseable`, `agent/excessive-permissions`, `command/allowed-tools-coverage`, `command/description-required`, `command/description-quality`, `content/allowed-tools-auto-approve` | Apply Claude-specific permission and command semantics only to Claude components while preserving direct-API compatibility when the source is unknown. |
| `hooks/api-key-helper`, `hooks/base-url-override`, `hooks/env-credential-override`, `hooks/local-settings-committed`, `hooks/permission-contradiction`, `hooks/permission-prompt-disabled`, `hooks/pre-trust-permissions`, `security/dangerous-permission-grant`, `cross/overpermissive-grants` | Stop interpreting every client's settings as Claude Code's `permissions` object. |
| `hooks/valid-structure`, `hooks/matcher-matches-no-tool` | Support Copilot's versioned command/HTTP/prompt hook handlers and restrict matcher semantics to compatible clients. |
| `mcp/valid-config`, `mcp/endpoint-integrity`, `mcp/no-plaintext-secrets`, `mcp/unpinned-package`, `mcp/auto-approve-risk`, `mcp/cross-assistant-divergence` | Parse JSON, JSONC, and TOML; support Codex `mcp_servers`, OpenCode command arrays, Gemini URL fields, and Codex HTTP headers. An empty auto-approval list no longer means “approve all.” |
| `security/cross-component-flow` | Require parser-backed edges for exfiltration chains, include explicit skill-to-MCP paths, remove the invalid assumption that a skill bypasses its invoking agent's tool policy, and make phantom-server wording format-neutral. |
| `cross/multi-assistant-drift` | Include Copilot instructions and move this similarity heuristic out of the gating tier. |
| `quality/scope-grab-description`, `quality/stale-references` | Clarify portable trigger guidance; limit “stale” findings to agent/API references rather than declaring a repository's supported runtimes obsolete. |

## Deprecate (14)

The registry retains migration messages for old configuration and suppression entries.

| Rule | Reason |
|---|---|
| `agent/model-specified` | Model inheritance is valid; requiring an explicit model is not a defect. |
| `claude-md/exists` | A linter cannot report a missing component that discovery did not claim was required. |
| `content/mcp-skill-alignment` | Configured MCP servers need not be referenced by a skill. |
| `content/missing-boundary-policy` | Repository boundaries are contextual and belong in semantic review. |
| `content/orphan-skills` | Skills are dynamically discovered; no static reference is required. |
| `content/permission-escalation` | Portable skill metadata is not an enforceable capability boundary. |
| `content/total-context-budget` | On-demand skill bodies are not loaded together. |
| `hooks/no-audit-trail` | Absence of repository-local telemetry is not a configuration defect. |
| `hooks/no-commit-guard` | A project hook is not required to guard `git commit`. |
| `mcp/no-wildcard-tools` | Per-server tool allowlists are not a portable MCP/client requirement. |
| `mcp/suspicious-endpoint` | Loopback and private-network endpoints are common and not intrinsically suspicious. |
| `security/mcp-least-privilege` | Script imports cannot establish client permissions, and Agent Skills `allowed-tools` remains experimental/client-specific. |
| `quality/scope-overreach`, `quality/trigger-manipulation` | Broad wording heuristics duplicated `quality/scope-grab-description` and produced speculative findings. |

## New deterministic rules (5)

| Rule | Scope | Defensible signal |
|---|---|---|
| `config/valid-structure` | File | Current client-specific field types and OpenCode permissions in both the V2 ordered list and the V1 `permission` object. |
| `config/dangerous-autonomy` | File | Codex explicitly combines no approval with full host access; Gemini explicitly trusts an MCP server; or OpenCode explicitly allows every high-impact resource. Advisory: the project may deliberately accept this tradeoff. |
| `content/activation-valid` | File | A Copilot path instruction has an empty or non-string `applyTo`. A missing `applyTo` is valid (manual attachment). |
| `cross/config-component-conflict` | Setup | A discovered Gemini skill/hook/MCP server or OpenCode skill is disabled/denied by the same setup. Advisory: disabled components can be intentional. |
| `cross/duplicate-skill-id` | Setup | Multiple discovery roots expose the same skill identity; divergent bodies make client search order behavior ambiguous. Advisory: recursive scans can intentionally include sibling projects. |

## Discovery and architecture changes

Discovery now covers Codex `.agents/skills`, `.codex/skills`, and TOML settings/MCP; Copilot path instructions, skills, hooks, and settings; Gemini skills and general settings; OpenCode JSONC/V2 config and portable skill roots; preferred Windsurf/Devin roots plus legacy Windsurf paths; Cline's current rule/skill roots; and Cursor `AGENTS.md`. A general `CONFIG` component preserves one physical file as separate settings, MCP, and hook views where applicable.

## LLM review audit

The old reviewer was Claude-centric, mixed component types in one batch while applying only the first type's rubric, omitted MCP/general settings, lost context during fallback calls, accepted arbitrary categories/severities/verdicts, and embedded component text in breakable code fences. It also asserted that hooks were “100% reliable” and requested invented token consequences.

The modernization makes the rubric client-neutral, adds MCP/config categories, keeps deterministic and semantic responsibilities separate, batches only homogeneous component types, preserves fallback context and category overrides, treats all reviewed content as untrusted JSON-encoded data, validates JSON output, caps issue count, and avoids unsupported quantitative claims.
