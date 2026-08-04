# Changelog

All notable changes to this project will be documented in this file.

## [7.0.0] - 2026-08-04

### Added
- `harness-eval doctor` command: shows installed optional capabilities, env var status, and version info
- `mcp/no-plaintext-secrets` rule (ERROR): flags literal secrets in MCP config env/headers using prefix matching and Shannon entropy
- `mcp/unpinned-package` rule (WARNING): flags npx/uvx/pipx/docker MCP servers running floating third-party code
- `hooks/matcher-matches-no-tool` rule (WARNING): flags hook matchers that match no known tool name, with case-sensitivity suggestions
- `content/hardcoded-machine-path` rule (WARNING): flags machine-specific absolute paths in code blocks that break portability
- `cross/config-instruction-conflict` rule (WARNING): flags when settings.json permissions.deny blocks tools that instructions direct to use
- `cross/multi-assistant-drift` rule (WARNING): detects diverged copies of CLAUDE.md/AGENTS.md/GEMINI.md using TF-IDF similarity
- `command/allowed-tools-coverage` rule (WARNING): checks that command allowed-tools covers tools actually used (under-grant and over-grant)
- `cross/overpermissive-grants` rule (WARNING): flags permissions.allow entries that grant broad or unrestricted tool access (Bash(*), bare tool names, short wildcard prefixes)
- `hooks/silent-failure-masking` rule (WARNING): flags hooks that silently suppress errors (2>/dev/null, || true, set +e), escalates to ERROR when combined with security-relevant operations
- `mcp/auto-approve-risk` rule (WARNING): flags MCP servers with autoApprove lists containing write/execute tools
- CI test matrix: `core` and `full` legs ensure optional-dependency code paths (bashlex, yara) are tested

### Changed
- Removed decorative mypy CI step (had continue-on-error: true); tracking issue #54 to re-add enforced

### Fixed
- Bash taint tracking: `read VAR; export SECRET=$VAR; eval $SECRET` flow now detected. The AST walker was missing a handler for `read` as a taint source, and the line-by-line supplement was missing `export` taint propagation.
- Doctor test `test_shows_set_unset_status` had a vacuous assertion (`"set" in "unset"` is always true); split into two non-vacuous tests
- `agent/no-credential-access`: added missing `_DANGEROUS_COMMANDS` check (sudo, chmod 777, chown root) that the command version had
- `agent/disallowed-tools-parseable`: regex now accepts hyphens and digits in tool names (e.g., MCP tool names)
- `cross/overpermissive-grants`: regex now correctly matches `Bash(g:*)` colon-wildcard form
- `security/ast-behavioral`: fixed substring matching false positives (`"get"` no longer matches `"target"`)
- `security/cve-lookup`: OSV error reporting no longer dead code; single-line pyproject.toml deps now parsed
- `security/bash-taint-flow`: regex fallback no longer double-reports lines matching both self-contained and sink patterns
- `security/memory-write-unscoped`, `security/unbounded-delegation`: greedy `.*` replaced with `[^.!?\n]*` to stay within sentence boundaries
- `mcp/unpinned-package`: Docker flag values (e.g., `-p 8080:8080`) no longer treated as image name
- `hooks/valid-structure`: script existence check now resolves against project root instead of CWD
- `content/token-budget`: no longer crashes with ZeroDivisionError when concurrent option is 0
- `content/permission-escalation`: fixed inverted logic; now correctly detects when referenced skill has capabilities the referencing skill lacks
- `content/broken-references`: replaced O(n^2) code fence detection with O(n) pre-computed set
- `security/taint-tracking`: removed unreachable `credential` branch in elif chain
- Removed unused `_VARIABLE_PATTERNS` regex from `content/hardcoded-machine-path`

## [6.3.0] - 2026-07-30

### Breaking
- `google-genai` and `anthropic` moved from hard dependencies to optional `[llm]` extras. Users of `review`, `security --review`, or `skill --rubric` via CLI must install with `pip install "harness-eval[llm]"` (or `uv sync --extra llm`). The `lint`, `security` (scan-only), and `rules` commands work without LLM packages. Plugin and Cursor modes are unaffected.

### Added
- OpenShift Pipelines integration: UBI9-based `Containerfile` and Tekton Task for running harness-eval as a CI gate in OpenShift Pipelines
- `docs/openshift.md`: full documentation for Tekton Task parameters, air-gapped support, and troubleshooting
- Drift-guard test for rule counts and command surface parity across `commands/` and `.cursor/commands/`

### Changed
- GitHub Action reduced from 6 `harness-eval` invocations per scanned directory to 4

### Fixed
- Single-file commands (e.g., `.cursor/commands/foo.md`) now display their actual name instead of "commands". This also fixes incorrect results in duplicate detection, circular reference, and skill overlap rules for single-file commands.
- Stale rule counts across commands, skills, docs, and GitHub Action updated to match registry (74 total, 18 security)
- Version consistency: `__init__.py` now stays in sync with `pyproject.toml`. The release script (`scripts/release.py`) now updates `__init__.py` and Tekton task version labels automatically.
- Missing LLM extras now produce a clean one-line error instead of a traceback, with install instructions for both pip and uv

### Removed
- `python-dotenv` dependency (was never imported)

### Internal
- Refactored `cli/security.py`: extracted `_clean_results`, `_assess_risk`, `_format_json_security`, `_format_terminal_security` from 381-line monolith function; replaced 12-parameter signatures with frozen `_SecurityReport` dataclass

## [6.2.1] - 2026-07-27

### Added
- `--exclude` option for `lint` and `security` CLI commands: repeatable glob patterns to exclude files or directories from scanning. Matches against relative path, absolute path, and filename (like gitignore). Example: `--exclude ".github/scripts/*" --exclude "*.yml"`
- `exclude` input for GitHub Action: multi-line glob patterns, one per line

## [6.2.0] - 2026-07-27

### Added
- Security rules now scan all markdown sub-files inside skill directories, not just SKILL.md. Dangerous content in phase files, rubric files, mode files, and other `.md` sub-files is now detected with correct file paths and line numbers. Capped at 50 sub-files and 100KB per file to prevent runaway scanning.

## [6.1.1] - 2026-07-24

### Fixed
- `content/broken-references`: reduced false positives by resolving paths against project root (not just skill directory), checking skill `scripts/` subdirectory, skipping code-fenced blocks, skipping bare filenames without path separators, skipping placeholder patterns (NNNN-), skipping unknown file extensions, and safely resolving relative `..` links within project boundary

## [6.1.0] - 2026-07-22

### Added
- `agent/excessive-permissions`: flags agents with no allowedTools or disallowedTools (OWASP ASI02)
- `security/memory-write-unscoped` + `agent/memory-write-unscoped`: flags unscoped memory/persistence writes (OWASP ASI06)
- `security/unbounded-delegation` + `agent/unbounded-delegation`: flags unbounded subagent spawning (OWASP ASI08)
- Rule count: 69 to 74 (5 new agentic security rules)
- `docs/rules-reference.md`: complete reference for all 74 lint rules and LLM review system
- Moved `INSTALL.md`, `THREAT_MODEL.md`, and `how-can-you-know-its-safe-to-use-this-tool.md` to `docs/`

## [6.0.0] - 2026-07-22

### Added
- Cross-component security analysis (`security/cross-component-flow`): graph-aware rule detecting inter-component exfiltration, confused-deputy privilege bypass, and phantom MCP server calls
- Unified `ComponentGraph` (`analysis/component_graph.py`): shared graph of all components, edges, and capabilities used by cross-component rules
- Capability taxonomy data file (`data/capabilities.yaml`): all source/sink/exec definitions extracted from hardcoded frozensets into a versioned, structured YAML
- Reachability analysis: security findings annotated with reachability status (reachable/unreachable) based on trigger and reference graph
- Framework mapping: OWASP LLM Top 10, OWASP Agentic Security, and MITRE ATLAS metadata on all security rules. Emitted in SARIF `rule.properties`
- `--framework` filter for `rules` and `security` commands (e.g., `--framework owasp_llm`)
- `harness-eval baseline` command: snapshot current findings for incremental adoption. `--baseline` option on `lint` and `security` suppresses baselined findings
- Suggestion plans: structured remediation guidance on security findings (advisory only, no auto-modification)
- Letter grade (A-F) in report card output
- Enhanced bash taint analysis: `base64 | bash`, `export` propagation, optional `bashlex` AST parsing with regex fallback
- `THREAT_MODEL.md`: attacker model, trust boundaries, and defense scope

### Fixed
- MCP tool call detection now skips code blocks, reducing false positives in cross-component and phantom MCP checks

### Changed
- Source/sink definitions loaded from `capabilities.yaml` instead of inline frozensets
- Rule count: 68 to 69 (1 new cross-component security rule)
- SARIF output includes framework metadata and reachability properties
- README restructured to lead with cross-component analysis

## [5.2.0] - 2026-07-22

### Added
- 4 cross-component lint rules: `content/orphan-skills` (unreferenced skills), `content/mcp-skill-alignment` (MCP config vs skill usage), `content/total-context-budget` (aggregate token usage), `content/permission-escalation` (transitive privilege through skill references)
- `--enforce` flag for `lint` and `security` commands: `strict` (exit 1 on any finding), `advisory` (exit 0 always), `off` (skip)
- `--report-card PATH` flag for `lint`: writes unified JSON report card with verdict (CLEAN/NEEDS_WORK/BLOCKED), per-component results, category breakdown, and certification tier
- Setup certification tiers in report card: Basic (0 lint errors), Verified (Basic + no quality warnings), Hardened (Verified + no security findings)
- Shared `ContextTracker` utility for consistent code-fence/blockquote/example detection across rules
- Contradictory guidance detection (check #22) in LLM review cross-type checks rubric
- `--recursive` flag for lint, security, and review: search the entire directory tree for agent configs in nested directories (skills, agents, commands, hooks, MCP configs)
- Recursive mode in GitHub Action via `recursive: "true"` input

### Changed
- Quality rules (`imprecise-instruction`, `unfinished-content`, `redundant-guidance`, `stale-references`) and `generic-advice` now use shared `ContextTracker` instead of ad-hoc code fence tracking
- Cross-type checks rubric expanded from 21 to 22 checks
- Rule count: 64 to 68 (4 new cross-component content rules)

### Fixed
- `--recursive` now skips symlinks that resolve outside the project boundary, preventing traversal into unrelated directories

## [5.1.0] - 2026-07-20

### Added
- New CLI command `harness-eval rules`: list all 64 rules with ID, severity, target type, and description. Supports `--category`, `--target`, and `--format json` filters.
- GitHub Action PR comment now shows scanned components table and rules by category table
- GitHub Action renamed from "Harness Eval / eval" to "Harness Checks / lint-and-security" for clarity

### Changed
- GitHub Action PR comment labels: "Security gate" -> "Security checks (15 rules)", "Lint gate" -> "Lint checks (64 rules)", "SARIF" -> "Code scanning"
- Warnings in lint checks shown as non-blocking in PR comment

## [5.0.0] - 2026-07-19

### Changed
- **BREAKING**: Python package renamed from `setup_eval` to `harness_eval`. Update imports: `from harness_eval...` instead of `from setup_eval...`
- **BREAKING**: PyPI package renamed from `setup-eval` to `harness-eval`. Install with `pip install harness-eval`.
- **BREAKING**: CLI binary renamed: `harness-eval lint .` instead of `setup-eval lint .`

### Added
- New rule `security/coercive-override`: detect patterns forcing the agent to comply unconditionally (forced compliance, refusal suppression, safety override directives)
- New rule `security/stealth-persistence`: detect instructions writing to config directories or persistent state without user awareness
- New rule `security/prompt-exfiltration`: detect instructions that leak system prompts or configuration to outputs
- New rule `quality/scope-overreach`: detect skills claiming authority over overly broad scope
- New rule `quality/trigger-manipulation`: detect triggers that hijack conversations by forcing invocation
- Summary block at top of lint terminal output showing error/warning count, fixable count, and top 3 issues
- Improved --fix output: shows fixable count before fix, shows total fixed after fix
- Rule count: 59 to 64
- 17 new tests for the 5 new rules (465 total)

## [4.2.0] - 2026-07-09

### Added
- GitHub Action at `.github/actions/harness-eval/`: one-step CI integration with two-tier gating (security + lint) and SARIF upload for inline PR annotations
- New rule `quality/negative-only`: flags prohibitions without constructive alternatives (e.g., "don't use var" without saying what to use instead)
- Scoring anchors (severity examples) added to all review rubric dimensions across 5 rubric files
- 3 new LLM review dimensions: contradiction detection, position effectiveness, specificity gradient

### Fixed
- `security/no-prompt-injection`: removed false-positive-prone patterns (bare markdown images, "you are now", "role play", "translate", bare base64). Tightened to require override/evasion context.
- `security/no-credential-access`: added code-block awareness; `sudo apt install` no longer fires
- `mcp/suspicious-endpoint`: changed from WARNING to INFO (localhost is the default for MCP servers)
- `quality/stale-references`: "moment" (the English word) no longer fires; requires `moment.js`, `moment(`, etc.
- `quality/imprecise-instruction`: removed passive voice patterns ("should be run", "must be checked") which flagged clear instructions
- `hooks/env-leakage`: only flags sensitive variable names (TOKEN, SECRET, KEY, PASSWORD), not all env vars
- `hooks/network-access`: removed bare `http` and `fetch` patterns; only flags actual network tools (curl, wget, netcat)
- `claude-md/skill-duplication` and `command/skill-overlap`: raised TF-IDF threshold from 0.60 to 0.80 to reduce false positives on same-domain content
- Agent/command variants of data-exfiltration, obfuscation, and reverse-shell rules now have code-block awareness (previously fired at ERROR on code examples)
- Agent/command credential-access rules now skip matches inside code blocks
- 22 new tests covering all 16 previously untested rules (agent, command, and content categories)

## [4.1.0] - 2026-07-08

### Added
- `--fail-on-warning` flag for lint and security commands: exit code 1 on any warnings or errors (not just errors)
- Versioned data files under `src/harness_eval/data/` for knowledge that decays: built-in commands list and tautological pattern definitions

### Changed
- AGENTS.md attribution changed from "opencode" to "agents-md" (cross-tool standard, not OpenCode-specific)
- tiktoken moved from hard dependency to optional extra (`pip install harness-eval[tiktoken]`). Token counting falls back to chars/4 when tiktoken is not installed.
- Built-in command list (`builtins.json`) and tautological patterns (`tautological_patterns.json`) extracted from hardcoded Python to versioned JSON data files
- Generic advice patterns in claude-md/generic_advice.py now load from the shared tautological patterns data file (first 12 entries), eliminating duplication with quality/_patterns.py

### Fixed
- Token counting no longer crashes in air-gapped or egress-restricted environments. Falls back to chars/4 heuristic when tiktoken cannot download the cl100k_base BPE file, with a one-time warning.
- Orphan detection no longer flags unreferenced skills. Skills are activated by description matching, not explicit references, so an unreferenced skill is healthy. Orphan detection is now scoped to commands and agents only.

## [4.0.0] - 2026-07-08

### Changed
- **BREAKING**: Python package renamed from `harness_eval_lab` to `harness_eval`. Update imports: `from harness_eval...` instead of `from harness_eval_lab...`
- **BREAKING**: CLI subcommands shortened: `lint`, `review`, `security`, `skill` (previously `harness-eval-lint`, `harness-eval-review`, `harness-eval-security`, `eval-skill`)
- GitHub repo renamed from `harness-eval-lab` to `harness-eval`
- Skill directories renamed: `skills/lint/`, `skills/review/`, `skills/security/` (previously `skills/harness-eval-lint/`, etc.)
- Command files renamed: `commands/lint.md`, `commands/review.md`, `commands/security.md`

## [3.8.0] - 2026-07-07

### Added
- Multi-assistant discovery: Copilot (`.github/skills/`, `.github/prompts/`, `.github/agents/`), Gemini CLI (`GEMINI.md`, `.gemini/commands/`), OpenCode (`AGENTS.md`, `.opencode/commands/`, `.opencode/agents/`)
- Third-party module discovery: scans `.lola/modules/` for skills, commands, and agents installed via package managers
- New rule `mcp/valid-config`: validates MCP configuration JSON structure (mcpServers key, server transport, args/env types)
- New rule `hooks/script-boundary`: ensures hook scripts resolve within the project directory (path traversal prevention)
- New rule `agent/model-specified`: suggests adding a model field to agent definitions (off by default, info in strict)
- MCP_CONFIG linting in the engine: MCP config files are now inspected by rules (previously discovered but not linted)
- New rule `mcp/duplicate-server`: flags duplicate MCP server URLs in configuration
- New rule `mcp/suspicious-endpoint`: flags MCP servers pointing to localhost or private IP ranges
- New rule `mcp/no-wildcard-tools`: flags MCP servers that expose all tools without restriction
- New rule `hooks/dangerous-command`: flags hooks containing destructive shell commands (rm -rf, chmod 777, dd, mkfs, fork bombs)
- New rule `hooks/env-leakage`: flags hooks that may leak environment variables via echo/printenv
- New rule `hooks/network-access`: flags hooks that make network calls (curl, wget, netcat)
- New rule `security/bash-taint-flow`: detects untrusted input flowing to dangerous sinks in bash scripts
- Future-plans spec for distributable packaging
- SARIF v2.1.0 output format (`--format sarif`) for `harness-eval-lint` and `harness-eval-security`, enabling GitHub code scanning inline annotations
- `--output` flag for writing lint and security output to a file instead of stdout

### Changed
- Tool-neutral language in rule messages (replaced assistant-specific references with generic "AI assistant")
- Consolidated duplicated security scan logic across component types into shared scanner module
- Extracted discovery layer into per-tool discoverer classes (`core/discoverers/`)
- Rule count: 43 to 58

### Removed
- Model-specific context window findings from system analysis output (model names and window sizes no longer appear in user-facing findings)

## [3.7.0] - 2026-06-29

### Added
- New `quality/` rule category with 5 lint rules for instruction effectiveness:
  - `quality/imprecise-instruction`: detect hedging, passive voice, and vague conditions
  - `quality/redundant-guidance`: detect instructions redundant with model defaults or project tooling config (.editorconfig, .prettierrc, .eslintrc, tsconfig.json, pyproject.toml)
  - `quality/unfinished-content`: detect placeholders, TODO/FIXME markers, deferred content (TBD, coming soon), and empty markdown sections
  - `quality/example-gap`: flag skills with many instructions but no code examples
  - `quality/stale-references`: detect deprecated models (text-davinci, gpt-3.5-turbo, claude-v1/v2), sunset APIs, old runtimes (Node 14/16, Python 3.7/3.8), and outdated tools (tslint, create-react-app)
- Shared pattern module `_patterns.py` for tautological detection across rules
- 56 tests covering positive matches and false-positive prevention for all quality rules
- Future plan spec for content intelligence Phase 2-3 rules

## [3.6.2] - 2026-06-29

### Added
- Path traversal protection: `safe_join()` and `is_within()` utilities prevent file references and auto-fixes from escaping the project directory
- 12 tests for path safety covering traversal, symlink escape, and absolute path injection
- Gitleaks and Bandit pre-commit hooks for secret scanning and Python security analysis
- Incident response plan in SECURITY.md (contain, assess, yank, notify, remediate, post-mortem)
- Privacy and data handling section in README documenting what each command sends externally
- CODEOWNERS: both @Benkapner and @csoceanu required for review (2 approvals), with stricter ownership rules for release-critical files

### Fixed
- Broken references rule now rejects path traversal attempts instead of following them
- Command script-exists rule now rejects path traversal in script references
- Auto-fixer validates file paths stay within project root before writing

## [3.6.1] - 2026-06-26

### Fixed
- UNKNOWN CVE severity now defaults to WARNING instead of ERROR (previously fell through to preset default)
- Subprocess calls with dynamic arguments downgraded from ERROR to WARNING (subprocess is a capability, not a vulnerability; only exec chains with decoded/fetched data remain ERROR)
- Parse errors (YAML frontmatter failures) excluded from security scan results (structural defects, not security findings)

## [3.6.0] - 2026-06-25

### Added
- LLM-based adjudication of scanner findings: when `--review` is enabled, each deterministic finding is classified as CONFIRMED, FALSE_POSITIVE, or DOWNGRADED before the risk assessment is computed
- `AdjudicatedFinding` type with `is_confirmed`, `is_false_positive`, and `effective_severity` properties
- Adjudication prompt template for structured LLM review of scanner findings
- 10 new tests covering base64 entropy filtering, subprocess argument analysis, CVE severity mapping, adjudication parsing, and adjudicated finding properties

### Changed
- Security risk assessment now uses adjudicated findings (not raw scanner output) when `--review` is enabled; without `--review`, behavior is unchanged (backward compatible)
- JSON output adds `adjudicated`, `raw_errors`, `raw_warnings`, `confirmed_errors`, `false_positives`, and `downgraded` fields
- Terminal output shows "Scanner: X errors -> After review: Y confirmed, Z false positives" when adjudicated
- `security/mcp-tool-poisoning`: base64 detection now uses Shannon entropy filtering (threshold 4.5 bits/char) and path exclusion to reduce false positives on file paths and command examples
- `security/ast-behavioral`: subprocess/os calls with hardcoded literal arguments are now reported as WARNING instead of ERROR; dynamic/user-controlled arguments remain ERROR
- `security/cve-lookup`: MEDIUM CVEs now produce WARNING (not ERROR), LOW CVEs produce INFO (not ERROR); only CRITICAL/HIGH CVEs produce ERROR

### Fixed
- False positive base64 detections on file paths containing base64-like character sequences (e.g., `/home/user/.specify/extensions.yml`)
- Overly aggressive subprocess detection flagging hardcoded `subprocess.run(["ruff", "check", "."])` as ERROR
- All CVE findings treated as errors in the security preset regardless of actual severity

## [3.5.2] - 2026-06-23

### Added
- Comprehensive tests for `content/broken-references` rule: valid links, URL skipping, anchor skipping, template variable skipping, glob skipping, inline code references, deduplication (7 new test cases)

## [3.5.0] - 2026-06-23

### Added
- Fuzzy matching for rule IDs: suppression comments, preset configs, and registry lookups now warn with "Did you mean?" suggestions when a rule ID doesn't match any registered rule
- Tool-aware rule filtering: rules can declare `tools=("claude",)` or `tools=("cursor",)` to only run for matching components
- `source_tool` field on `ParsedComponent` and `RuleContext` to track whether a component came from `.claude/` or `.cursor/`
- Cursor-aware budget analysis: respects `alwaysApply` frontmatter in `.mdc` files instead of treating all Cursor rules as always-loaded
- Tool-aware report labels: Cursor-only setups show "Cursor Rules" instead of "CLAUDE.md" in reports
- 8 new Cursor-specific tests (source_tool tracking, rule filtering, budget, report labels)

### Fixed
- `security/no-prompt-injection`: removed `\bDAN\b` from jailbreak pattern to prevent false positives on legitimate names (e.g., "Dan reviewed the PR")

### Added
- Positive-match unit tests for all 17 injection regex patterns, proving each detects its target content
- Negative-match tests confirming clean text (including "Dan") does not trigger false positives

### Changed
- `claude-md/exists`, `claude-md/generic-advice`, and `command/shadows-builtin` rules now only fire for Claude Code components (skipped for Cursor)
- `claude-md/skill-duplication` uses Cursor-appropriate message text when evaluating Cursor rules
- System analysis messages use tool-aware labels ("cursor rules" vs "CLAUDE.md")

## [3.4.0] - 2026-06-18

### Added
- `--watch` flag for `harness-eval-lint` that monitors agent setup files and re-runs lint on save

## [3.3.0] - 2026-06-17

### Added
- Impact field on rubric issues: states concrete runtime consequence for each finding
- Attack scenarios required for security review FLAG findings
- Evaluation metadata in all command outputs (version, duration, components, LLM call info)
- Parallel LLM calls in review and security commands (ThreadPoolExecutor, max 4 workers)
- Batch evaluation for small components (up to 3 per LLM call)
- Multi-tool expansion future plan (Codex, Cline, Gemini CLI, Windsurf file patterns)
- `EvalMetadata` dataclass for structured metadata output
- Batch prompt template for grouped component evaluation
- LLM client call counters (total/succeeded) for metadata tracking

### Changed
- JSON output includes `impact`, `verdict`, and `metadata` fields
- LLM prompt (issue-template.md) requests impact for each issue
- Security review rubric requires concrete attack scenarios for FLAG findings
- All review rubric files include impact guidance sections
- All SKILL.md files and Cursor commands include metadata footer instructions

### Fixed
- Broken symlink in `skills/eval-skill/rubric/skills-rubric.md` (pointed to old directory name)

## [3.1.2] - 2026-06-17

### Changed
- Renamed `harness-eval-skill` command to `eval-skill` across CLI, Claude Code plugin, and Cursor
- Renamed `how-to-contribute.md` to `CONTRIBUTING.md` (standard convention)
- LLM dependencies (anthropic, google-genai) now included in default install (no separate extras)
- Simplified README (removed duplication, fixed inconsistencies)

### Added
- `SECURITY.md` with vulnerability reporting instructions
- `py.typed` marker for type checking support
- PyPI version badge in README

## [3.1.0] - 2026-06-16

### Changed
- Renamed package from `harness-eval-lab` to `harness-eval` on PyPI (`pip install harness-eval`)
- Renamed CLI entry point from `harness-eval-lab` to `harness-eval`
- Renamed all commands: `eval-setup-lint` to `harness-eval-lint`, `eval-setup-review` to `harness-eval-review`, `eval-setup-security` to `harness-eval-security`, `eval-skill` to `eval-skill`
- Renamed plugin skill directories to match new command names
- Cursor commands rewritten to use in-session LLM (no extra API key needed for review/security/skill)

## [3.0.0] - 2026-06-16

### Added
- Cursor IDE support: discovers `.cursor/rules/*.mdc`, `.cursorrules`, `.cursor/commands/*.md`, `.cursor/skills/*/SKILL.md`, `.cursor/hooks.json`, `.cursor/mcp.json`
- Multi-tool auto-detection: reports which tools a project uses (Claude Code, Cursor, or both)
- 4 Cursor commands (`.cursor/commands/`): harness-eval-lint, harness-eval-review, harness-eval-security, eval-skill
- Component deduplication across tools (shared skills are not double-counted)
- "Detected tools" shown in terminal and JSON output
- Cursor file patterns added to fingerprinting for change detection
- Published to PyPI: `pip install harness-eval`
- 14 new tests for Cursor discovery and linting (153 total)

## [2.0.0] - 2026-06-15

### Added
- CI pipeline: GitHub Actions with lint, typecheck, test, and dogfood jobs
- CI enforces minimum 70% test coverage via `--cov-fail-under=70`
- CODEOWNERS file for PR review governance
- Skillsaw linter config (`.skillsaw.yaml`) for skill context budget validation
- `eval-setup-security` CLI command: dedicated security audit with all security rules, AST analysis, YARA scanning, CVE lookups, and optional LLM semantic review
- `eval-setup-security` plugin skill with 4-check semantic security review
- 6 new security inspection rules (MCP least-privilege, MCP tool poisoning, AST behavioral, taint tracking, YARA scan, CVE lookup)
- Security test fixtures (`tests/fixtures/security-issues/`) with injection, credential, exfiltration, and reverse shell patterns
- Security rule unit and integration tests
- E2E CLI tests using Click's CliRunner
- Mock LLM response tests for rubric checker
- Instruction clarity checks added to eval-setup-review rubrics
- PASS/FAIL/WARNING labels with legend in lint output
- Per-rule pass/fail checklist in lint output
- Discovery of `.claude/rules/`, output-styles, and uncategorized files
- Timing output for all plugin skills
- Plugin marketplace support via `marketplace.json`
- Install script and command files for plugin installation
- Native Claude Code plugin system (replaces custom install script)
- Plugin namespace prefix for command names (`harness-eval-lab:eval-setup-lint`)
- Runner abstraction future plan (`future-plans/runner-abstraction/`)
- Setup recommend future plan (`future-plans/setup-recommend/`)
- Security benchmarks future plan (`future-plans/security-benchmarks/`)
- SARIF output future plan (`future-plans/sarif-output/`)
- Prompt versioning: LLM prompts extracted to `src/harness_eval_lab/rubric/prompts/` as markdown files
- `content/circular-references` rule: detect circular reference chains between skills and commands
- `command/references-nonexistent-skill` rule: detect commands referencing skills that don't exist
- Network access detection in hooks: curl, wget, netcat, ncat patterns with dedup against pipe-to-shell
- Release script (`scripts/release.py`) for version bumping, changelog management, and tagging
- PyPI publish workflow (`.github/workflows/publish.yml`)
- README badges: CI status, coverage, Python version, license

### Changed
- Renamed "Layer 1/Layer 2" terminology to "lint/review" throughout codebase
- README updated to remove dimension-based framing, describes review as best-practices + cross-component + redundancy checking
- Future plans restructured from free-form READMEs to structured spec format (problem, proposal, user stories, requirements, success criteria)
- SessionStart `ensure_deps.py` rewritten with isolated venv, stamp-based caching, and uv/pip fallback
- Report output reordered for clarity, added exact timing
- Reduced false positives in lint output
- MCP least-privilege rule skips overdeclared check on SKILL.md-only skills
- Security command outputs only security findings (not full lint)
- Deduplicated YARA/CVE skip notices in security output

### Removed
- References to "5 dimensions" (Soundness, Safety, Coherence, Efficiency, Impact) from README
- `future-plans/impact-dimension/` and `future-plans/scoring-calibration/` removed from README (plans still exist, just not listed as active)
- Context utilization section removed from lint output

## [0.1.0] - 2026-05-01

Initial release.

- 26 deterministic inspection rules across 8 categories
- System-level analysis (token budget, trigger overlaps, dependencies, context utilization)
- LLM-based qualitative review with per-component issue categories
- CLI with 3 commands: eval-setup-lint, eval-setup-review, eval-skill
- Claude Code plugin with 3 skills
- 62 tests
