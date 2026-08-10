# harness-eval

AI agent setup evaluation tool. See [`README.md`](README.md) for usage, features, and installation.

## Development

- Python 3.11+, managed with `uv`
- Run tests: `uv run pytest`
- Lint: `uv run ruff check src/ tests/`
- Format: `uv run ruff format src/ tests/`
- Format check (dry run): `uv run ruff format --check src/ tests/`
- Type check: `uv run mypy src/`
- See [`CONTRIBUTING.md`](CONTRIBUTING.md) for adding rules, plans, and PRs
- See [`CHANGELOG.md`](CHANGELOG.md) for release history

## Changelog

Every PR that adds a feature, fixes a bug, or changes behavior must include a CHANGELOG.md entry under `[Unreleased]`. Add it in the appropriate subsection (Added, Changed, Fixed, Removed). One line per change.

To cut a release: `uv run scripts/release.py minor` (or `patch`/`major`). This moves unreleased entries to a dated version, bumps pyproject.toml, commits, and tags.

## Before committing

The CI runs 5 jobs: lint, typecheck, test, security gate, lint gate. All must pass. Run this before committing:

```bash
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run pytest tests/ -q
uv run harness-eval harness-security . --fail-on-error      # security gate: errors block (warnings are informational)
uv run harness-eval harness-lint . --fail-on-error          # lint gate: only errors block
```

The most common CI failure is forgetting `ruff format`. The security gate blocks on any security finding (even warnings). The lint gate blocks only on structural errors (broken references, missing descriptions).

## Project structure

- `src/harness_eval/` - main package
  - `cli/` - Click CLI package (5 commands: `lint.py`, `review.py`, `security.py`, `skill.py`, `doctor.py`)
  - `config/` - rule presets (recommended/strict/security/scan/pre-workflow)
  - `core/` - setup discovery, fingerprinting, component types
    - `discoverers/` - per-tool discoverer classes (`ToolDiscoverer` ABC); add new assistants here
  - `inspection/` - static analysis: parsers, lint engine, 92 rules, suppression, auto-fix
    - `rules/security/_shared.py` - shared scanning logic used by security rules across component types
  - `rubric/` - LLM-based issue detection; prompts in `rubric/prompts/`
  - `analysis/` - system-level analysis (budget, triggers, dependencies, context utilization)
  - `output/` - report generation (terminal + JSON)
  - `utils/` - token counting, TF-IDF similarity, frontmatter parsing, LLM client, path safety
  - `data/` - versioned JSON data files (builtins, tautological patterns) for knowledge that decays
- `skills/` - plugin skills with SKILL.md + rubric files + scripts
- `tests/` - pytest test suite with fixtures

## Conventions

- Use `uv run` for all commands
- Frozen dataclasses for domain objects, Pydantic for config
- CLI uses Click command groups
- Plugin skills call Python scripts that use the same engine as the CLI
- Cross-component state in rules uses `context.scan_state`, not module-level variables
- Tests go in `tests/` mirroring the source structure
- LLM prompts live in `src/harness_eval/rubric/prompts/` as markdown files, not inline strings
- `skills/eval-skill/rubric/skills-rubric.md` is a symlink to `skills/review/rubric/skills-rubric.md`; edit the source, not the link
- YARA and CVE rules only run in the `security` preset (used by `security`), never in lint
- Rules that resolve file paths from user content must use `safe_join()` from `utils.paths` to prevent path traversal; never join untrusted paths with raw `/` or `Path()`
