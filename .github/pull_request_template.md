## Summary

<!-- What does this PR do and why? -->

## Checklist

- [ ] `uv run pytest tests/ -q` passes
- [ ] `uv run ruff check src/ tests/` clean
- [ ] `uv run ruff format --check src/ tests/` clean
- [ ] `uv run harness-eval harness-security . --fail-on-warning` clean (security gate)
- [ ] `uv run harness-eval harness-lint . --fail-on-error` clean (lint gate)
- [ ] Version bumped in `pyproject.toml` if this is a feature or breaking change
- [ ] Version bumped in `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` if version changed
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if this adds, changes, or fixes behavior
