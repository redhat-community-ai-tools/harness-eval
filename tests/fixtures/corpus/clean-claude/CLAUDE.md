# Project Instructions

This is a Python CLI application using Click for the command interface.

## Development

- Python 3.12+, managed with `uv`
- Run tests: `uv run pytest`
- Lint: `uv run ruff check src/ tests/`
- Format: `uv run ruff format src/ tests/`

## Conventions

- Use frozen dataclasses for domain objects
- All CLI commands go in `src/app/cli/`
- Tests mirror the source structure under `tests/`
