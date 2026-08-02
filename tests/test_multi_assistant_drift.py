"""Tests for cross/multi-assistant-drift rule."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint

RULE_CONFIG = {"cross/multi-assistant-drift": "warning"}


def _make_project_with_memory_files(tmp_path: Path, files: dict[str, str]) -> str:
    """Create a project with memory files and a minimal skill."""
    # Create .git dir to mark project root
    (tmp_path / ".git").mkdir()

    # Write memory files
    for name, content in files.items():
        (tmp_path / name).write_text(content)

    # Create a skill
    skill_dir = tmp_path / "skills" / "test-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: test-skill\ndescription: Test\n---\n\nTest body."
    )
    return str(skill_dir)


# Two files with the same section but slightly different content (diverged copies)
_CLAUDE_MD = """# Project Setup

This project uses Python 3.11 with uv for package management.
Run tests with `uv run pytest`. Format with `uv run ruff format`.
Always check lint before committing with `uv run ruff check`.

# Conventions

Use frozen dataclasses for domain objects. Keep functions short.
Follow PEP 8. Use type hints everywhere.
"""

_AGENTS_MD_DIVERGED = """# Project Setup

This project uses Python 3.11 with uv for package management.
Run tests with `pytest`. Format with `ruff format`.
Always check lint before committing with `ruff check`.
Use mypy for type checking.

# Conventions

Use frozen dataclasses for domain objects. Keep functions short.
Follow PEP 8. Use type hints everywhere.
"""

_AGENTS_MD_SYNCED = """# Project Setup

This project uses Python 3.11 with uv for package management.
Run tests with `uv run pytest`. Format with `uv run ruff format`.
Always check lint before committing with `uv run ruff check`.

# Conventions

Use frozen dataclasses for domain objects. Keep functions short.
Follow PEP 8. Use type hints everywhere.
"""

_AGENTS_MD_DIFFERENT = """# Architecture

The system uses a microservices approach with gRPC communication.
Each service has its own database and API boundary.
"""


class TestMultiAssistantDrift:
    def test_flags_diverged_sections(self, tmp_path: Path) -> None:
        path = _make_project_with_memory_files(
            tmp_path,
            {
                "CLAUDE.md": _CLAUDE_MD,
                "AGENTS.md": _AGENTS_MD_DIVERGED,
            },
        )
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "cross/multi-assistant-drift"]
        assert len(diags) >= 1
        assert any("CLAUDE.md" in d.message and "AGENTS.md" in d.message for d in diags)

    def test_skips_synced_copies(self, tmp_path: Path) -> None:
        path = _make_project_with_memory_files(
            tmp_path,
            {
                "CLAUDE.md": _CLAUDE_MD,
                "AGENTS.md": _AGENTS_MD_SYNCED,
            },
        )
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "cross/multi-assistant-drift"]
        assert len(diags) == 0

    def test_skips_different_content(self, tmp_path: Path) -> None:
        path = _make_project_with_memory_files(
            tmp_path,
            {
                "CLAUDE.md": _CLAUDE_MD,
                "AGENTS.md": _AGENTS_MD_DIFFERENT,
            },
        )
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "cross/multi-assistant-drift"]
        assert len(diags) == 0

    def test_skips_single_file(self, tmp_path: Path) -> None:
        path = _make_project_with_memory_files(
            tmp_path,
            {
                "CLAUDE.md": _CLAUDE_MD,
            },
        )
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "cross/multi-assistant-drift"]
        assert len(diags) == 0

    def test_skips_short_files(self, tmp_path: Path) -> None:
        path = _make_project_with_memory_files(
            tmp_path,
            {
                "CLAUDE.md": "Short.",
                "AGENTS.md": "Also short.",
            },
        )
        result = lint(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "cross/multi-assistant-drift"]
        assert len(diags) == 0
