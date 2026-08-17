"""Tests for setup discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentScope, ComponentType


def test_discover_setup_a(setup_a_path: str) -> None:
    setup = discover_setup("setup-a", setup_a_path)
    assert setup.name == "setup-a"
    assert setup.fingerprint
    assert setup.total_tokens > 0


def test_discover_claude_md(setup_a_path: str) -> None:
    setup = discover_setup("setup-a", setup_a_path)
    claude_mds = setup.by_type(ComponentType.CLAUDE_MD)
    assert len(claude_mds) == 1
    assert "Project Instructions" in claude_mds[0].content


def test_discover_skills(setup_a_path: str) -> None:
    setup = discover_setup("setup-a", setup_a_path)
    skills = setup.by_type(ComponentType.SKILL)
    assert len(skills) == 1
    assert skills[0].name == "code-review"
    assert skills[0].frontmatter is not None
    assert skills[0].frontmatter["name"] == "code-review"


def test_discover_commands(setup_a_path: str) -> None:
    setup = discover_setup("setup-a", setup_a_path)
    commands = setup.by_type(ComponentType.COMMAND)
    assert len(commands) == 1
    assert commands[0].name == "review"


def test_discover_hooks(setup_a_path: str) -> None:
    setup = discover_setup("setup-a", setup_a_path)
    hooks = setup.by_type(ComponentType.HOOKS)
    assert len(hooks) == 1
    assert "PreToolUse" in hooks[0].content


def test_setup_b_has_more_components(setup_a_path: str, setup_b_path: str) -> None:
    setup_a = discover_setup("setup-a", setup_a_path)
    setup_b = discover_setup("setup-b", setup_b_path)
    assert len(setup_b.components) > len(setup_a.components)


def test_setup_b_skills(setup_b_path: str) -> None:
    setup = discover_setup("setup-b", setup_b_path)
    skills = setup.by_type(ComponentType.SKILL)
    skill_names = {s.name for s in skills}
    assert skill_names == {"code-review", "security-scan"}


def test_setup_b_commands(setup_b_path: str) -> None:
    setup = discover_setup("setup-b", setup_b_path)
    commands = setup.by_type(ComponentType.COMMAND)
    cmd_names = {c.name for c in commands}
    assert cmd_names == {"review", "deploy"}


def test_discover_nonexistent_path() -> None:
    with pytest.raises(FileNotFoundError):
        discover_setup("bad", "/nonexistent/path")


def test_scope_field_default(setup_a_path: str) -> None:
    setup = discover_setup("setup-a", setup_a_path)
    for comp in setup.components:
        assert comp.scope == ComponentScope.PROJECT


def test_discover_user_global_claude_md(setup_a_path: str, tmp_path) -> None:
    user_dir = tmp_path / ".claude"
    user_dir.mkdir()
    (user_dir / "CLAUDE.md").write_text("# Global user instructions\nUse uv.\n")

    setup = discover_setup("setup-a", setup_a_path, user_config_dir=str(user_dir))
    claude_mds = setup.by_type(ComponentType.CLAUDE_MD)
    user_globals = [c for c in claude_mds if c.scope == ComponentScope.USER_GLOBAL]
    assert len(user_globals) == 1
    assert "Global user instructions" in user_globals[0].content
    assert "(user-global)" in user_globals[0].name


def test_discover_user_project_claude_md(setup_a_path: str, tmp_path) -> None:
    user_dir = tmp_path / ".claude"
    projects_dir = user_dir / "projects" / "abc123"
    projects_dir.mkdir(parents=True)
    (projects_dir / "CLAUDE.md").write_text("# Project-scoped user instructions\n")

    setup = discover_setup("setup-a", setup_a_path, user_config_dir=str(user_dir))
    claude_mds = setup.by_type(ComponentType.CLAUDE_MD)
    user_projects = [c for c in claude_mds if c.scope == ComponentScope.USER_PROJECT]
    assert len(user_projects) == 1
    assert "Project-scoped" in user_projects[0].content
    assert "abc123" in user_projects[0].name


def test_no_user_config_graceful(setup_a_path: str) -> None:
    setup = discover_setup("setup-a", setup_a_path, user_config_dir="/nonexistent/path")
    claude_mds = setup.by_type(ComponentType.CLAUDE_MD)
    user_scoped = [c for c in claude_mds if c.scope != ComponentScope.PROJECT]
    assert len(user_scoped) == 0


def test_svg_not_treated_as_binary(tmp_path: Path) -> None:
    """SVG files are text and should be discovered, not skipped as binary."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    svg_file = claude_dir / "diagram.svg"
    svg_file.write_text('<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>')
    (tmp_path / "CLAUDE.md").write_text("# Instructions\n")

    setup = discover_setup("svg-test", str(tmp_path))
    paths = [c.path for c in setup.components]
    assert any("diagram.svg" in p for p in paths), "SVG should be discovered"


def test_binary_file_skipped(tmp_path: Path) -> None:
    """Actual binary files (.png, .exe) should be skipped."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    png_file = claude_dir / "icon.png"
    png_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    (tmp_path / "CLAUDE.md").write_text("# Instructions\n")

    setup = discover_setup("binary-test", str(tmp_path))
    paths = [c.path for c in setup.components]
    assert not any("icon.png" in p for p in paths), "PNG should be skipped"


def test_unknown_text_extension_discovered(tmp_path: Path) -> None:
    """Files with unknown extensions containing text should be discovered."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    xyz_file = claude_dir / "config.xyz"
    xyz_file.write_text("some configuration text")
    (tmp_path / "CLAUDE.md").write_text("# Instructions\n")

    setup = discover_setup("unknown-ext-test", str(tmp_path))
    paths = [c.path for c in setup.components]
    assert any("config.xyz" in p for p in paths), "Unknown text extension should be discovered"
