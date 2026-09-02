"""Tests for recursive discovery, symlink safety, and deduplication."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from harness_eval.core.discoverers.base import _recursive_glob
from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType


@pytest.fixture
def nested_skills_tree(tmp_path: Path) -> Path:
    """Create a project tree with skills at multiple nesting levels."""
    # Root-level CLAUDE.md (so Claude Code discoverer detects the project)
    (tmp_path / "CLAUDE.md").write_text("# Root\n")

    # Root-level skill
    root_skill = tmp_path / "skills" / "root-skill"
    root_skill.mkdir(parents=True)
    (root_skill / "SKILL.md").write_text("---\nname: root-skill\n---\nRoot skill.\n")

    # Nested skill at apps/frontend/skills/
    nested_skill = tmp_path / "apps" / "frontend" / "skills" / "nested-skill"
    nested_skill.mkdir(parents=True)
    (nested_skill / "SKILL.md").write_text("---\nname: nested-skill\n---\nNested skill.\n")

    # Deeply nested skill at packages/core/skills/
    deep_skill = tmp_path / "packages" / "core" / "skills" / "deep-skill"
    deep_skill.mkdir(parents=True)
    (deep_skill / "SKILL.md").write_text("---\nname: deep-skill\n---\nDeep skill.\n")

    return tmp_path


class TestRecursiveDiscovery:
    def test_recursive_discovers_nested_configs(self, nested_skills_tree: Path) -> None:
        setup = discover_setup("test", str(nested_skills_tree), recursive=True)
        skills = setup.by_type(ComponentType.SKILL)
        skill_names = {s.name for s in skills}
        assert "root-skill" in skill_names
        assert "nested-skill" in skill_names
        assert "deep-skill" in skill_names

    def test_non_recursive_skips_nested(self, nested_skills_tree: Path) -> None:
        setup = discover_setup("test", str(nested_skills_tree), recursive=False)
        skills = setup.by_type(ComponentType.SKILL)
        skill_names = {s.name for s in skills}
        assert "root-skill" in skill_names
        assert "nested-skill" not in skill_names
        assert "deep-skill" not in skill_names


class TestExcludedDirectories:
    def test_excluded_directories_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Root\n")

        # Skill inside node_modules (should be excluded)
        excluded_skill = tmp_path / "node_modules" / "pkg" / "skills" / "bad-skill"
        excluded_skill.mkdir(parents=True)
        (excluded_skill / "SKILL.md").write_text("---\nname: bad-skill\n---\nShould skip.\n")

        # Skill outside node_modules (should be found)
        good_skill = tmp_path / "lib" / "skills" / "good-skill"
        good_skill.mkdir(parents=True)
        (good_skill / "SKILL.md").write_text("---\nname: good-skill\n---\nShould find.\n")

        setup = discover_setup("test", str(tmp_path), recursive=True)
        skills = setup.by_type(ComponentType.SKILL)
        skill_names = {s.name for s in skills}
        assert "good-skill" in skill_names
        assert "bad-skill" not in skill_names

    def test_mcp_under_tests_fixtures_is_skipped(self, tmp_path: Path) -> None:
        import json

        (tmp_path / "CLAUDE.md").write_text("# Root\n")
        real_mcp = tmp_path / ".mcp.json"
        real_mcp.write_text(json.dumps({"mcpServers": {}}))
        fixture_mcp = tmp_path / "tests" / "fixtures" / "corpus" / "sample" / ".mcp.json"
        fixture_mcp.parent.mkdir(parents=True)
        fixture_mcp.write_text(
            json.dumps({"mcpServers": {"npx-pkg": {"command": "npx", "args": ["foo"]}}})
        )

        setup = discover_setup("test", str(tmp_path))
        mcp_paths = [Path(c.path).resolve() for c in setup.by_type(ComponentType.MCP_CONFIG)]
        assert real_mcp.resolve() in mcp_paths
        assert fixture_mcp.resolve() not in mcp_paths


class TestDeduplication:
    def test_deduplication(self, nested_skills_tree: Path) -> None:
        setup = discover_setup("test", str(nested_skills_tree), recursive=True)
        skills = setup.by_type(ComponentType.SKILL)
        paths = [s.path for s in skills]
        # No path should appear more than once
        assert len(paths) == len(set(paths))

    def test_root_skill_not_duplicated(self, tmp_path: Path) -> None:
        """A root-level skill should not be reported twice with recursive=True."""
        (tmp_path / "CLAUDE.md").write_text("# Root\n")
        skill = tmp_path / "skills" / "only-skill"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: only-skill\n---\nOnly skill.\n")

        setup = discover_setup("test", str(tmp_path), recursive=True)
        skills = setup.by_type(ComponentType.SKILL)
        matching = [s for s in skills if s.name == "only-skill"]
        assert len(matching) == 1


class TestSymlinkSafety:
    def test_symlink_outside_repo_is_skipped(self, tmp_path: Path) -> None:
        """Symlinks pointing outside the project root are skipped."""
        project = tmp_path / "project"
        project.mkdir()

        outside = tmp_path / "outside"
        outside.mkdir()

        # Create a real skill outside the project
        outside_skill = outside / "skills" / "external-skill"
        outside_skill.mkdir(parents=True)
        (outside_skill / "SKILL.md").write_text("---\nname: external-skill\n---\nExternal.\n")

        # Symlink from inside the project to outside
        link_dir = project / "linked-stuff" / "skills" / "external-skill"
        link_dir.parent.mkdir(parents=True)
        os.symlink(outside_skill / "SKILL.md", link_dir.parent / "SKILL.md")

        results = _recursive_glob(project, "skills/*/SKILL.md")
        resolved_paths = {str(r.resolve()) for r in results}
        assert str((outside_skill / "SKILL.md").resolve()) not in resolved_paths

    def test_symlink_inside_repo_is_kept(self, tmp_path: Path) -> None:
        """Symlinks pointing within the project root are kept."""
        # Create a real skill
        real_skill = tmp_path / "skills" / "real-skill"
        real_skill.mkdir(parents=True)
        (real_skill / "SKILL.md").write_text("---\nname: real-skill\n---\nReal.\n")

        # Create a symlink within the project
        link_skill = tmp_path / "apps" / "skills" / "link-skill"
        link_skill.mkdir(parents=True)
        os.symlink(real_skill / "SKILL.md", link_skill / "SKILL.md")

        results = _recursive_glob(tmp_path, "skills/*/SKILL.md")
        result_names = {r.parent.name for r in results}
        assert "real-skill" in result_names
        assert "link-skill" in result_names

    def test_broken_symlink_is_skipped(self, tmp_path: Path) -> None:
        """Broken symlinks are skipped without raising errors."""
        skill_dir = tmp_path / "skills" / "broken-skill"
        skill_dir.mkdir(parents=True)
        os.symlink("/nonexistent/path/SKILL.md", skill_dir / "SKILL.md")

        # Should not raise
        results = _recursive_glob(tmp_path, "skills/*/SKILL.md")
        assert len(results) == 0


class TestRootAgentsDiscovery:
    def test_discovers_repo_root_agents(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Root\n")
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir()
        (agents_dir / "review.md").write_text(
            "---\nname: review\ndescription: Reviews pull requests\n---\n\nReview the diff.\n"
        )
        (agents_dir / "triage.md").write_text(
            "---\nname: triage\ndescription: Triages incoming issues\n---\n\nTriage issues.\n"
        )

        setup = discover_setup("test", str(tmp_path))
        agents = setup.by_type(ComponentType.AGENT)
        names = {Path(a.path).name for a in agents}
        assert "review.md" in names
        assert "triage.md" in names

    def test_root_agents_not_duplicated_with_claude_agents(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Root\n")
        claude_agents = tmp_path / ".claude" / "agents"
        claude_agents.mkdir(parents=True)
        (claude_agents / "review.md").write_text(
            "---\nname: review\ndescription: Reviews pull requests\n---\n\nReview.\n"
        )
        root_agents = tmp_path / "agents"
        root_agents.mkdir()
        (root_agents / "triage.md").write_text(
            "---\nname: triage\ndescription: Triages incoming issues\n---\n\nTriage.\n"
        )

        setup = discover_setup("test", str(tmp_path))
        agents = setup.by_type(ComponentType.AGENT)
        paths = {Path(a.path).resolve() for a in agents}
        assert len(paths) == 2
