"""Tests for --exclude pattern filtering."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.setup import discover_setup


def _make_skill(tmp: Path, name: str, body: str = "Test skill.") -> None:
    skill_dir = tmp / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill\n---\n\n{body}"
    )


class TestExclude:
    def test_excluded_skill_not_in_results(self, tmp_path: Path) -> None:
        _make_skill(tmp_path, "keep-me")
        _make_skill(tmp_path, "drop-me")
        (tmp_path / "CLAUDE.md").write_text("# Test")

        setup = discover_setup("test", str(tmp_path), exclude=("**/drop-me/*",))
        names = [c.name for c in setup.components]
        assert "drop-me" not in str(names)
        assert any("keep-me" in str(n) for n in names)

    def test_non_excluded_skill_still_scanned(self, tmp_path: Path) -> None:
        _make_skill(tmp_path, "my-skill")
        (tmp_path / "CLAUDE.md").write_text("# Test")

        setup = discover_setup("test", str(tmp_path), exclude=("*.yml",))
        skill_names = [c.name for c in setup.components if "my-skill" in c.name]
        assert len(skill_names) >= 1

    def test_filename_glob_excludes(self, tmp_path: Path) -> None:
        _make_skill(tmp_path, "good-skill")
        (tmp_path / "CLAUDE.md").write_text("# Test")
        ci_dir = tmp_path / ".github" / "workflows"
        ci_dir.mkdir(parents=True)
        (ci_dir / "lint.yml").write_text("name: CI")

        setup = discover_setup("test", str(tmp_path), exclude=("*.yml",))
        paths = [c.path for c in setup.components]
        assert not any("lint.yml" in p for p in paths)

    def test_directory_glob_excludes(self, tmp_path: Path) -> None:
        _make_skill(tmp_path, "good-skill")
        (tmp_path / "CLAUDE.md").write_text("# Test")
        scripts_dir = tmp_path / ".github" / "scripts"
        scripts_dir.mkdir(parents=True)
        (scripts_dir / "install.sh").write_text("#!/bin/bash\nsudo apt install foo")

        setup = discover_setup("test", str(tmp_path), exclude=(".github/scripts/*",))
        paths = [c.path for c in setup.components]
        assert not any("install.sh" in p for p in paths)

    def test_empty_exclude_changes_nothing(self, tmp_path: Path) -> None:
        _make_skill(tmp_path, "my-skill")
        (tmp_path / "CLAUDE.md").write_text("# Test")

        setup_no_exclude = discover_setup("test", str(tmp_path))
        setup_with_empty = discover_setup("test", str(tmp_path), exclude=())
        assert len(setup_no_exclude.components) == len(setup_with_empty.components)
