"""Integration tests for plugin skills.

Verifies that SKILL.md files reference correct CLI commands, rubric
files exist, and report format files exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

SKILLS = Path(__file__).parent.parent / "skills"


class TestSkillScriptPaths:
    """Verify that SKILL.md files reference the correct CLI commands."""

    @pytest.mark.parametrize(
        "skill_name,cli_command",
        [
            ("lint", "harness-eval harness-lint"),
            ("security", "harness-eval harness-security"),
            ("eval-skill", "harness-eval skill-review"),
            ("skill-verify", "harness-eval skill-verify"),
        ],
    )
    def test_skill_md_references_cli_command(self, skill_name: str, cli_command: str) -> None:
        skill_md = SKILLS / skill_name / "SKILL.md"
        content = skill_md.read_text()
        assert cli_command in content, (
            f"{skill_name}/SKILL.md does not reference CLI command '{cli_command}'."
        )

    @pytest.mark.parametrize(
        "skill_name",
        ["lint", "security", "eval-skill", "review"],
    )
    def test_skill_md_rubric_references_exist(self, skill_name: str) -> None:
        skill_dir = SKILLS / skill_name
        skill_md = skill_dir / "SKILL.md"
        content = skill_md.read_text()
        for line in content.splitlines():
            if "rubric/" in line and "read" in line.lower():
                for part in line.split("`"):
                    if part.startswith("rubric/") and part.endswith(".md"):
                        rubric_path = skill_dir / part
                        assert rubric_path.is_file(), (
                            f"{skill_name}/SKILL.md references '{part}' but it doesn't exist"
                        )

    @pytest.mark.parametrize(
        "skill_name",
        ["lint", "security", "eval-skill", "review"],
    )
    def test_report_format_exists(self, skill_name: str) -> None:
        skill_dir = SKILLS / skill_name
        skill_md = skill_dir / "SKILL.md"
        content = skill_md.read_text()
        if "report-format.md" in content:
            assert (skill_dir / "report-format.md").is_file(), (
                f"{skill_name}/SKILL.md references report-format.md but it doesn't exist"
            )
