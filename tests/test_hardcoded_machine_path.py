"""Tests for content/hardcoded-machine-path rule."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from harness_eval.inspection.engine import lint
from harness_eval.inspection.parsers import parse_skill

RULE_CONFIG = {"content/hardcoded-machine-path": "warning"}


def _make_skill(tmp_path: Path, name: str, content: str) -> str:
    skill_dir = tmp_path / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill\n---\n\n{content}"
    )
    return str(skill_dir)


def _lint_skill(tmp_path: Path, name: str, content: str) -> list[Any]:
    """Create a skill, parse it, and lint with all_skills populated."""
    path = _make_skill(tmp_path, name, content)
    parsed = parse_skill(path)
    scan_state: dict[str, Any] = {}
    result = lint(
        path,
        RULE_CONFIG,
        all_skills=[parsed],
        all_commands=[],
        scan_state=scan_state,
    )
    return [d for d in result.diagnostics if d.rule_id == "content/hardcoded-machine-path"]


class TestHardcodedMachinePath:
    def test_flags_home_path_in_code_block(self, tmp_path: Path) -> None:
        content = "```bash\ncp /home/alice/config.yaml .\n```"
        diags = _lint_skill(tmp_path, "home-path", content)
        assert len(diags) == 1
        assert "/home/alice/" in diags[0].message

    def test_flags_users_path_in_inline_code(self, tmp_path: Path) -> None:
        content = "Run `cat /Users/bob/settings.json` to check config."
        diags = _lint_skill(tmp_path, "users-path", content)
        assert len(diags) == 1
        assert "/Users/bob/" in diags[0].message

    def test_skips_home_in_plain_prose(self, tmp_path: Path) -> None:
        content = "The config is at /home/alice/config.yaml by default."
        diags = _lint_skill(tmp_path, "prose-path", content)
        assert len(diags) == 0

    def test_skips_runner_path(self, tmp_path: Path) -> None:
        content = "```bash\nls /home/runner/work/\n```"
        diags = _lint_skill(tmp_path, "runner-path", content)
        assert len(diags) == 0

    def test_skips_variable_reference(self, tmp_path: Path) -> None:
        content = "```bash\nls /home/$USER/config\n```"
        diags = _lint_skill(tmp_path, "var-path", content)
        assert len(diags) == 0

    def test_flags_windows_path_in_code(self, tmp_path: Path) -> None:
        content = "```\ndir C:\\Users\\Charlie\\Documents\\\n```"
        diags = _lint_skill(tmp_path, "win-path", content)
        assert len(diags) == 1

    def test_skips_path_in_url(self, tmp_path: Path) -> None:
        content = "```\ncurl https://example.com/home/alice/file\n```"
        diags = _lint_skill(tmp_path, "url-path", content)
        assert len(diags) == 0
