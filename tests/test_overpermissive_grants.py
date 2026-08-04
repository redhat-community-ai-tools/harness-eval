"""Tests for cross/overpermissive-grants rule."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint
from harness_eval.inspection.parsers import parse_skill

RULE_ID = "cross/overpermissive-grants"
RULE_CONFIG = {RULE_ID: "warning"}


def _make_skill(tmp_path: Path, name: str = "test-skill") -> Path:
    skill_dir = tmp_path / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill\n---\n\nA skill."
    )
    return skill_dir


def _make_settings(
    tmp_path: Path,
    allow_list: list[str] | None = None,
    deny_list: list[str] | None = None,
) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(exist_ok=True)
    permissions: dict = {}
    if allow_list is not None:
        permissions["allow"] = allow_list
    if deny_list is not None:
        permissions["deny"] = deny_list
    (claude_dir / "settings.json").write_text(json.dumps({"permissions": permissions}))


def _lint(tmp_path: Path, skill_dir: Path) -> list:
    all_skills = [parse_skill(str(skill_dir))]
    scan_state: dict = {}
    result = lint(
        str(skill_dir),
        RULE_CONFIG,
        scan_state=scan_state,
        all_skills=all_skills,
        all_commands=[],
    )
    return [d for d in result.diagnostics if d.rule_id == RULE_ID]


class TestOverpermissiveGrants:
    def test_flags_bash_star(self, tmp_path: Path) -> None:
        """Bash(*) should be flagged at error severity."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["Bash(*)"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 1
        assert "unrestricted shell" in diags[0].message
        assert diags[0].severity.value == "error"

    def test_flags_bare_bash(self, tmp_path: Path) -> None:
        """Bare 'Bash' without parens should be flagged."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["Bash"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 1
        assert "bare" in diags[0].message

    def test_flags_bare_edit(self, tmp_path: Path) -> None:
        """Bare 'Edit' should be flagged."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["Edit"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 1
        assert "Edit" in diags[0].message

    def test_flags_bare_write(self, tmp_path: Path) -> None:
        """Bare 'Write' should be flagged."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["Write"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 1
        assert "Write" in diags[0].message

    def test_flags_bare_webfetch(self, tmp_path: Path) -> None:
        """Bare 'WebFetch' should be flagged."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["WebFetch"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 1
        assert "WebFetch" in diags[0].message

    def test_flags_broad_bash_wildcard(self, tmp_path: Path) -> None:
        """Bash(g*) with a very short prefix should be flagged."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["Bash(g*)"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 1
        assert "too broad" in diags[0].message

    def test_no_flag_scoped_bash(self, tmp_path: Path) -> None:
        """Bash(npm test:*) is scoped enough, should not flag."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["Bash(npm test:*)"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 0

    def test_no_flag_read(self, tmp_path: Path) -> None:
        """Bare 'Read' is not in the high-risk set, should not flag."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["Read"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 0

    def test_no_flag_empty_allow(self, tmp_path: Path) -> None:
        """Empty allow list should not produce findings."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=[])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 0

    def test_no_flag_without_settings(self, tmp_path: Path) -> None:
        """Without settings.json, no findings."""
        skill_dir = _make_skill(tmp_path)

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 0

    def test_multiple_entries(self, tmp_path: Path) -> None:
        """Multiple overpermissive entries should each produce a finding."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["Bash(*)", "Edit", "Write"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 3

    def test_scan_state_runs_once(self, tmp_path: Path) -> None:
        """Rule should only run once across multiple skills."""
        skill_a = _make_skill(tmp_path, "skill-a")
        skill_b = _make_skill(tmp_path, "skill-b")
        _make_settings(tmp_path, allow_list=["Bash(*)"])

        all_skills = [parse_skill(str(skill_a)), parse_skill(str(skill_b))]
        scan_state: dict = {}

        result_a = lint(
            str(skill_a),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )
        result_b = lint(
            str(skill_b),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )

        diags_a = [d for d in result_a.diagnostics if d.rule_id == RULE_ID]
        diags_b = [d for d in result_b.diagnostics if d.rule_id == RULE_ID]

        assert len(diags_a) == 1
        assert len(diags_b) == 0

    def test_settings_local_also_checked(self, tmp_path: Path) -> None:
        """settings.local.json should also be checked."""
        skill_dir = _make_skill(tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir(exist_ok=True)
        (claude_dir / "settings.local.json").write_text(
            json.dumps({"permissions": {"allow": ["Bash(*)"]}})
        )

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 1

    def test_no_flag_scoped_entry_with_colon_wildcard(self, tmp_path: Path) -> None:
        """Bash(uv run ruff:*) is well-scoped, should not flag."""
        skill_dir = _make_skill(tmp_path)
        _make_settings(tmp_path, allow_list=["Bash(uv run ruff:*)"])

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 0

    def test_malformed_settings_ignored(self, tmp_path: Path) -> None:
        """Malformed JSON should not crash."""
        skill_dir = _make_skill(tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir(exist_ok=True)
        (claude_dir / "settings.json").write_text("not json")

        diags = _lint(tmp_path, skill_dir)
        assert len(diags) == 0
