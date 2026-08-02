"""Tests for cross/config-instruction-conflict rule."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint
from harness_eval.inspection.parsers import parse_skill

RULE_ID = "cross/config-instruction-conflict"
RULE_CONFIG = {RULE_ID: "warning"}


def _make_skill(
    tmp_path: Path,
    name: str,
    body: str = "A useful skill.",
    frontmatter_extra: str = "",
) -> Path:
    """Create a minimal skill directory with SKILL.md and return its path."""
    skill_dir = tmp_path / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill {name}\n{frontmatter_extra}---\n\n{body}"
    )
    return skill_dir


def _make_settings(tmp_path: Path, deny_list: list[str]) -> None:
    """Create .claude/settings.json with a deny list at the given root."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(exist_ok=True)
    settings = {"permissions": {"deny": deny_list}}
    (claude_dir / "settings.json").write_text(json.dumps(settings))


class TestConfigInstructionConflict:
    def test_flags_denied_tool_in_directive(self, tmp_path: Path) -> None:
        """Skill instructing 'use the WebFetch tool' with WebFetch denied should flag."""
        skill_dir = _make_skill(
            tmp_path, "fetch-skill", body="Use the WebFetch tool to download the page."
        )
        _make_settings(tmp_path, ["WebFetch"])

        all_skills = [parse_skill(str(skill_dir))]
        scan_state: dict = {}

        result = lint(
            str(skill_dir),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )

        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "WebFetch" in diags[0].message

    def test_flags_denied_bash_prefix(self, tmp_path: Path) -> None:
        """Skill with bash block using 'git push' denied via Bash(git push:*) should flag."""
        skill_dir = _make_skill(
            tmp_path,
            "push-skill",
            body="```bash\ngit push origin main\n```",
        )
        _make_settings(tmp_path, ["Bash(git push:*)"])

        all_skills = [parse_skill(str(skill_dir))]
        scan_state: dict = {}

        result = lint(
            str(skill_dir),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )

        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1

    def test_flags_bare_tool_deny(self, tmp_path: Path) -> None:
        """Bare 'Bash' deny should match any Bash(...) instruction."""
        skill_dir = _make_skill(
            tmp_path,
            "bash-skill",
            body="```bash\nls -la\n```",
        )
        _make_settings(tmp_path, ["Bash"])

        all_skills = [parse_skill(str(skill_dir))]
        scan_state: dict = {}

        result = lint(
            str(skill_dir),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )

        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1

    def test_no_conflict_when_not_denied(self, tmp_path: Path) -> None:
        """Skill with bash 'git status' should not flag when WebFetch is denied."""
        skill_dir = _make_skill(
            tmp_path,
            "status-skill",
            body="```bash\ngit status\n```",
        )
        _make_settings(tmp_path, ["WebFetch"])

        all_skills = [parse_skill(str(skill_dir))]
        scan_state: dict = {}

        result = lint(
            str(skill_dir),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )

        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_no_conflict_without_settings(self, tmp_path: Path) -> None:
        """Without a settings.json file, no conflict should be reported."""
        skill_dir = _make_skill(tmp_path, "lonely-skill", body="Use the WebFetch tool.")

        all_skills = [parse_skill(str(skill_dir))]
        scan_state: dict = {}

        result = lint(
            str(skill_dir),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )

        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_no_conflict_empty_deny(self, tmp_path: Path) -> None:
        """Empty deny list should not produce any conflict."""
        skill_dir = _make_skill(tmp_path, "safe-skill", body="Use the WebFetch tool to check.")
        _make_settings(tmp_path, [])

        all_skills = [parse_skill(str(skill_dir))]
        scan_state: dict = {}

        result = lint(
            str(skill_dir),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )

        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_scan_state_runs_once(self, tmp_path: Path) -> None:
        """Rule should only run once even when linting multiple skills."""
        skill_a = _make_skill(tmp_path, "skill-a", body="Use the WebFetch tool.")
        skill_b = _make_skill(tmp_path, "skill-b", body="Use the WebFetch tool.")
        _make_settings(tmp_path, ["WebFetch"])

        all_skills = [parse_skill(str(skill_a)), parse_skill(str(skill_b))]
        scan_state: dict = {}

        # Lint first skill: rule runs and should flag both skills
        result_a = lint(
            str(skill_a),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )

        # Lint second skill: rule should skip (scan_state guard)
        result_b = lint(
            str(skill_b),
            RULE_CONFIG,
            scan_state=scan_state,
            all_skills=all_skills,
            all_commands=[],
        )

        diags_a = [d for d in result_a.diagnostics if d.rule_id == RULE_ID]
        diags_b = [d for d in result_b.diagnostics if d.rule_id == RULE_ID]

        # First invocation should find conflicts for both skills
        assert len(diags_a) == 2
        # Second invocation should be skipped
        assert len(diags_b) == 0
