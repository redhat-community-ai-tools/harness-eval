"""Tests for content/skill-script-exists."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import harness_eval.inspection  # noqa: F401 — triggers register_all_rules
from harness_eval.inspection.engine import lint
from harness_eval.inspection.registry import get_all_rules

RULE_ID = "content/skill-script-exists"
RULE_CONFIG = {RULE_ID: "error"}


def _make_skill(root: Path, rel_dir: str, body: str, frontmatter: str = "") -> Path:
    skill_dir = root / rel_dir
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {skill_dir.name}\ndescription: Test skill\n{frontmatter}---\n\n{body}"
    )
    return skill_dir


def _write(path: Path, text: str = "# ok\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _findings(skill_dir: Path, project_root: Path | None = None) -> list[Any]:
    scan_state: dict[str, Any] = {}
    if project_root is not None:
        scan_state["project_root"] = str(project_root)
    result = lint(str(skill_dir), RULE_CONFIG, scan_state=scan_state)
    return [d for d in result.diagnostics if d.rule_id == RULE_ID]


class TestSkillDir:
    def test_missing_script_in_code_block_is_reported(self, tmp_path: Path) -> None:
        body = "Run it:\n\n```bash\npython3 ${CLAUDE_SKILL_DIR}/scripts/check.py --root .\n```\n"
        skill = _make_skill(tmp_path, "skills/demo", body)
        (finding,) = _findings(skill, tmp_path)
        assert "${CLAUDE_SKILL_DIR}/scripts/check.py" in finding.message
        assert finding.location.start_line == 9

    def test_existing_script_is_not_reported(self, tmp_path: Path) -> None:
        skill = _make_skill(
            tmp_path, "skills/demo", "```bash\npython3 ${CLAUDE_SKILL_DIR}/scripts/check.py\n```\n"
        )
        _write(skill / "scripts" / "check.py")
        assert not _findings(skill, tmp_path)

    def test_missing_script_in_inline_code_is_reported(self, tmp_path: Path) -> None:
        skill = _make_skill(tmp_path, "skills/demo", "Run `${CLAUDE_SKILL_DIR}/scripts/go.sh`.\n")
        assert len(_findings(skill, tmp_path)) == 1

    def test_trailing_sentence_period_is_not_part_of_the_path(self, tmp_path: Path) -> None:
        skill = _make_skill(
            tmp_path, "skills/demo", "Then run ${CLAUDE_SKILL_DIR}/scripts/go.sh.\n"
        )
        _write(skill / "scripts" / "go.sh")
        assert not _findings(skill, tmp_path)

    def test_reference_in_frontmatter_is_checked(self, tmp_path: Path) -> None:
        frontmatter = (
            "hooks:\n  PreToolUse:\n    - hooks:\n"
            "        - type: command\n"
            "          command: ${CLAUDE_SKILL_DIR}/scripts/guard.sh\n"
        )
        skill = _make_skill(tmp_path, "skills/demo", "Body.\n", frontmatter)
        assert len(_findings(skill, tmp_path)) == 1

    def test_same_reference_twice_is_reported_once(self, tmp_path: Path) -> None:
        body = "`${CLAUDE_SKILL_DIR}/scripts/a.py`\n\n`${CLAUDE_SKILL_DIR}/scripts/a.py`\n"
        skill = _make_skill(tmp_path, "skills/demo", body)
        assert len(_findings(skill, tmp_path)) == 1

    def test_without_a_project_root_the_skill_directory_bounds_the_check(
        self, tmp_path: Path
    ) -> None:
        body = "`${CLAUDE_SKILL_DIR}/scripts/a.py` and `${CLAUDE_SKILL_DIR}/../x/b.py`\n"
        skill = _make_skill(tmp_path, "demo", body)
        (finding,) = _findings(skill)
        assert "scripts/a.py" in finding.message


class TestOutsideTheSkillDirectory:
    def test_sibling_script_inside_the_project_resolves(self, tmp_path: Path) -> None:
        skill = _make_skill(
            tmp_path, "skills/demo", "`${CLAUDE_SKILL_DIR}/../shared/scripts/lib.py`\n"
        )
        _write(tmp_path / "skills" / "shared" / "scripts" / "lib.py")
        assert not _findings(skill, tmp_path)

    def test_missing_sibling_script_inside_the_project_is_reported(self, tmp_path: Path) -> None:
        skill = _make_skill(
            tmp_path, "skills/demo", "`${CLAUDE_SKILL_DIR}/../shared/scripts/lib.py`\n"
        )
        assert len(_findings(skill, tmp_path)) == 1

    def test_path_leaving_the_project_is_not_checked(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        skill = _make_skill(
            project, "skills/demo", "`${CLAUDE_SKILL_DIR}/../../../elsewhere/run.py`\n"
        )
        assert not _findings(skill, project)

    def test_script_behind_a_symlinked_directory_resolves(self, tmp_path: Path) -> None:
        skill = _make_skill(tmp_path, "skills/demo", "`${CLAUDE_SKILL_DIR}/scripts/pkg/run.py`\n")
        _write(tmp_path / "pkg" / "run.py")
        (skill / "scripts").mkdir()
        (skill / "scripts" / "pkg").symlink_to(tmp_path / "pkg", target_is_directory=True)
        assert not _findings(skill, tmp_path)


class TestPluginRoot:
    def test_missing_script_under_the_plugin_root_is_reported(self, tmp_path: Path) -> None:
        _write(tmp_path / ".claude-plugin" / "plugin.json", '{"name": "demo"}')
        skill = _make_skill(
            tmp_path, "skills/demo", "`${CLAUDE_PLUGIN_ROOT}/skills/other/scripts/x.py`\n"
        )
        assert len(_findings(skill, tmp_path)) == 1

    def test_existing_script_under_the_plugin_root_resolves(self, tmp_path: Path) -> None:
        _write(tmp_path / ".claude-plugin" / "plugin.json", '{"name": "demo"}')
        _write(tmp_path / "skills" / "other" / "scripts" / "x.py")
        skill = _make_skill(
            tmp_path, "skills/demo", "`${CLAUDE_PLUGIN_ROOT}/skills/other/scripts/x.py`\n"
        )
        assert not _findings(skill, tmp_path)

    def test_nested_plugin_uses_its_own_root(self, tmp_path: Path) -> None:
        plugin = tmp_path / "plugins" / "alpha"
        _write(plugin / ".claude-plugin" / "plugin.json", '{"name": "alpha"}')
        _write(plugin / "scripts" / "x.py")
        skill = _make_skill(plugin, "skills/demo", "`${CLAUDE_PLUGIN_ROOT}/scripts/x.py`\n")
        assert not _findings(skill, tmp_path)

    def test_skill_outside_any_plugin_is_not_checked(self, tmp_path: Path) -> None:
        skill = _make_skill(
            tmp_path, ".claude/skills/demo", "`${CLAUDE_PLUGIN_ROOT}/scripts/x.py`\n"
        )
        assert not _findings(skill, tmp_path)


class TestNotAScriptReference:
    def test_data_file_is_not_checked(self, tmp_path: Path) -> None:
        body = "Writes `${CLAUDE_SKILL_DIR}/cache/state.json` and `${CLAUDE_SKILL_DIR}/out.md`.\n"
        skill = _make_skill(tmp_path, "skills/demo", body)
        assert not _findings(skill, tmp_path)

    def test_placeholders_and_globs_are_not_checked(self, tmp_path: Path) -> None:
        body = (
            "`${CLAUDE_SKILL_DIR}/scripts/<name>.py`\n"
            "`${CLAUDE_SKILL_DIR}/scripts/*.py`\n"
            "`${CLAUDE_SKILL_DIR}/scripts/run_$MODE.py`\n"
            "`${CLAUDE_SKILL_DIR}/scripts/my_script.py`\n"
            "`${CLAUDE_SKILL_DIR}/scripts/example.sh`\n"
        )
        skill = _make_skill(tmp_path, "skills/demo", body)
        assert not _findings(skill, tmp_path)

    def test_unbraced_variable_is_not_checked(self, tmp_path: Path) -> None:
        skill = _make_skill(tmp_path, "skills/demo", "`$CLAUDE_SKILL_DIR/scripts/x.py`\n")
        assert not _findings(skill, tmp_path)

    def test_bare_relative_path_is_left_to_broken_references(self, tmp_path: Path) -> None:
        skill = _make_skill(tmp_path, "skills/demo", "Run `scripts/x.py`.\n")
        assert not _findings(skill, tmp_path)


def test_rule_is_a_provisional_block_rule() -> None:
    (rule,) = [r for r in get_all_rules() if r.meta.id == RULE_ID]
    assert rule.meta.effect == "block"
    assert rule.meta.tier == "provisional"
    assert rule.meta.scope == "FILE_FS"
