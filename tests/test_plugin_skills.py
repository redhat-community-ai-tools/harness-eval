"""Integration tests for plugin skill scripts.

Each test runs the actual script against a fixture and validates the JSON output.
Catches broken paths, missing imports, schema regressions, and incorrect results.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
SKILLS = Path(__file__).parent.parent / "skills"
CLEAN_FIXTURE = FIXTURES / "sample-setup-a"
DIRTY_FIXTURE = FIXTURES / "security-issues"


def _run_script(script_path: str, args: list[str]) -> dict:
    result = subprocess.run(
        ["uv", "run", "python", script_path, *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Script failed:\n{result.stderr}"
    return json.loads(result.stdout)


class TestLintSkillScript:
    SCRIPT = str(SKILLS / "lint" / "scripts" / "run_assessment.py")

    def test_produces_valid_json(self) -> None:
        data = _run_script(self.SCRIPT, [str(CLEAN_FIXTURE)])
        assert isinstance(data, dict)

    def test_has_required_sections(self) -> None:
        data = _run_script(self.SCRIPT, [str(CLEAN_FIXTURE)])
        assert "inspection" in data
        assert "budget" in data
        assert "triggers" in data

    def test_inspection_has_summary(self) -> None:
        data = _run_script(self.SCRIPT, [str(CLEAN_FIXTURE)])
        summary = data["inspection"]["summary"]
        assert "total" in summary
        assert "errors" in summary
        assert "warnings" in summary
        assert summary["total"] > 0

    def test_preset_argument(self) -> None:
        data = _run_script(self.SCRIPT, [str(CLEAN_FIXTURE), "strict"])
        assert data["inspection"]["summary"]["total"] > 0

    def test_dirty_fixture_has_findings(self) -> None:
        data = _run_script(self.SCRIPT, [str(DIRTY_FIXTURE)])
        assert data["inspection"]["summary"]["errors"] > 0


class TestSecuritySkillScript:
    SCRIPT = str(SKILLS / "security" / "scripts" / "run_security_scan.py")

    def test_produces_valid_json(self) -> None:
        data = _run_script(self.SCRIPT, [str(CLEAN_FIXTURE)])
        assert isinstance(data, dict)

    def test_has_required_fields(self) -> None:
        data = _run_script(self.SCRIPT, [str(CLEAN_FIXTURE)])
        assert data["security_scan"] is True
        assert "risk_assessment" in data
        assert "components_scanned" in data
        assert "rules_checked" in data
        assert "findings" in data

    def test_clean_fixture_is_not_unsafe(self) -> None:
        data = _run_script(self.SCRIPT, [str(CLEAN_FIXTURE)])
        assert data["risk_assessment"] == "SAFE"

    def test_dirty_fixture_is_unsafe(self) -> None:
        data = _run_script(self.SCRIPT, [str(DIRTY_FIXTURE)])
        assert data["risk_assessment"] == "UNSAFE"
        assert data["raw_errors"] > 0
        assert len(data["findings"]) > 0

    def test_findings_have_structure(self) -> None:
        data = _run_script(self.SCRIPT, [str(DIRTY_FIXTURE)])
        for finding in data["findings"]:
            assert "component" in finding
            assert "errors" in finding
            assert "details" in finding
            for detail in finding["details"]:
                assert "rule" in detail
                assert "severity" in detail
                assert "message" in detail

    def test_rules_checked_is_nonempty(self) -> None:
        data = _run_script(self.SCRIPT, [str(CLEAN_FIXTURE)])
        assert len(data["rules_checked"]) > 10


class TestEvalSkillScript:
    SCRIPT = str(SKILLS / "eval-skill" / "scripts" / "run_skill_eval.py")
    SKILL_PATH = str(CLEAN_FIXTURE / "skills" / "code-review")

    def test_produces_valid_json(self) -> None:
        data = _run_script(self.SCRIPT, [self.SKILL_PATH])
        assert isinstance(data, dict)

    def test_has_required_fields(self) -> None:
        data = _run_script(self.SCRIPT, [self.SKILL_PATH])
        assert "skill" in data
        assert "tokens" in data
        assert "findings" in data
        assert "errors" in data
        assert "warnings" in data

    def test_has_security_section(self) -> None:
        data = _run_script(self.SCRIPT, [self.SKILL_PATH])
        assert "security" in data
        assert "errors" in data["security"]
        assert "warnings" in data["security"]
        assert "findings" in data["security"]

    def test_with_context(self) -> None:
        data = _run_script(self.SCRIPT, [self.SKILL_PATH, str(CLEAN_FIXTURE)])
        assert "context_findings" in data
        assert isinstance(data["context_findings"], list)

    def test_without_context(self) -> None:
        data = _run_script(self.SCRIPT, [self.SKILL_PATH, "-"])
        assert data["context_findings"] == []

    def test_dirty_skill_has_security_findings(self) -> None:
        dirty_skill = str(DIRTY_FIXTURE / "skills" / "exfil-skill")
        data = _run_script(self.SCRIPT, [dirty_skill])
        total_findings = len(data["findings"])
        assert total_findings > 0


class TestSkillScriptPaths:
    """Verify that all script paths referenced in SKILL.md files are correct."""

    @pytest.mark.parametrize(
        "skill_name,cli_command",
        [
            ("lint", "harness-eval harness-lint"),
            ("security", "harness-eval harness-security"),
            ("eval-skill", "harness-eval skill-review"),
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
