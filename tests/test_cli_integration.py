"""CLI integration tests using Click's CliRunner.

Covers all CLI commands with success and failure paths,
output format validation, and error handling.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = str(FIXTURES / "sample-setup-a")
DIRTY = str(FIXTURES / "security-issues")


class TestLintCommand:
    def test_lint_clean_fixture(self) -> None:
        result = CliRunner().invoke(cli, ["harness-lint", CLEAN])
        assert result.exit_code == 0
        assert "Setup Assessment" in result.output

    def test_lint_dirty_fixture_has_errors(self) -> None:
        result = CliRunner().invoke(cli, ["harness-lint", DIRTY])
        assert "FAIL" in result.output or "error" in result.output.lower()

    def test_lint_fail_on_error(self) -> None:
        result = CliRunner().invoke(cli, ["harness-lint", DIRTY, "--all", "--fail-on-error"])
        assert result.exit_code == 1

    def test_lint_json_output(self) -> None:
        result = CliRunner().invoke(cli, ["harness-lint", CLEAN, "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "component_count" in data

    def test_lint_sarif_output(self) -> None:
        result = CliRunner().invoke(cli, ["harness-lint", CLEAN, "--format", "sarif"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data.get("$schema") or data.get("version")

    def test_lint_with_preset(self) -> None:
        result = CliRunner().invoke(cli, ["harness-lint", CLEAN, "--preset", "strict"])
        assert result.exit_code == 0

    def test_lint_nonexistent_path(self) -> None:
        result = CliRunner().invoke(cli, ["harness-lint", "/nonexistent/path"])
        assert result.exit_code != 0


class TestSecurityCommand:
    def test_security_clean_fixture(self) -> None:
        result = CliRunner().invoke(cli, ["harness-security", CLEAN])
        assert result.exit_code == 0
        assert "Risk Assessment" in result.output

    def test_security_dirty_fixture(self) -> None:
        result = CliRunner().invoke(cli, ["harness-security", DIRTY])
        assert "UNSAFE" in result.output

    def test_security_fail_on_error(self) -> None:
        result = CliRunner().invoke(cli, ["harness-security", DIRTY, "--fail-on-error"])
        assert result.exit_code == 1

    def test_security_json_output(self) -> None:
        result = CliRunner().invoke(cli, ["harness-security", CLEAN, "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "security_scan" in data
        assert "risk_assessment" in data


class TestDoctorCommand:
    def test_doctor_runs(self) -> None:
        result = CliRunner().invoke(cli, ["doctor"])
        assert result.exit_code == 0
        assert "harness-eval" in result.output.lower()


class TestRulesCommand:
    def test_rules_list(self) -> None:
        result = CliRunner().invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "security/no-prompt-injection" in result.output

    def test_rules_category_filter(self) -> None:
        result = CliRunner().invoke(cli, ["rules", "--category", "security"])
        assert result.exit_code == 0
        assert "security/" in result.output

    def test_rules_json(self) -> None:
        result = CliRunner().invoke(cli, ["rules", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 80


class TestLintJsonOutputParseable:
    """JSON/SARIF output must be a single parseable document with no extra text."""

    @staticmethod
    def _make_fixable_setup(tmp_path: Path) -> str:
        """Create a minimal project whose SKILL.md triggers a fixable finding."""
        skill_dir = tmp_path / "skills" / "demo"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: demo\ndescription: Does a thing.\nallowed_tools: Read\n---\n\nBody text.\n"
        )
        return str(tmp_path)

    def test_json_output_is_one_document_without_fix(self, tmp_path: Path) -> None:
        path = self._make_fixable_setup(tmp_path)
        result = CliRunner().invoke(cli, ["harness-lint", path, "--all", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["fixable_count"] >= 1

    def test_json_output_is_one_document_with_fix(self, tmp_path: Path) -> None:
        path = self._make_fixable_setup(tmp_path)
        result = CliRunner().invoke(
            cli, ["harness-lint", path, "--all", "--format", "json", "--fix"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "fixed_count" in data
        assert data["fixed_count"] >= 1

    def test_sarif_output_includes_fixable_count(self, tmp_path: Path) -> None:
        path = self._make_fixable_setup(tmp_path)
        result = CliRunner().invoke(cli, ["harness-lint", path, "--all", "--format", "sarif"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["runs"][0]["properties"]["fixableCount"] >= 1


class TestLintFixIdempotency:
    """Running --fix twice must be idempotent and leave valid JSON."""

    @staticmethod
    def _make_fixable_settings(tmp_path: Path) -> Path:
        """Create .claude/settings.json with a fixable hook event name."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        settings.write_text(
            json.dumps(
                {
                    "hooks": {
                        "preToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [{"type": "command", "command": "echo hi"}],
                            }
                        ]
                    }
                }
            )
        )
        return settings

    def test_fix_twice_is_idempotent(self, tmp_path: Path) -> None:
        settings = self._make_fixable_settings(tmp_path)

        # First fix pass
        r1 = CliRunner().invoke(cli, ["harness-lint", str(settings), "--all", "--fix"])
        assert r1.exit_code == 0
        content_after_first = settings.read_text()
        # The fixed file must still be valid JSON.
        json.loads(content_after_first)

        # Second fix pass — idempotent, nothing left to fix
        r2 = CliRunner().invoke(cli, ["harness-lint", str(settings), "--all", "--fix"])
        assert r2.exit_code == 0
        content_after_second = settings.read_text()
        assert content_after_first == content_after_second

    def test_fixed_settings_json_is_valid(self, tmp_path: Path) -> None:
        settings = self._make_fixable_settings(tmp_path)
        CliRunner().invoke(cli, ["harness-lint", str(settings), "--all", "--fix"])
        data = json.loads(settings.read_text())
        assert "PreToolUse" in data.get("hooks", {})
        assert "preToolUse" not in data.get("hooks", {})


class TestVersionFlag:
    def test_version(self) -> None:
        result = CliRunner().invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "harness-eval" in result.output
