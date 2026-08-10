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
        result = CliRunner().invoke(cli, ["harness-lint", DIRTY, "--fail-on-error"])
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


class TestScanCommand:
    def test_scan_clean_fixture(self) -> None:
        result = CliRunner().invoke(cli, ["skill-verify", CLEAN])
        assert result.exit_code == 0
        assert "Verdict" in result.output

    def test_scan_dirty_fixture(self) -> None:
        result = CliRunner().invoke(cli, ["skill-verify", DIRTY])
        assert "UNSAFE" in result.output

    def test_scan_json_output(self) -> None:
        result = CliRunner().invoke(cli, ["skill-verify", CLEAN, "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["scan"] is True
        assert "verdict" in data


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
        assert len(data) >= 92


class TestVersionFlag:
    def test_version(self) -> None:
        result = CliRunner().invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "harness-eval" in result.output
