"""Tests for the scan CLI command."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli

FIXTURES = Path(__file__).parent / "fixtures"


class TestScanCommand:
    def test_clean_fixture_not_unsafe(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(FIXTURES / "sample-setup-a")])
        assert result.exit_code == 0
        assert "UNSAFE" not in result.output

    def test_dirty_fixture_is_unsafe(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(FIXTURES / "security-issues")])
        assert "UNSAFE" in result.output

    def test_dirty_fixture_fail_on_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(FIXTURES / "security-issues"), "--fail-on-error"])
        assert result.exit_code == 1

    def test_json_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(FIXTURES / "sample-setup-a"), "--format", "json"])
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert data["scan"] is True
        assert "verdict" in data
        assert "components" in data

    def test_no_components_exits_1(self, tmp_path: Path) -> None:
        (tmp_path / "empty.txt").write_text("nothing here")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == 1

    def test_suggestions_in_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(FIXTURES / "security-issues")])
        assert "Fix:" in result.output
