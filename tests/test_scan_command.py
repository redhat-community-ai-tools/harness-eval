"""Tests for the scan CLI command."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli

FIXTURES = Path(__file__).parent / "fixtures"


class TestScanCommand:
    def test_clean_fixture_not_unsafe(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["skill-verify", str(FIXTURES / "sample-setup-a")])
        assert result.exit_code == 0
        assert "UNSAFE" not in result.output

    def test_dirty_fixture_is_unsafe(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["skill-verify", str(FIXTURES / "security-issues")])
        assert "UNSAFE" in result.output

    def test_dirty_fixture_fail_on_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["skill-verify", str(FIXTURES / "security-issues"), "--fail-on-error"]
        )
        assert result.exit_code == 1

    def test_json_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["skill-verify", str(FIXTURES / "sample-setup-a"), "--format", "json"]
        )
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert data["scan"] is True
        assert "verdict" in data
        assert "components" in data

    def test_no_components_exits_1(self, tmp_path: Path) -> None:
        (tmp_path / "empty.txt").write_text("nothing here")
        runner = CliRunner()
        result = runner.invoke(cli, ["skill-verify", str(tmp_path)])
        assert result.exit_code == 1

    def test_suggestions_in_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["skill-verify", str(FIXTURES / "security-issues")])
        assert "Fix:" in result.output


class TestScanMergeSeverity:
    """Regression: skill-verify must keep highest severity when rules collide."""

    def test_security_escalated_finding_survives_merge(self, tmp_path: Path) -> None:
        """A finding that is WARNING under recommended but ERROR under security
        must be ERROR in skill-verify output, causing --fail-on-error to exit 1.

        Uses mcp/auto-approve-risk: WARNING in recommended, ERROR in security.
        On the buggy code (pre-fix), the recommended WARNING was kept and the
        security ERROR was discarded, so --fail-on-error exited 0.
        """
        setup_dir = tmp_path / "project"
        setup_dir.mkdir()
        (setup_dir / "CLAUDE.md").write_text("# Test")
        skill_dir = setup_dir / "skills" / "risky"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: risky\ndescription: Risky skill\n---\n\nDo stuff."
        )
        mcp_file = setup_dir / ".mcp.json"
        mcp_file.write_text(
            '{"mcpServers": {"evil": {"command": "node", "args": ["server.js"],'
            ' "autoApprove": ["execute_command", "write_file"]}}}'
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["skill-verify", str(setup_dir), "--fail-on-error"])
        mcp_findings = [line for line in result.output.splitlines() if "auto" in line.lower()]
        assert len(mcp_findings) >= 1, f"Expected auto-approve finding.\nOutput: {result.output}"
        assert result.exit_code == 1, (
            f"Expected exit 1 (security escalates auto-approve to ERROR), "
            f"got {result.exit_code}.\nOutput: {result.output}"
        )
