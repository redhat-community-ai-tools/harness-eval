"""Tests for --enforce flag on lint and security commands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli


def _setup_with_finding(cwd: Path) -> None:
    """Create a setup that will produce a lint warning (orphan skill)."""
    (cwd / "CLAUDE.md").write_text("# Test project")
    for name in ("alpha", "beta"):
        skill_dir = cwd / "skills" / name
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Skill {name}\n---\n\nDo stuff."
        )


def _setup_clean(cwd: Path) -> None:
    """Create a setup that will produce no findings."""
    (cwd / "CLAUDE.md").write_text(
        "# Test project\n\nUse /alpha for feature A. Use /beta for feature B."
    )
    for name in ("alpha", "beta"):
        skill_dir = cwd / "skills" / name
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Skill {name}\n---\n\nAlways do stuff directly."
        )


class TestEnforceLint:
    def test_enforce_strict_exits_1_on_findings(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _setup_with_finding(Path("."))
            result = runner.invoke(cli, ["harness-lint", ".", "--enforce", "strict"])
            assert result.exit_code == 1

    def test_enforce_advisory_exits_0(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _setup_with_finding(Path("."))
            result = runner.invoke(cli, ["harness-lint", ".", "--enforce", "advisory"])
            assert result.exit_code == 0

    def test_enforce_off_exits_0(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _setup_with_finding(Path("."))
            result = runner.invoke(cli, ["harness-lint", ".", "--enforce", "off"])
            assert result.exit_code == 0

    def test_enforce_strict_exits_0_when_clean(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("CLAUDE.md").write_text("# Clean project\n\nFollow these rules.")
            result = runner.invoke(cli, ["harness-lint", ".", "--enforce", "strict"])
            assert result.exit_code == 0

    def test_enforce_mutual_exclusion_with_fail_on_error(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _setup_clean(Path("."))
            result = runner.invoke(
                cli, ["harness-lint", ".", "--enforce", "strict", "--fail-on-error"]
            )
            assert result.exit_code != 0
            assert "mutually exclusive" in result.output.lower() or result.exception


class TestEnforceSecurity:
    def test_enforce_advisory_exits_0(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _setup_with_finding(Path("."))
            result = runner.invoke(cli, ["harness-security", ".", "--enforce", "advisory"])
            assert result.exit_code == 0

    def test_enforce_off_exits_0(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _setup_with_finding(Path("."))
            result = runner.invoke(cli, ["harness-security", ".", "--enforce", "off"])
            assert result.exit_code == 0
