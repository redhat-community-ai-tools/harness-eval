"""Test harness-eval doctor command."""

from __future__ import annotations

from click.testing import CliRunner

from harness_eval.cli import cli


class TestDoctor:
    def test_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["doctor"])
        assert result.exit_code == 0

    def test_shows_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["doctor"])
        assert "harness-eval" in result.output
        assert "Python" in result.output

    def test_lists_all_capabilities(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["doctor"])
        for name in [
            "Anthropic LLM provider",
            "Gemini LLM provider",
            "YARA malware signatures",
            "File watching",
            "Bash AST taint analysis",
            "Accurate token counting",
        ]:
            assert name in result.output, f"Missing capability: {name}"

    def test_lists_env_vars(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["doctor"])
        for var in ["GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY"]:
            assert var in result.output, f"Missing env var: {var}"

    def test_shows_set_status_when_var_present(self) -> None:
        runner = CliRunner(env={"GEMINI_API_KEY": "test-key"})
        result = runner.invoke(cli, ["doctor"])
        gemini_line = next(line for line in result.output.splitlines() if "GEMINI_API_KEY" in line)
        assert "unset" not in gemini_line
        assert gemini_line.rstrip().endswith("set")
        assert "test-key" not in result.output

    def test_shows_unset_status_when_var_absent(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["doctor"], env={"GEMINI_API_KEY": None, "GOOGLE_API_KEY": None}
        )
        gemini_line = next(line for line in result.output.splitlines() if "GEMINI_API_KEY" in line)
        assert "unset" in gemini_line
