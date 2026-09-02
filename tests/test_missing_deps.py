"""Test that missing LLM dependencies produce a clean error, not a traceback."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from harness_eval.cli import cli

FIXTURES = Path(__file__).parent / "fixtures" / "sample-setup-a"

_ERR_MSG = (
    'LLM dependencies not installed. Install with: pip install "harness-eval[llm]"'
    "  (or: uv sync --extra llm)"
)


def _make_failing_client(*_args, **_kwargs):
    client = MagicMock()
    client._ensure_client.side_effect = ImportError(_ERR_MSG)
    return client


class TestMissingLLMDeps:
    def test_review_gives_clean_error(self) -> None:
        runner = CliRunner()
        with patch("harness_eval.utils.llm.create_client", side_effect=_make_failing_client):
            result = runner.invoke(cli, ["harness-review", str(FIXTURES)])
        assert result.exit_code != 0
        assert "LLM dependencies not installed" in result.output
        assert "Traceback" not in result.output

    def test_security_review_gives_clean_error(self) -> None:
        runner = CliRunner()
        with patch("harness_eval.utils.llm.create_client", side_effect=_make_failing_client):
            result = runner.invoke(cli, ["harness-security", str(FIXTURES), "--review"])
        assert result.exit_code != 0
        assert "LLM dependencies not installed" in result.output
        assert "Traceback" not in result.output

    def test_skill_rubric_gives_clean_error(self) -> None:
        skill_path = FIXTURES / "skills" / "code-review"
        runner = CliRunner()
        with patch("harness_eval.utils.llm.create_client", side_effect=_make_failing_client):
            result = runner.invoke(cli, ["skill-review", str(skill_path), "--rubric"])
        assert result.exit_code != 0
        assert "LLM dependencies not installed" in result.output
        assert "Traceback" not in result.output
