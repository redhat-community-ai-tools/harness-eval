"""Integration tests: run the full CLI and verify real behavior.

These tests catch issues that unit tests miss: exit codes, CLI flag
interactions, data file loading, tiktoken fallback, and self-dogfooding.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from harness_eval.utils import tokens

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).parent.parent


class TestCLIExitCodes:
    """CLI must return correct exit codes for CI gating."""

    def test_lint_clean_fixture_exits_0(self):
        result = subprocess.run(
            ["uv", "run", "harness-eval", "lint", str(FIXTURES / "sample-setup-a")],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

    def test_lint_fail_on_error_exits_1_on_errors(self):
        result = subprocess.run(
            [
                "uv",
                "run",
                "harness-eval",
                "lint",
                str(FIXTURES / "security-issues"),
                "--fail-on-error",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1

    def test_lint_fail_on_warning_exits_1_on_warnings(self):
        result = subprocess.run(
            [
                "uv",
                "run",
                "harness-eval",
                "lint",
                str(FIXTURES / "security-issues"),
                "--fail-on-warning",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1

    def test_lint_json_output_is_valid(self):
        import json

        result = subprocess.run(
            [
                "uv",
                "run",
                "harness-eval",
                "lint",
                str(FIXTURES / "sample-setup-a"),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "inspection" in parsed

    def test_lint_sarif_output_is_valid(self):
        import json

        result = subprocess.run(
            [
                "uv",
                "run",
                "harness-eval",
                "lint",
                str(FIXTURES / "sample-setup-a"),
                "--format",
                "sarif",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert parsed.get("version") == "2.1.0"


class TestDataFileLoading:
    """Data files must load correctly and contain expected content."""

    def test_builtins_loads(self):
        from harness_eval.data import load_builtins

        builtins = load_builtins()
        assert isinstance(builtins, set)
        assert len(builtins) >= 10
        assert "help" in builtins
        assert "config" in builtins

    def test_tautological_patterns_loads(self):
        from harness_eval.data import load_tautological_patterns

        patterns = load_tautological_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) == 24

    def test_generic_advice_subset(self):
        from harness_eval.data import load_tautological_patterns

        generic = load_tautological_patterns(generic_advice_only=True)
        assert len(generic) == 12
        labels = [label for label, _ in generic]
        assert "write clean code" in labels
        assert "be thorough" in labels

    def test_generic_is_subset_of_all(self):
        from harness_eval.data import load_tautological_patterns

        all_patterns = load_tautological_patterns()
        generic = load_tautological_patterns(generic_advice_only=True)
        all_labels = {label for label, _ in all_patterns}
        for label, _ in generic:
            assert label in all_labels

    def test_builtins_json_is_valid(self):
        import json

        path = Path(__file__).parent.parent / "src" / "harness_eval" / "data" / "builtins.json"
        data = json.loads(path.read_text())
        assert "claude_code_commands" in data
        assert isinstance(data["claude_code_commands"], list)

    def test_patterns_json_is_valid(self):
        import json

        path = (
            Path(__file__).parent.parent
            / "src"
            / "harness_eval"
            / "data"
            / "tautological_patterns.json"
        )
        data = json.loads(path.read_text())
        assert "patterns" in data
        for p in data["patterns"]:
            assert "label" in p
            assert "regex" in p


class TestTiktokenFallbackIntegration:
    """The full CLI must work when tiktoken is not available."""

    def test_lint_works_without_tiktoken(self):
        tokens._reset()
        with patch.object(
            tokens, "_init_encoder", side_effect=lambda: setattr(tokens, "_FALLBACK", True)
        ):
            tokens._init_encoder()
        result = subprocess.run(
            ["uv", "run", "harness-eval", "lint", str(FIXTURES / "sample-setup-a")],
            capture_output=True,
            text=True,
            env={**__import__("os").environ, "TIKTOKEN_CACHE_DIR": "/nonexistent"},
        )
        tokens._reset()
        assert result.returncode == 0


class TestSelfDogfood:
    """harness-eval must be able to lint its own repo without crashing."""

    def test_lint_own_repo_runs(self):
        result = subprocess.run(
            ["uv", "run", "harness-eval", "lint", str(REPO_ROOT)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Dogfood crashed:\n{result.stderr}"
        assert "Setup Assessment" in result.stdout

    def test_lint_own_repo_json_output(self):
        import json

        result = subprocess.run(
            ["uv", "run", "harness-eval", "lint", str(REPO_ROOT), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "inspection" in data
        assert data["inspection"]["summary"]["total"] > 0
