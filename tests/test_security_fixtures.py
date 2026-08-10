"""Tests using the security-issues fixture to verify security rules fire correctly."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup, lint, lint_command

FIXTURES = Path(__file__).parent / "fixtures"
SECURITY_SETUP = FIXTURES / "security-issues"


class TestSecurityFixture:
    """Integration tests: run the full engine against a setup with known security issues."""

    def test_injection_skill_fires_injection_rule(self) -> None:
        result = lint(str(SECURITY_SETUP / "skills/injection-skill"))
        rule_ids = {d.rule_id for d in result.diagnostics}
        assert "security/no-prompt-injection" in rule_ids

    def test_injection_skill_catches_multiple_patterns(self) -> None:
        result = lint(str(SECURITY_SETUP / "skills/injection-skill"))
        injection_findings = [
            d for d in result.diagnostics if d.rule_id == "security/no-prompt-injection"
        ]
        assert len(injection_findings) >= 2, (
            f"Expected at least 2 injection findings, got {len(injection_findings)}"
        )

    def test_creds_skill_fires_credential_rule(self) -> None:
        result = lint(str(SECURITY_SETUP / "skills/creds-skill"))
        rule_ids = {d.rule_id for d in result.diagnostics}
        assert "security/no-credential-access" in rule_ids

    def test_creds_skill_catches_path_and_env_var(self) -> None:
        result = lint(str(SECURITY_SETUP / "skills/creds-skill"))
        cred_findings = [
            d for d in result.diagnostics if d.rule_id == "security/no-credential-access"
        ]
        assert len(cred_findings) >= 2, (
            f"Expected at least 2 credential findings, got {len(cred_findings)}"
        )

    def test_exfil_skill_fires_exfiltration_rule(self) -> None:
        result = lint(str(SECURITY_SETUP / "skills/exfil-skill"))
        rule_ids = {d.rule_id for d in result.diagnostics}
        assert "security/data-exfiltration" in rule_ids

    def test_deploy_command_fires_reverse_shell_rule(self) -> None:
        result = lint_command(str(SECURITY_SETUP / "commands/deploy"))
        rule_ids = {d.rule_id for d in result.diagnostics}
        assert "command/reverse-shell" in rule_ids

    def test_full_setup_security_findings_count(self) -> None:
        setup = discover_setup(name="security-issues", path=str(SECURITY_SETUP))
        results = inspect_setup(setup)
        security_findings = [
            d for r in results for d in r.diagnostics if d.rule_id.startswith("security/")
        ]
        assert len(security_findings) >= 5, (
            f"Expected at least 5 security findings across the setup, got {len(security_findings)}"
        )


class TestSecurityFixtureE2E:
    """E2E: run the CLI command against the fixture and check output."""

    def test_cli_lint_reports_security_issues(self) -> None:
        from click.testing import CliRunner

        from harness_eval.cli import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "harness-lint",
                str(SECURITY_SETUP),
                "--preset",
                "security",
            ],
        )
        assert result.exit_code == 0
        assert "no-credential-access" in result.output or "no-prompt-injection" in result.output

    def test_cli_lint_fail_on_error_exits_nonzero(self) -> None:
        from click.testing import CliRunner

        from harness_eval.cli import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "harness-lint",
                str(SECURITY_SETUP),
                "--preset",
                "security",
                "--fail-on-error",
            ],
        )
        assert result.exit_code == 1

    def test_cli_lint_json_output_parseable(self) -> None:
        import json

        from click.testing import CliRunner

        from harness_eval.cli import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "harness-lint",
                str(SECURITY_SETUP),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "inspection" in data
        assert "summary" in data["inspection"]
        all_components = []
        for key, val in data["inspection"].items():
            if key == "summary":
                continue
            all_components.extend(val)
        security_rules = [
            f
            for comp in all_components
            for f in comp["findings"]
            if f["rule"].startswith("security/")
        ]
        assert len(security_rules) >= 5


class TestMockLLMReview:
    """Test review with mocked LLM responses (no real API calls)."""

    def test_rubric_checker_parses_multi_issue_response(self) -> None:
        from harness_eval.rubric.scorer import RubricChecker
        from harness_eval.utils.llm import LLMClient

        class MockClient(LLMClient):
            def generate(self, system: str, prompt: str) -> str:
                return (
                    "ISSUE: Vague instructions | CATEGORY: specificity "
                    "| EVIDENCE: 'do the thing' | SUGGESTION: Be specific\n"
                    "ISSUE: Duplicates default | CATEGORY: redundancy "
                    "| EVIDENCE: 'write clean code' | SUGGESTION: Remove\n"
                    "ISSUE: Missing activation | CATEGORY: trigger_quality "
                    "| EVIDENCE: no 'use when' | SUGGESTION: Add trigger\n"
                    "SUMMARY: Skill needs significant improvement."
                )

        checker = RubricChecker(MockClient())
        result = checker.check(
            component_type="skill",
            component_name="test-skill",
            content="---\nname: test\n---\ndo the thing, write clean code",
        )
        assert len(result.issues) == 3
        assert result.summary == "Skill needs significant improvement."
        categories = {i.category for i in result.issues}
        assert categories == {"specificity", "redundancy", "trigger_quality"}

    def test_rubric_checker_handles_clean_response(self) -> None:
        from harness_eval.rubric.scorer import RubricChecker
        from harness_eval.utils.llm import LLMClient

        class MockClient(LLMClient):
            def generate(self, system: str, prompt: str) -> str:
                return "SUMMARY: Component is well-structured with no issues."

        checker = RubricChecker(MockClient())
        result = checker.check(
            component_type="skill",
            component_name="clean-skill",
            content="---\nname: clean\n---\nGood content here.",
        )
        assert len(result.issues) == 0
        assert "well-structured" in result.summary

    def test_rubric_checker_handles_malformed_response(self) -> None:
        from harness_eval.rubric.scorer import RubricChecker
        from harness_eval.utils.llm import LLMClient

        class MockClient(LLMClient):
            def generate(self, system: str, prompt: str) -> str:
                return "This response doesn't follow the format at all.\nRandom text."

        checker = RubricChecker(MockClient())
        result = checker.check(
            component_type="skill",
            component_name="test-skill",
            content="anything",
        )
        assert len(result.issues) == 0
        assert result.summary == ""
