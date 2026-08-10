"""Tests for report card and certification tiers."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli
from harness_eval.inspection.types import (
    Finding,
    InspectionResult,
    Location,
    RuleCategory,
    Severity,
)
from harness_eval.output.report import _compute_certification, format_report_card


def _make_result(
    name: str = "test",
    diagnostics: list[Finding] | None = None,
) -> InspectionResult:
    diags = diagnostics or []
    return InspectionResult(
        target_path=f"/tmp/{name}",
        target_name=name,
        tokens=100,
        target_type="skill",
        diagnostics=diags,
        rules_run=[],
        error_count=sum(1 for d in diags if d.severity == Severity.ERROR),
        warning_count=sum(1 for d in diags if d.severity == Severity.WARNING),
        info_count=0,
        fixable_count=0,
        suppression_count=0,
    )


def _diag(rule_id: str, severity: Severity = Severity.ERROR) -> Finding:
    category = RuleCategory.CONTENT
    if rule_id.startswith("security/"):
        category = RuleCategory.SECURITY
    elif rule_id.startswith("structural/"):
        category = RuleCategory.STRUCTURAL
    elif rule_id.startswith("quality/"):
        category = RuleCategory.BEST_PRACTICES
    return Finding(
        rule_id=rule_id,
        message=f"Test finding for {rule_id}",
        severity=severity,
        location=Location(file="test.md", start_line=1),
        category=category,
    )


class TestComputeCertification:
    def test_hardened(self) -> None:
        result = _compute_certification([_make_result()])
        assert result["tier"] == "HARDENED"
        assert result["basic"]["passed"]
        assert result["verified"]["passed"]
        assert result["hardened"]["passed"]

    def test_basic_with_lint_errors(self) -> None:
        results = [_make_result(diagnostics=[_diag("structural/skill-md-exists")])]
        result = _compute_certification(results)
        assert result["tier"] == "NONE"
        assert not result["basic"]["passed"]

    def test_verified_with_quality_warnings(self) -> None:
        results = [
            _make_result(diagnostics=[_diag("quality/imprecise-instruction", Severity.WARNING)])
        ]
        result = _compute_certification(results)
        assert result["tier"] == "BASIC"
        assert result["basic"]["passed"]
        assert not result["verified"]["passed"]

    def test_basic_with_security_errors(self) -> None:
        results = [_make_result(diagnostics=[_diag("security/no-credential-access")])]
        result = _compute_certification(results)
        assert result["tier"] == "NONE"
        assert not result["basic"]["passed"]

    def test_verified_blocked_by_security_errors(self) -> None:
        results = [
            _make_result(diagnostics=[_diag("security/no-credential-access", Severity.ERROR)])
        ]
        result = _compute_certification(results)
        assert result["tier"] == "NONE"
        assert not result["hardened"]["passed"]


class TestFormatReportCard:
    def test_clean_verdict(self) -> None:
        card = format_report_card([_make_result()])
        assert card["verdict"] == "CLEAN"
        assert card["summary"]["total_errors"] == 0
        assert card["certification"]["tier"] == "HARDENED"

    def test_blocked_verdict(self) -> None:
        results = [_make_result(diagnostics=[_diag("structural/skill-md-exists")])]
        card = format_report_card(results)
        assert card["verdict"] == "BLOCKED"

    def test_needs_work_verdict(self) -> None:
        results = [
            _make_result(diagnostics=[_diag("quality/imprecise-instruction", Severity.WARNING)])
        ]
        card = format_report_card(results)
        assert card["verdict"] == "NEEDS_WORK"

    def test_has_components(self) -> None:
        card = format_report_card([_make_result(name="my-skill")])
        assert len(card["components"]) == 1
        assert card["components"][0]["name"] == "my-skill"


class TestReportCardCLI:
    def test_report_card_writes_json(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("CLAUDE.md").write_text("# Test")
            skill_dir = Path("skills/clean-skill")
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "---\nname: clean-skill\ndescription: A clean skill\n---\n\nDo the thing."
            )
            card_path = str(tmp_path / "card.json")
            result = runner.invoke(cli, ["harness-lint", ".", "--report-card", card_path])
            assert result.exit_code == 0
            card = json.loads(Path(card_path).read_text())
            assert "verdict" in card
            assert "certification" in card
            assert "tier" in card["certification"]
