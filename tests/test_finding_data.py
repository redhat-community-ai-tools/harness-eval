"""Structured rule evidence is kept on the finding and in machine-readable output."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli
from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup
from harness_eval.inspection.types import (
    Finding,
    InspectionResult,
    Location,
    RuleCategory,
    Severity,
)
from harness_eval.output.sarif import format_sarif


def _project(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# project\n")
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"remote": {"url": "http://evil.example/sse"}}})
    )


def _endpoint_findings(tmp_path: Path) -> list[Finding]:
    setup = discover_setup("t", str(tmp_path))
    results = inspect_setup(setup, {"mcp/endpoint-integrity": "error"})
    return [
        d
        for r in results
        for d in r.diagnostics
        if d.rule_id == "mcp/endpoint-integrity" and d.data and d.data.get("server") == "remote"
    ]


def test_inspect_setup_keeps_endpoint_data(tmp_path: Path) -> None:
    _project(tmp_path)

    findings = _endpoint_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].data == {"server": "remote", "host": "evil.example"}
    assert findings[0].reachability in {"reachable", "unreachable"}
    assert findings[0].message_id is not None
    assert findings[0].rule_effect == "block"


def test_json_and_sarif_include_endpoint_data(tmp_path: Path) -> None:
    _project(tmp_path)
    runner = CliRunner()

    gate = runner.invoke(cli, ["harness-gate", str(tmp_path), "--format", "json"])
    assert gate.exit_code == 1
    gate_rows = json.loads(gate.output)
    remote = next(
        row
        for row in gate_rows
        if row["rule"] == "mcp/endpoint-integrity" and row["data"]["server"] == "remote"
    )
    assert remote["data"]["host"] == "evil.example"
    assert remote["rule_effect"] == "block"
    assert remote["message_id"]

    security = runner.invoke(cli, ["harness-security", str(tmp_path), "--format", "json"])
    assert security.exit_code == 0
    body = json.loads(security.output)
    details = [
        item
        for comp in body["findings"]
        for item in comp["details"]
        if item["rule"] == "mcp/endpoint-integrity"
    ]
    assert any(item["data"]["host"] == "evil.example" for item in details)

    lint = runner.invoke(cli, ["harness-lint", str(tmp_path), "--all", "--format", "json"])
    assert lint.exit_code == 0
    lint_body = json.loads(lint.output)
    lint_findings = [
        item
        for group in lint_body["inspection"].values()
        if isinstance(group, list)
        for result in group
        for item in result["findings"]
        if item["rule"] == "mcp/endpoint-integrity"
    ]
    assert any(item["data"]["host"] == "evil.example" for item in lint_findings)
    assert all(item["rule_effect"] == "block" and item["message_id"] for item in lint_findings)

    sarif_run = runner.invoke(cli, ["harness-gate", str(tmp_path), "--format", "sarif"])
    assert sarif_run.exit_code == 1
    doc = json.loads(sarif_run.output)
    evidence = [
        result["properties"]["data"]
        for result in doc["runs"][0]["results"]
        if result["ruleId"] == "mcp/endpoint-integrity"
    ]
    assert {"server": "remote", "host": "evil.example"} in evidence
    assert all(
        row["properties"]["rule_effect"] == "block" and row["properties"]["message_id"]
        for row in doc["runs"][0]["results"]
        if row["ruleId"] == "mcp/endpoint-integrity"
    )


def test_signal_error_and_block_info_keep_separate_axes(tmp_path: Path) -> None:
    from harness_eval.inspection.engine import lint, lint_claude_md

    instruction = tmp_path / "CLAUDE.md"
    instruction.write_text("Run\u200btests", encoding="utf-8")
    signal = lint_claude_md(str(instruction), source_tool="claude")
    match = next(d for d in signal.diagnostics if d.rule_id == "security/mcp-tool-poisoning")
    assert match.severity == Severity.ERROR
    assert match.rule_effect == "signal"
    assert match.source_tool == "claude"
    assert match.message_id == "mcp_unicode_deception"

    skill = tmp_path / "helper"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\ndescription: example\n---\nRun tests.\n")
    result = lint(str(skill), {"frontmatter/format-valid": "warning"}, source_tool="claude")
    info = next(d for d in result.diagnostics if d.message_id == "missing_name")
    assert info.severity == Severity.INFO
    assert info.rule_effect == "block"


def test_single_file_json_keeps_location_and_message_id(tmp_path: Path) -> None:
    instruction = tmp_path / "CLAUDE.md"
    instruction.write_text("# Project\nRun\u200btests", encoding="utf-8")
    result = CliRunner().invoke(
        cli, ["harness-lint", str(instruction), "--all", "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    row = next(
        d
        for r in json.loads(result.output)["results"]
        for d in r["findings"]
        if d["rule"] == "security/mcp-tool-poisoning"
    )
    assert row["message_id"] == "mcp_unicode_deception"
    assert row["rule_effect"] == "signal"
    assert row["line"] == 2
    assert Path(row["file"]) == instruction


def test_sarif_omits_data_when_a_finding_has_none() -> None:
    finding = Finding(
        rule_id="test/rule",
        severity=Severity.WARNING,
        message="plain",
        location=Location(file="CLAUDE.md", start_line=1),
        category=RuleCategory.CONTENT,
    )
    result = InspectionResult(
        target_path="t",
        target_name="t",
        tokens=0,
        diagnostics=[finding],
        error_count=0,
        warning_count=1,
    )

    sarif = format_sarif([result])

    assert "data" not in sarif["runs"][0]["results"][0].get("properties", {})


def test_parser_findings_have_explicit_identity(tmp_path: Path) -> None:
    from harness_eval.inspection.engine import lint

    path = tmp_path / "SKILL.md"
    path.write_text("---\nname: [invalid\n---\nBody\n")
    result = lint(str(tmp_path))
    finding = next(d for d in result.diagnostics if d.rule_id == "parser")
    assert finding.message_id == "parse_error"
    assert finding.rule_effect == "block"
    assert finding.source_tool is None  # Direct-file invocation has no known client.
