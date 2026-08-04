"""Tests for mcp/auto-approve-risk rule."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint_mcp_config

RULE_ID = "mcp/auto-approve-risk"
RULE_CONFIG = {RULE_ID: "warning"}


def _make_mcp_config(tmp_path: Path, servers: dict) -> str:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}))
    return str(path)


class TestAutoApproveRisk:
    def test_flags_write_tool(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {"github": {"command": "gh", "autoApprove": ["create_issue", "read_file"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "create_issue" in diags[0].message

    def test_flags_execute_tool(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {"ci": {"command": "ci-tool", "autoApprove": ["run_pipeline"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "run_pipeline" in diags[0].message

    def test_flags_empty_auto_approve(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {"danger": {"command": "x", "autoApprove": []}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "empty" in diags[0].message.lower() or "all tools" in diags[0].message.lower()

    def test_no_flag_read_only_tools(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {"safe": {"command": "x", "autoApprove": ["list_files", "get_status", "search"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_no_flag_no_auto_approve(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {"normal": {"command": "x"}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_multiple_risky_tools(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {"db": {"command": "x", "autoApprove": ["delete_record", "update_row", "read_row"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 2
