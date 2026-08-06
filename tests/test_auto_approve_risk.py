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

    def test_no_flag_substring_match(self, tmp_path: Path) -> None:
        """Tool names containing write keywords as substrings should still flag."""
        # "executor" contains "exec", so _is_high_risk_tool flags it via substring matching.
        # This documents the current behavior.
        path = _make_mcp_config(
            tmp_path,
            {"ci": {"command": "x", "autoApprove": ["executor"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "executor" in diags[0].message

    def test_auto_approve_bool_ignored(self, tmp_path: Path) -> None:
        """autoApprove: true (non-list) should not crash."""
        path = _make_mcp_config(
            tmp_path,
            {"s": {"command": "x", "autoApprove": True}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        # Non-list autoApprove is silently ignored by the rule
        assert len(diags) == 0

    def test_multiple_servers(self, tmp_path: Path) -> None:
        """Multiple servers each with autoApprove should each be checked."""
        path = _make_mcp_config(
            tmp_path,
            {
                "server_a": {"command": "x", "autoApprove": ["delete_item"]},
                "server_b": {"command": "y", "autoApprove": ["create_record"]},
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 2
        servers_flagged = {d.message.split("'")[1] for d in diags}
        assert "server_a" in servers_flagged
        assert "server_b" in servers_flagged
