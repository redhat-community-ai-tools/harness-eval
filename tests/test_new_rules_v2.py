"""Tests for new lint rules: mcp/valid-config, hooks/script-boundary, agent/model-specified."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint_agent, lint_hooks, lint_mcp_config


class TestMcpValidConfig:
    def test_valid_config_no_findings(self, tmp_path: Path) -> None:
        mcp = tmp_path / ".mcp.json"
        mcp.write_text(
            json.dumps({"mcpServers": {"my-server": {"command": "node", "args": ["server.js"]}}})
        )
        result = lint_mcp_config(str(mcp), {"mcp/valid-config": "warning"})
        assert not any(d.rule_id == "mcp/valid-config" for d in result.diagnostics)

    def test_invalid_json(self, tmp_path: Path) -> None:
        mcp = tmp_path / ".mcp.json"
        mcp.write_text("{bad json")
        result = lint_mcp_config(str(mcp), {"mcp/valid-config": "warning"})
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/valid-config"]
        assert len(diags) == 1
        assert "not valid JSON" in diags[0].message

    def test_missing_mcp_servers_key(self, tmp_path: Path) -> None:
        mcp = tmp_path / ".mcp.json"
        mcp.write_text(json.dumps({"other": "stuff"}))
        result = lint_mcp_config(str(mcp), {"mcp/valid-config": "warning"})
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/valid-config"]
        assert len(diags) == 1
        assert "mcpServers" in diags[0].message

    def test_server_missing_transport(self, tmp_path: Path) -> None:
        mcp = tmp_path / ".mcp.json"
        mcp.write_text(json.dumps({"mcpServers": {"broken": {"args": ["--verbose"]}}}))
        result = lint_mcp_config(str(mcp), {"mcp/valid-config": "warning"})
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/valid-config"]
        assert len(diags) == 1
        assert "broken" in diags[0].message

    def test_server_with_url_passes(self, tmp_path: Path) -> None:
        mcp = tmp_path / ".mcp.json"
        mcp.write_text(
            json.dumps({"mcpServers": {"remote": {"url": "https://api.example.com/mcp"}}})
        )
        result = lint_mcp_config(str(mcp), {"mcp/valid-config": "warning"})
        assert not any(d.rule_id == "mcp/valid-config" for d in result.diagnostics)

    def test_args_not_array(self, tmp_path: Path) -> None:
        mcp = tmp_path / ".mcp.json"
        mcp.write_text(
            json.dumps({"mcpServers": {"srv": {"command": "node", "args": "--verbose"}}})
        )
        result = lint_mcp_config(str(mcp), {"mcp/valid-config": "warning"})
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/valid-config"]
        assert len(diags) == 1
        assert "args" in diags[0].message

    def test_env_not_object(self, tmp_path: Path) -> None:
        mcp = tmp_path / ".mcp.json"
        mcp.write_text(json.dumps({"mcpServers": {"srv": {"command": "node", "env": "DEBUG=1"}}}))
        result = lint_mcp_config(str(mcp), {"mcp/valid-config": "warning"})
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/valid-config"]
        assert len(diags) == 1
        assert "env" in diags[0].message

    def test_root_not_object(self, tmp_path: Path) -> None:
        mcp = tmp_path / ".mcp.json"
        mcp.write_text(json.dumps([1, 2, 3]))
        result = lint_mcp_config(str(mcp), {"mcp/valid-config": "warning"})
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/valid-config"]
        assert len(diags) == 1
        assert "object" in diags[0].message


class TestHooksScriptBoundary:
    def test_script_within_project_passes(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        script = tmp_path / "scripts" / "check.sh"
        script.parent.mkdir(parents=True)
        script.write_text("#!/bin/bash\necho ok")
        settings.write_text(
            json.dumps({"hooks": {"PreToolUse": [{"command": "scripts/check.sh"}]}})
        )
        result = lint_hooks(str(settings), {"hooks/script-boundary": "error"})
        boundary_diags = [d for d in result.diagnostics if d.rule_id == "hooks/script-boundary"]
        assert len(boundary_diags) == 0

    def test_path_traversal_detected(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        settings.write_text(
            json.dumps({"hooks": {"PreToolUse": [{"command": "../../etc/evil.sh"}]}})
        )
        result = lint_hooks(str(settings), {"hooks/script-boundary": "error"})
        boundary_diags = [d for d in result.diagnostics if d.rule_id == "hooks/script-boundary"]
        assert len(boundary_diags) == 1
        assert "outside" in boundary_diags[0].message.lower()

    def test_absolute_path_detected(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        settings.write_text(
            json.dumps({"hooks": {"PreToolUse": [{"command": "/usr/bin/evil.sh"}]}})
        )
        result = lint_hooks(str(settings), {"hooks/script-boundary": "error"})
        boundary_diags = [d for d in result.diagnostics if d.rule_id == "hooks/script-boundary"]
        assert len(boundary_diags) == 1

    def test_hook_without_script_passes(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"command": "echo hello"}]}}))
        result = lint_hooks(str(settings), {"hooks/script-boundary": "error"})
        boundary_diags = [d for d in result.diagnostics if d.rule_id == "hooks/script-boundary"]
        assert len(boundary_diags) == 0


class TestAgentModelSpecified:
    def test_agent_with_model_passes(self, tmp_path: Path) -> None:
        agent_file = tmp_path / "helper.md"
        agent_file.write_text("---\ndescription: Helper\nmodel: inherit\n---\n\n# Helper\n")
        result = lint_agent(str(agent_file), {"agent/model-specified": "info"})
        model_diags = [d for d in result.diagnostics if d.rule_id == "agent/model-specified"]
        assert len(model_diags) == 0

    def test_agent_without_model_inherits(self, tmp_path: Path) -> None:
        agent_file = tmp_path / "helper.md"
        agent_file.write_text("---\ndescription: Helper\n---\n\n# Helper\n")
        result = lint_agent(str(agent_file), {"agent/model-specified": "info"})
        model_diags = [d for d in result.diagnostics if d.rule_id == "agent/model-specified"]
        assert len(model_diags) == 0

    def test_agent_with_specific_model_passes(self, tmp_path: Path) -> None:
        agent_file = tmp_path / "helper.md"
        agent_file.write_text("---\ndescription: Helper\nmodel: sonnet\n---\n\n# Helper\n")
        result = lint_agent(str(agent_file), {"agent/model-specified": "info"})
        model_diags = [d for d in result.diagnostics if d.rule_id == "agent/model-specified"]
        assert len(model_diags) == 0
