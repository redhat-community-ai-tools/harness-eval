"""Tests for mcp/unpinned-package rule: Docker flag-value edge cases."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint_mcp_config

RULE_ID = "mcp/unpinned-package"
RULE_CONFIG = {RULE_ID: "warning"}


def _make_mcp_config(tmp_path: Path, servers: dict) -> str:
    config_path = tmp_path / ".mcp.json"
    config_path.write_text(json.dumps({"mcpServers": servers}))
    return str(config_path)


class TestDockerFlagValueHandling:
    def test_flags_after_port_flag(self, tmp_path: Path) -> None:
        """Image after -p 8080:8080 should be checked, not the port value."""
        path = _make_mcp_config(
            tmp_path,
            {"s": {"command": "docker", "args": ["run", "-p", "8080:8080", "myimage"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "myimage" in diags[0].message

    def test_flags_after_env_flag(self, tmp_path: Path) -> None:
        """Image after -e KEY=VALUE should be checked."""
        path = _make_mcp_config(
            tmp_path,
            {"s": {"command": "docker", "args": ["run", "-e", "FOO=bar", "myimage"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "myimage" in diags[0].message

    def test_flags_after_long_flag_with_equals(self, tmp_path: Path) -> None:
        """--name=mycontainer should not be confused with image."""
        path = _make_mcp_config(
            tmp_path,
            {"s": {"command": "docker", "args": ["run", "--name=mycontainer", "myimage"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "myimage" in diags[0].message

    def test_pinned_image_after_flags(self, tmp_path: Path) -> None:
        """Pinned image after flags should not flag."""
        path = _make_mcp_config(
            tmp_path,
            {
                "s": {
                    "command": "docker",
                    "args": ["run", "-p", "8080:8080", "--rm", "myimage:v1.2.3"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0
