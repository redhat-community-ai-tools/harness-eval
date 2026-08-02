"""Tests for mcp/unpinned-package rule."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint_mcp_config

RULE_CONFIG = {"mcp/unpinned-package": "warning"}


def _make_mcp_config(tmp_path: Path, servers: dict) -> str:
    config_path = tmp_path / ".mcp.json"
    config_path.write_text(json.dumps({"mcpServers": servers}))
    return str(config_path)


class TestMcpUnpinnedPackage:
    def test_flags_npx_no_version(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path, {"my-server": {"command": "npx", "args": ["-y", "some-mcp-server"]}}
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 1
        assert "some-mcp-server" in diags[0].message

    def test_flags_npx_latest(self, tmp_path: Path) -> None:
        path = _make_mcp_config(tmp_path, {"srv": {"command": "npx", "args": ["some-pkg@latest"]}})
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 1

    def test_flags_docker_no_tag(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path, {"docker-srv": {"command": "docker", "args": ["run", "myimage"]}}
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 1

    def test_flags_docker_latest(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path, {"docker-srv": {"command": "docker", "args": ["run", "myimage:latest"]}}
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 1

    def test_flags_uvx_no_pin(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path, {"uvx-srv": {"command": "uvx", "args": ["mcp-server-fetch"]}}
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 1

    def test_skips_npx_pinned(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path, {"pinned": {"command": "npx", "args": ["-y", "some-pkg@1.2.3"]}}
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 0

    def test_skips_npx_local_spec(self, tmp_path: Path) -> None:
        path = _make_mcp_config(tmp_path, {"local": {"command": "npx", "args": ["./my-server"]}})
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 0

    def test_skips_docker_sha_digest(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {"digest": {"command": "docker", "args": ["run", "myimage@sha256:abc123def456"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 0

    def test_skips_node_command(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path, {"local-node": {"command": "node", "args": ["server.js"]}}
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 0

    def test_skips_npx_with_pinned_package_flag(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {"pkg-flag": {"command": "npx", "args": ["--package", "my-pkg@2.0.0", "my-cmd"]}},
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/unpinned-package"]
        assert len(diags) == 0
