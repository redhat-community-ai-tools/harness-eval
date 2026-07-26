"""Tests for issue #30 'also needed' items: Copilot instructions and
Gemini/OpenCode MCP config discovery."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType
from harness_eval.inspection.engine import inspect_setup


def _diag_ids(setup, config):
    results = inspect_setup(setup, config)
    return [(d.rule_id, d.message) for r in results for d in r.diagnostics]


class TestCopilotInstructions:
    def test_discovered_as_claude_md(self, tmp_path: Path) -> None:
        gh = tmp_path / ".github"
        gh.mkdir()
        (gh / "copilot-instructions.md").write_text(
            "# Copilot instructions\n\nUse PEP 8. Prefer small functions.\n", encoding="utf-8"
        )
        setup = discover_setup("copilot", str(tmp_path))
        claude_md = setup.by_type(ComponentType.CLAUDE_MD)
        names = {c.name for c in claude_md}
        assert "copilot-instructions" in names
        comp = next(c for c in claude_md if c.name == "copilot-instructions")
        assert comp.source_tool == "copilot"
        assert "Copilot" in setup.detected_tools

    def test_no_claude_only_rules_fire(self, tmp_path: Path) -> None:
        gh = tmp_path / ".github"
        gh.mkdir()
        (gh / "copilot-instructions.md").write_text("# Instructions\n\nBe concise.\n", "utf-8")
        setup = discover_setup("copilot", str(tmp_path))
        ids = [rid for rid, _ in _diag_ids(setup, {"claude-md/exists": "warning"})]
        assert "claude-md/exists" not in ids


class TestGeminiMcp:
    def _write(self, tmp_path: Path, obj: dict) -> None:
        gd = tmp_path / ".gemini"
        gd.mkdir()
        (gd / "settings.json").write_text(json.dumps(obj), encoding="utf-8")

    def test_settings_with_mcpservers_discovered(self, tmp_path: Path) -> None:
        self._write(
            tmp_path,
            {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "server-fs"]}}},
        )
        setup = discover_setup("gemini", str(tmp_path))
        mcp = setup.by_type(ComponentType.MCP_CONFIG)
        assert len(mcp) == 1
        assert mcp[0].source_tool == "gemini"
        # valid-config must NOT report missing servers for a real MCP config
        msgs = [m for rid, m in _diag_ids(setup, {"mcp/valid-config": "warning"})]
        assert not any("no 'mcpServers'" in m for m in msgs)

    def test_settings_without_mcpservers_not_discovered(self, tmp_path: Path) -> None:
        self._write(tmp_path, {"theme": "dark", "vimMode": True})
        setup = discover_setup("gemini", str(tmp_path))
        assert setup.by_type(ComponentType.MCP_CONFIG) == []

    def test_global_settings_via_user_config(self, tmp_path: Path) -> None:
        home = tmp_path / "home-gemini"
        home.mkdir()
        (home / "settings.json").write_text(
            json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "srv"]}}}),
            encoding="utf-8",
        )
        proj = tmp_path / "proj"
        proj.mkdir()
        setup = discover_setup("gemini", str(proj), user_config_dir=str(home))
        mcp = setup.by_type(ComponentType.MCP_CONFIG)
        assert len(mcp) == 1
        assert mcp[0].source_tool == "gemini"
        assert mcp[0].name == "~/.gemini/settings.json"


class TestOpenCodeMcp:
    def _write(self, tmp_path: Path, obj: dict) -> None:
        (tmp_path / "opencode.json").write_text(json.dumps(obj), encoding="utf-8")

    def test_opencode_mcp_key_discovered(self, tmp_path: Path) -> None:
        self._write(
            tmp_path,
            {
                "$schema": "https://opencode.ai/config.json",
                "mcp": {
                    "local-fs": {
                        "type": "local",
                        "command": ["bun", "x", "mcp-fs"],
                        "enabled": True,
                    }
                },
            },
        )
        setup = discover_setup("opencode", str(tmp_path))
        mcp = setup.by_type(ComponentType.MCP_CONFIG)
        assert len(mcp) == 1
        assert mcp[0].source_tool == "opencode"
        # The MCP rules must understand the 'mcp' key: no false missing-servers,
        # and a list-form command must not trigger the no-transport error.
        msgs = [m for rid, m in _diag_ids(setup, {"mcp/valid-config": "warning"})]
        assert not any("no 'mcpServers'" in m for m in msgs)
        assert not any("no 'command'" in m for m in msgs)

    def test_opencode_remote_server_url_seen(self, tmp_path: Path) -> None:
        self._write(
            tmp_path,
            {
                "mcp": {
                    "remote": {"type": "remote", "url": "http://127.0.0.1:8080", "enabled": True}
                }
            },
        )
        setup = discover_setup("opencode", str(tmp_path))
        # suspicious-endpoint reads url via the shared extractor -> should flag localhost
        ids = [rid for rid, _ in _diag_ids(setup, {"mcp/suspicious-endpoint": "warning"})]
        assert "mcp/suspicious-endpoint" in ids

    def test_opencode_without_mcp_key_not_discovered(self, tmp_path: Path) -> None:
        self._write(tmp_path, {"theme": "opencode", "model": "anthropic/claude"})
        setup = discover_setup("opencode", str(tmp_path))
        assert setup.by_type(ComponentType.MCP_CONFIG) == []
