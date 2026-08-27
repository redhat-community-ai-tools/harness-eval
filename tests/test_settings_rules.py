"""Tests for the four rules added in v8: permission contradiction, prompt
disabled, local settings committed, and MCP cross-assistant divergence."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint_hooks, lint_mcp_config
from harness_eval.inspection.rules.hooks.permission_contradiction import deny_covers_allow


def _settings(tmp_path: Path, data: dict, name: str = "settings.json") -> Path:
    d = tmp_path / ".claude"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_text(json.dumps(data))
    return p


def _hooks_diags(p: Path, rule: str) -> list:
    r = lint_hooks(str(p), {rule: "warning"})
    return [d for d in r.diagnostics if d.rule_id == rule]


class TestPermissionContradiction:
    RULE = "hooks/permission-contradiction"

    def test_covers(self) -> None:
        assert deny_covers_allow("Bash(rm:*)", "Bash(rm:*)")
        assert deny_covers_allow("Bash", "Bash(git:*)")
        assert deny_covers_allow("Bash(*)", "Bash(git:*)")
        assert deny_covers_allow("Bash(git:*)", "Bash(git commit:*)")
        assert not deny_covers_allow("Bash(git commit:*)", "Bash(git:*)")
        assert not deny_covers_allow("Bash(rm:*)", "Bash(git:*)")
        assert not deny_covers_allow("Edit", "Bash(git:*)")

    def test_flags_exact_overlap(self, tmp_path: Path) -> None:
        p = _settings(tmp_path, {"permissions": {"allow": ["Bash(rm:*)"], "deny": ["Bash(rm:*)"]}})
        d = _hooks_diags(p, self.RULE)
        assert len(d) == 1 and "Bash(rm:*)" in d[0].message

    def test_flags_broader_deny(self, tmp_path: Path) -> None:
        p = _settings(
            tmp_path, {"permissions": {"allow": ["Bash(git commit:*)"], "deny": ["Bash(git:*)"]}}
        )
        assert len(_hooks_diags(p, self.RULE)) == 1

    def test_silent_when_disjoint(self, tmp_path: Path) -> None:
        p = _settings(tmp_path, {"permissions": {"allow": ["Bash(git:*)"], "deny": ["Bash(rm:*)"]}})
        assert _hooks_diags(p, self.RULE) == []


class TestPermissionPromptDisabled:
    RULE = "hooks/permission-prompt-disabled"

    def test_flags_bypass(self, tmp_path: Path) -> None:
        p = _settings(tmp_path, {"permissions": {"defaultMode": "bypassPermissions"}})
        d = _hooks_diags(p, self.RULE)
        assert len(d) == 1 and "bypassPermissions" in d[0].message

    def test_flags_all_mcp(self, tmp_path: Path) -> None:
        p = _settings(tmp_path, {"enableAllProjectMcpServers": True})
        assert len(_hooks_diags(p, self.RULE)) == 1

    def test_silent_default(self, tmp_path: Path) -> None:
        p = _settings(
            tmp_path,
            {"permissions": {"defaultMode": "default"}, "enableAllProjectMcpServers": False},
        )
        assert _hooks_diags(p, self.RULE) == []


class TestLocalSettingsCommitted:
    RULE = "hooks/local-settings-committed"

    def test_flags_when_present(self, tmp_path: Path) -> None:
        p = _settings(tmp_path, {})
        _settings(
            tmp_path,
            {"permissions": {"allow": ["Bash(git:*)", "Read"]}},
            name="settings.local.json",
        )
        d = _hooks_diags(p, self.RULE)
        assert len(d) == 1 and "2 permissions.allow" in d[0].message

    def test_silent_when_absent(self, tmp_path: Path) -> None:
        assert _hooks_diags(_settings(tmp_path, {}), self.RULE) == []


class TestMcpCrossAssistantDivergence:
    RULE = "mcp/cross-assistant-divergence"

    def _project(self, tmp_path: Path, claude: dict, cursor: dict) -> Path:
        (tmp_path / "CLAUDE.md").write_text("# p")
        p = tmp_path / ".mcp.json"
        p.write_text(json.dumps({"mcpServers": claude}))
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": cursor}))
        return p

    def test_flags_divergent_args(self, tmp_path: Path) -> None:
        p = self._project(
            tmp_path,
            {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
                }
            },
            {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}},
        )
        r = lint_mcp_config(str(p), {self.RULE: "warning"})
        d = [x for x in r.diagnostics if x.rule_id == self.RULE]
        assert len(d) == 1 and "fs" in d[0].message and "Cursor" in d[0].message

    def test_silent_when_identical(self, tmp_path: Path) -> None:
        srv = {"fs": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}
        p = self._project(tmp_path, srv, srv)
        r = lint_mcp_config(str(p), {self.RULE: "warning"})
        assert [x for x in r.diagnostics if x.rule_id == self.RULE] == []

    def test_silent_when_different_servers(self, tmp_path: Path) -> None:
        p = self._project(tmp_path, {"a": {"command": "x"}}, {"b": {"command": "y"}})
        r = lint_mcp_config(str(p), {self.RULE: "warning"})
        assert [x for x in r.diagnostics if x.rule_id == self.RULE] == []
