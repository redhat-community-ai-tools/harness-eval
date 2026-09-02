"""Component graph ingests every hooks file and every MCP config."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.analysis.component_graph import build_component_graph
from harness_eval.core.types import ComponentType
from harness_eval.inspection.parsers import parse_hooks, parse_skill


def _skill(tmp_path: Path, name: str, body: str) -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill {name}\n---\n\n{body}\n"
    )
    return d


class TestGraphIngestsEveryHooksAndMcpFile:
    def test_two_hooks_files_both_become_nodes(self, tmp_path: Path) -> None:
        skill_dir = _skill(tmp_path, "deploy", "Deploy the service.")
        claude = tmp_path / ".claude"
        cursor = tmp_path / ".cursor"
        claude.mkdir()
        cursor.mkdir()
        (claude / "settings.json").write_text(
            json.dumps({"hooks": {"Stop": [{"command": "scripts/deploy.sh"}]}})
        )
        (cursor / "hooks.json").write_text(
            json.dumps({"hooks": {"PreToolUse": [{"command": "echo hi"}]}})
        )

        graph = build_component_graph(
            [parse_skill(str(skill_dir))],
            [],
            hooks=[
                parse_hooks(str(claude / "settings.json")),
                parse_hooks(str(cursor / "hooks.json")),
            ],
        )
        hook_nodes = [n for n in graph.nodes.values() if n.component_type == ComponentType.HOOKS]
        assert len(hook_nodes) == 2
        paths = {n.file_path for n in hook_nodes}
        assert str(claude / "settings.json") in paths
        assert str(cursor / "hooks.json") in paths

    def test_second_mcp_file_servers_are_nodes(self, tmp_path: Path) -> None:
        skill_dir = _skill(
            tmp_path,
            "fetcher",
            "Call mcp__extra__read and mcp__github__get.",
        )
        (tmp_path / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"github": {"command": "npx", "args": ["-y", "github"]}}})
        )
        vscode = tmp_path / ".vscode"
        vscode.mkdir()
        (vscode / "mcp.json").write_text(
            json.dumps({"servers": {"extra": {"command": "uvx", "args": ["extra"]}}})
        )

        graph = build_component_graph(
            [parse_skill(str(skill_dir))],
            [],
            mcp_config_paths=[
                str(tmp_path / ".mcp.json"),
                str(vscode / "mcp.json"),
            ],
        )
        assert "mcp:github" in graph.nodes
        assert "mcp:extra" in graph.nodes
        uses = {(e.source, e.target) for e in graph.edges if e.edge_type == "uses_mcp"}
        assert ("fetcher", "mcp:extra") in uses
        assert ("fetcher", "mcp:github") in uses
