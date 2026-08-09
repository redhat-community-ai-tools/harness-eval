"""Unified component graph for cross-component security analysis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from harness_eval.core.types import ComponentType
from harness_eval.data import load_capabilities

if TYPE_CHECKING:
    from harness_eval.inspection.types import ParsedAgent, ParsedCommand, ParsedHooks, ParsedSkill


@dataclass(frozen=True)
class GraphNode:
    name: str
    component_type: ComponentType
    file_path: str
    allowed_tools: list[str] = field(default_factory=list)
    disallowed_tools: list[str] = field(default_factory=list)
    detected_capabilities: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    edge_type: str
    evidence: str = ""


@dataclass
class ComponentGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def edges_from(self, node_name: str) -> list[GraphEdge]:
        return [e for e in self.edges if e.source == node_name]

    def edges_to(self, node_name: str) -> list[GraphEdge]:
        return [e for e in self.edges if e.target == node_name]

    def reachable_from(self, node_name: str) -> set[str]:
        visited: set[str] = set()
        stack = [node_name]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for edge in self.edges_from(current):
                if edge.target not in visited:
                    stack.append(edge.target)
        visited.discard(node_name)
        return visited


def _detect_capabilities_for_dir(skill_dir: Path) -> dict[str, list[str]]:
    caps = load_capabilities()
    cap_patterns = caps.capability_patterns()
    found: dict[str, list[str]] = {}

    for py_file in sorted(skill_dir.rglob("*.py")):
        if ".git" in py_file.parts or "__pycache__" in py_file.parts:
            continue
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for cap, patterns in cap_patterns.items():
            for pat in patterns:
                if pat.search(content):
                    found.setdefault(cap, []).append(py_file.name)
                    break

    for sh_file in sorted(skill_dir.rglob("*.sh")):
        if ".git" in sh_file.parts:
            continue
        found.setdefault("shell", []).append(sh_file.name)

    return found


_MCP_TOOL_PATTERN = re.compile(r"mcp__(\w+)__(\w+)")


def _extract_mcp_tool_calls(body: str) -> list[tuple[str, str]]:
    """Extract (server_name, tool_name) from mcp__server__tool patterns."""
    return _MCP_TOOL_PATTERN.findall(body)


def _parse_mcp_config(mcp_path: str) -> dict[str, dict]:
    """Parse .mcp.json and return {server_name: config_dict}."""
    path = Path(mcp_path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return {}
    return servers


def build_component_graph(
    all_skills: list[ParsedSkill],
    all_commands: list[ParsedCommand],
    agents: list[ParsedAgent] | None = None,
    hooks: ParsedHooks | None = None,
    mcp_config_path: str | None = None,
) -> ComponentGraph:
    """Build a unified component graph from all discovered components."""
    from harness_eval.inspection.rules.content._skill_refs import extract_references
    from harness_eval.inspection.rules.security._shared import strip_code_blocks

    graph = ComponentGraph()
    agents = agents or []
    skill_names: set[str] = set()

    for skill in all_skills:
        name = skill.dir_name
        skill_names.add(name)
        skill_dir = Path(skill.dir_path) if skill.dir_path else None
        detected = (
            _detect_capabilities_for_dir(skill_dir) if skill_dir and skill_dir.is_dir() else {}
        )

        allowed_tools = skill.frontmatter.get("allowed-tools", [])
        if not isinstance(allowed_tools, list):
            allowed_tools = []

        graph.nodes[name] = GraphNode(
            name=name,
            component_type=ComponentType.SKILL,
            file_path=skill.skill_md_path,
            allowed_tools=allowed_tools,
            detected_capabilities=detected,
        )

    for cmd in all_commands:
        name = cmd.dir_name
        graph.nodes[f"cmd:{name}"] = GraphNode(
            name=name,
            component_type=ComponentType.COMMAND,
            file_path=cmd.command_md_path,
        )

    for agent in agents:
        name = agent.file_name.removesuffix(".md")
        graph.nodes[f"agent:{name}"] = GraphNode(
            name=name,
            component_type=ComponentType.AGENT,
            file_path=agent.agent_md_path,
            disallowed_tools=agent.disallowed_tools,
            allowed_tools=agent.allowed_tools,
        )

        for skill_name in agent.referenced_skills:
            if skill_name in skill_names:
                graph.edges.append(
                    GraphEdge(
                        source=f"agent:{name}",
                        target=skill_name,
                        edge_type="delegates_to",
                        evidence=f"agent frontmatter skills: {skill_name}",
                    )
                )

        if agent.body:
            for ref in extract_references(agent.body, name):
                if ref in skill_names:
                    graph.edges.append(
                        GraphEdge(
                            source=f"agent:{name}",
                            target=ref,
                            edge_type="references",
                            evidence=f"agent body references {ref}",
                        )
                    )

    for skill in all_skills:
        if skill.body:
            for ref in extract_references(skill.body, skill.dir_name):
                if ref in skill_names and ref != skill.dir_name:
                    graph.edges.append(
                        GraphEdge(
                            source=skill.dir_name,
                            target=ref,
                            edge_type="references",
                            evidence=f"skill body references {ref}",
                        )
                    )

    if hooks:
        graph.nodes["hooks"] = GraphNode(
            name="hooks",
            component_type=ComponentType.HOOKS,
            file_path=hooks.file_path,
        )
        for hook in hooks.hooks:
            cmd = hook.get("command", "")
            if not isinstance(cmd, str):
                continue
            for skill_name in skill_names:
                if skill_name in cmd:
                    graph.edges.append(
                        GraphEdge(
                            source="hooks",
                            target=skill_name,
                            edge_type="references",
                            evidence=f"hook command mentions {skill_name}",
                        )
                    )

    if mcp_config_path:
        servers = _parse_mcp_config(mcp_config_path)
        for server_name, _config in servers.items():
            node_key = f"mcp:{server_name}"
            graph.nodes[node_key] = GraphNode(
                name=server_name,
                component_type=ComponentType.MCP_CONFIG,
                file_path=mcp_config_path,
            )

        for skill in all_skills:
            if not skill.body:
                continue
            mcp_calls = _extract_mcp_tool_calls(strip_code_blocks(skill.body))
            for server_name, tool_name in mcp_calls:
                server_key = f"mcp:{server_name}"
                if server_key in graph.nodes:
                    graph.edges.append(
                        GraphEdge(
                            source=skill.dir_name,
                            target=server_key,
                            edge_type="uses_mcp",
                            evidence=f"calls mcp__{server_name}__{tool_name}",
                        )
                    )

    return graph
