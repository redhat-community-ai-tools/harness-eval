"""Cross-component security analysis: detect security issues that span component boundaries."""

from __future__ import annotations

from typing import TYPE_CHECKING

from harness_eval.core.types import ComponentType
from harness_eval.data import load_capabilities
from harness_eval.inspection.rules.security._shared import strip_code_blocks

if TYPE_CHECKING:
    from harness_eval.analysis.component_graph import ComponentGraph

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class CrossComponentFlow:
    meta = RuleMeta(
        id="security/cross-component-flow",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect security issues that span component boundaries",
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "xc_exfiltration": (
                "Cross-component exfiltration: '{{source}}' has credential/env access"
                " and delegates to '{{target}}' which has network capability."
                " Sensitive data may flow across this boundary."
            ),
            "xc_confused_deputy": (
                "Confused deputy: agent '{{agent}}' disallows '{{tool}}'"
                " but references skill '{{skill}}' which uses {{capability}}"
                " capability (in {{files}})"
            ),
            "xc_mcp_phantom": (
                "Skill '{{skill}}' calls MCP tool '{{tool_call}}'"
                " but server '{{server}}' is not configured in .mcp.json"
            ),
        },
        target_type=ComponentType.SKILL,
        frameworks={
            "owasp_llm": "LLM06",
            "owasp_agentic": "AG04",
            "mitre_atlas": "AML.T0054",
        },
        default_suggestion="Restrict network access in the delegated component or scope credentials.",
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("cross_component_flow_checked"):
            return
        context.scan_state["cross_component_flow_checked"] = True

        from harness_eval.analysis.component_graph import ComponentGraph  # noqa: F401

        graph: ComponentGraph | None = context.scan_state.get("component_graph")
        if not graph or len(graph.nodes) < 2:
            return

        self._check_exfiltration(context, graph)
        self._check_confused_deputy(context, graph)
        self._check_mcp_phantom(context, graph)

    def _check_exfiltration(self, context: RuleContext, graph: ComponentGraph) -> None:
        credential_caps = {"credential", "env"}
        network_caps = {"network"}

        for node in graph.nodes.values():
            if node.component_type != ComponentType.SKILL:
                continue

            source_caps = set(node.detected_capabilities.keys())
            has_creds = bool(source_caps & credential_caps)
            if not has_creds:
                continue

            reachable = graph.reachable_from(node.name)
            for target_name in reachable:
                target = graph.nodes.get(target_name)
                if not target or target.component_type != ComponentType.SKILL:
                    continue
                target_caps = set(target.detected_capabilities.keys())
                if target_caps & network_caps:
                    context.report(
                        ReportDescriptor(
                            message_id="xc_exfiltration",
                            data={
                                "source": node.name,
                                "target": target.name,
                            },
                            location=Location(file=node.file_path, start_line=1),
                            suggestion=(
                                "Separate credential-reading logic from network-capable components."
                            ),
                        )
                    )

    def _check_confused_deputy(self, context: RuleContext, graph: ComponentGraph) -> None:
        caps = load_capabilities()
        tool_to_cap = caps.tool_to_capability()

        for node in graph.nodes.values():
            if node.component_type != ComponentType.AGENT:
                continue
            if not node.disallowed_tools:
                continue

            disallowed_caps: dict[str, str] = {}
            for tool in node.disallowed_tools:
                tool_lower = tool.lower().strip()
                for cap in tool_to_cap.get(tool_lower, set()):
                    disallowed_caps[cap] = tool

            if not disallowed_caps:
                continue

            agent_key = f"agent:{node.name}"
            for edge in graph.edges_from(agent_key):
                target = graph.nodes.get(edge.target)
                if not target or target.component_type != ComponentType.SKILL:
                    continue

                target_caps = target.detected_capabilities
                for cap, tool_name in disallowed_caps.items():
                    if cap in target_caps:
                        files = ", ".join(sorted(set(target_caps[cap]))[:3])
                        context.report(
                            ReportDescriptor(
                                message_id="xc_confused_deputy",
                                data={
                                    "agent": node.name,
                                    "tool": tool_name,
                                    "skill": target.name,
                                    "capability": cap,
                                    "files": files,
                                },
                                location=Location(file=node.file_path, start_line=1),
                                suggestion=(
                                    "Remove the capability from the referenced skill,"
                                    " or adjust the agent's disallowed tools."
                                ),
                            )
                        )

    def _check_mcp_phantom(self, context: RuleContext, graph: ComponentGraph) -> None:
        configured_servers = {
            node.name
            for node in graph.nodes.values()
            if node.component_type == ComponentType.MCP_CONFIG
        }

        if not configured_servers and not any(e.edge_type == "uses_mcp" for e in graph.edges):
            return

        for skill in context.all_skills:
            if not skill.body:
                continue
            from harness_eval.analysis.component_graph import _extract_mcp_tool_calls

            mcp_calls = _extract_mcp_tool_calls(strip_code_blocks(skill.body))
            for server_name, tool_name in mcp_calls:
                if server_name not in configured_servers:
                    context.report(
                        ReportDescriptor(
                            message_id="xc_mcp_phantom",
                            data={
                                "skill": skill.dir_name,
                                "tool_call": f"mcp__{server_name}__{tool_name}",
                                "server": server_name,
                            },
                            location=Location(file=skill.skill_md_path, start_line=1),
                        )
                    )
