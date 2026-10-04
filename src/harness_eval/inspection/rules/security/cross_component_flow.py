"""Cross-component security analysis: detect security issues that span component boundaries."""

from __future__ import annotations

from typing import TYPE_CHECKING

from harness_eval.core.types import ComponentType
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
        scope="SETUP",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect security issues that span component boundaries",
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "xc_exfiltration": (
                "Cross-component exfiltration: '{{source}}' has credential/env access"
                " and explicitly reaches '{{target}}', which can transmit data."
                " Review whether sensitive values can cross this boundary."
            ),
            "xc_mcp_phantom": (
                "Skill '{{skill}}' calls MCP tool '{{tool_call}}'"
                " but server '{{server}}' is not configured in any discovered MCP configuration"
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
        if not context.artifacts.mark_once("cross_component_flow_checked"):
            return

        from harness_eval.analysis.component_graph import ComponentGraph  # noqa: F401

        graph: ComponentGraph | None = context.artifacts.component_graph
        if not graph or len(graph.nodes) < 2:
            return

        self._check_exfiltration(context, graph)
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

            # Only parser-backed references are strong enough for a security
            # finding. Free-text mention edges are intentionally excluded.
            reachable = graph.reachable_from(node.name, min_confidence=1.0)
            for target_name in reachable:
                target = graph.nodes.get(target_name)
                if not target:
                    continue
                target_caps = set(target.detected_capabilities.keys())
                can_transmit = bool(target_caps & network_caps) or (
                    target.component_type == ComponentType.MCP_CONFIG
                )
                if can_transmit:
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

    def _check_mcp_phantom(self, context: RuleContext, graph: ComponentGraph) -> None:
        configured_servers = {
            node.name
            for node in graph.nodes.values()
            if node.component_type == ComponentType.MCP_CONFIG
        }

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
