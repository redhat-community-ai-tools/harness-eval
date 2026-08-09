from __future__ import annotations

import json

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.mcp._shared import extract_servers
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class McpNoWildcardTools:
    meta = RuleMeta(
        id="mcp/no-wildcard-tools",
        default_severity=Severity.INFO,
        fixable=False,
        description="Flag MCP servers that expose all tools without restriction",
        category=RuleCategory.BEST_PRACTICES,
        messages={
            "no_tool_restriction": "Server '{{name}}' has no 'tools' or 'allowedTools' field, exposing all available tools.",
        },
        target_type=ComponentType.MCP_CONFIG,
    )

    def create(self, context: RuleContext) -> None:
        raw = context.skill.raw_content
        if not raw or not raw.strip():
            return

        loc = Location(file=context.skill.skill_md_path)

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(data, dict):
            return

        servers = extract_servers(data)
        if not isinstance(servers, dict):
            return

        for name, server_def in servers.items():
            if not isinstance(server_def, dict):
                continue
            has_tools = "tools" in server_def or "allowedTools" in server_def
            if not has_tools:
                context.report(
                    ReportDescriptor(
                        message_id="no_tool_restriction",
                        data={"name": name},
                        location=loc,
                    )
                )
