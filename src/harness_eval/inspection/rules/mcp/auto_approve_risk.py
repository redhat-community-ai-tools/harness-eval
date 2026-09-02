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

_WRITE_EXECUTE_KEYWORDS = {
    "write",
    "create",
    "delete",
    "update",
    "edit",
    "push",
    "execute",
    "run",
    "exec",
    "send",
    "post",
    "put",
    "patch",
    "remove",
    "drop",
    "merge",
    "deploy",
}


def _is_high_risk_tool(tool_name: str) -> bool:
    lower = tool_name.lower()
    return any(kw in lower for kw in _WRITE_EXECUTE_KEYWORDS)


class McpAutoApproveRisk:
    meta = RuleMeta(
        id="mcp/auto-approve-risk",
        default_severity=Severity.WARNING,
        fixable=False,
        description=("Flag MCP servers with autoApprove lists containing write or execute tools"),
        category=RuleCategory.SECURITY,
        messages={
            "auto_approve_write": (
                "Server '{{server}}' auto-approves '{{tool}}' which appears to have"
                " write/execute capability. Auto-approved tools bypass human confirmation."
            ),
            "auto_approve_all": (
                "Server '{{server}}' has an empty autoApprove list, which may auto-approve"
                " all tools depending on the runtime."
            ),
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Remove write/execute tools from the autoApprove list.",
    )

    def create(self, context: RuleContext) -> None:
        raw, path = context.source_text()
        if not raw or not raw.strip():
            return

        loc = Location(file=path)

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

            auto_approve = server_def.get("autoApprove")
            if auto_approve is None:
                continue

            if isinstance(auto_approve, list):
                if len(auto_approve) == 0:
                    context.report(
                        ReportDescriptor(
                            message_id="auto_approve_all",
                            data={"server": name},
                            location=loc,
                        )
                    )
                    continue

                for tool in auto_approve:
                    if isinstance(tool, str) and _is_high_risk_tool(tool):
                        context.report(
                            ReportDescriptor(
                                message_id="auto_approve_write",
                                data={"server": name, "tool": tool},
                                location=loc,
                            )
                        )
