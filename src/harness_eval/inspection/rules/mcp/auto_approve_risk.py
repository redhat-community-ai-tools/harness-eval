from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.mcp._shared import extract_servers, parse_config
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
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Remove write/execute tools from the autoApprove list.",
    )

    def create(self, context: RuleContext) -> None:
        raw, path = context.source_text()
        if not raw or not raw.strip():
            return

        loc = Location(file=path)

        data, _ = parse_config(raw)

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
                for tool in auto_approve:
                    if isinstance(tool, str) and _is_high_risk_tool(tool):
                        context.report(
                            ReportDescriptor(
                                message_id="auto_approve_write",
                                data={"server": name, "tool": tool},
                                location=loc,
                            )
                        )
