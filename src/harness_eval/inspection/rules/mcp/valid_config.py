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


class McpValidConfig:
    meta = RuleMeta(
        id="mcp/valid-config",
        tier="gating",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Validate MCP configuration file structure",
        category=RuleCategory.STRUCTURAL,
        messages={
            "invalid_json": "MCP config is not valid JSON: {{error}}",
            "not_object": "MCP config root must be a JSON object",
            "missing_servers": "MCP config has no 'mcpServers', 'servers', or 'mcp' key",
            "servers_not_object": "MCP servers must be a JSON object, got {{actual_type}}",
            "server_no_transport": "Server '{{name}}' has no 'command' (stdio) or 'url' (HTTP/SSE)",
            "args_not_array": "Server '{{name}}': 'args' must be an array, got {{actual_type}}",
            "env_not_object": "Server '{{name}}': 'env' must be an object, got {{actual_type}}",
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Fix the MCP config file to match the expected JSON structure.",
    )

    def create(self, context: RuleContext) -> None:
        raw = context.skill.raw_content
        if not raw or not raw.strip():
            return

        loc = Location(file=context.skill.skill_md_path)

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            context.report(
                ReportDescriptor(
                    message_id="invalid_json",
                    data={"error": str(e)},
                    location=loc,
                )
            )
            return

        if not isinstance(data, dict):
            context.report(ReportDescriptor(message_id="not_object", location=loc))
            return

        servers = extract_servers(data)
        if servers is None:
            context.report(ReportDescriptor(message_id="missing_servers", location=loc))
            return

        if not isinstance(servers, dict):
            context.report(
                ReportDescriptor(
                    message_id="servers_not_object",
                    data={"actual_type": type(servers).__name__},
                    location=loc,
                )
            )
            return

        for name, server_def in servers.items():
            if not isinstance(server_def, dict):
                continue

            has_command = bool(server_def.get("command"))
            has_url = bool(server_def.get("url"))
            if not has_command and not has_url:
                context.report(
                    ReportDescriptor(
                        message_id="server_no_transport",
                        data={"name": name},
                        location=loc,
                    )
                )

            args = server_def.get("args")
            if args is not None and not isinstance(args, list):
                context.report(
                    ReportDescriptor(
                        message_id="args_not_array",
                        data={"name": name, "actual_type": type(args).__name__},
                        location=loc,
                    )
                )

            env = server_def.get("env")
            if env is not None and not isinstance(env, dict):
                context.report(
                    ReportDescriptor(
                        message_id="env_not_object",
                        data={"name": name, "actual_type": type(env).__name__},
                        location=loc,
                    )
                )
