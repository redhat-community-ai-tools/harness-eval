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


class McpDuplicateServer:
    meta = RuleMeta(
        id="mcp/duplicate-server",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Flag duplicate MCP server names or URLs in configuration",
        category=RuleCategory.STRUCTURAL,
        messages={
            "duplicate_url": "Multiple servers share the same URL '{{url}}': {{servers}}",
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

        # Check for duplicate URLs
        url_to_names: dict[str, list[str]] = {}
        for name, server_def in servers.items():
            if not isinstance(server_def, dict):
                continue
            url = server_def.get("url", "")
            if url:
                url_to_names.setdefault(url, []).append(name)

        for url, names in url_to_names.items():
            if len(names) > 1:
                context.report(
                    ReportDescriptor(
                        message_id="duplicate_url",
                        data={"url": url, "servers": ", ".join(names)},
                        location=loc,
                    )
                )
