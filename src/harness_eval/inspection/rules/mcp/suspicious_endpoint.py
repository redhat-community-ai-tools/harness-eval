from __future__ import annotations

import json
import re

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

_SUSPICIOUS_PATTERNS = [
    re.compile(r"(?:https?://)?localhost(?::\d+)?(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:https?://)?127\.0\.0\.1(?::\d+)?(?:/|$)"),
    re.compile(r"(?:https?://)?0\.0\.0\.0(?::\d+)?(?:/|$)"),
    re.compile(r"(?:https?://)?10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)"),
    re.compile(r"(?:https?://)?172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)"),
    re.compile(r"(?:https?://)?192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)"),
]


class McpSuspiciousEndpoint:
    meta = RuleMeta(
        id="mcp/suspicious-endpoint",
        default_severity=Severity.INFO,
        fixable=False,
        description="Flag MCP servers pointing to localhost or private IP ranges",
        category=RuleCategory.SECURITY,
        messages={
            "suspicious_url": "Server '{{name}}' points to local/private address '{{url}}'. This may be a test config left in production.",
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
            url = server_def.get("url", "")
            if not url:
                continue
            for pattern in _SUSPICIOUS_PATTERNS:
                if pattern.search(url):
                    context.report(
                        ReportDescriptor(
                            message_id="suspicious_url",
                            data={"name": name, "url": url},
                            location=loc,
                        )
                    )
                    break
