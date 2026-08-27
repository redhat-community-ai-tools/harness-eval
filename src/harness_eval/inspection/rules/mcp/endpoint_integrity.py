"""Flag MCP server declarations that cannot work or leak credentials.

Three decidable conditions:
- a local `command` or `cwd` that is a relative path and does not exist in the repository;
- a `url` with an `http://` scheme to a host that is not loopback;
- a `url` carrying userinfo (`https://user:token@host`).
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules._config_fs import project_root
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}


class McpEndpointIntegrity:
    meta = RuleMeta(
        id="mcp/endpoint-integrity",
        tier="provisional",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag MCP servers whose local command path is missing, whose URL is plain HTTP to a remote host, or whose URL embeds credentials",
        category=RuleCategory.SECURITY,
        messages={
            "missing_path": "MCP server '{{server}}': {{field}} '{{path}}' does not exist in the repository.",
            "insecure_url": "MCP server '{{server}}': url uses http:// to non-loopback host '{{host}}'; tool traffic and tokens travel in the clear.",
            "userinfo_url": "MCP server '{{server}}': url embeds credentials in the authority; move them to an env or headers field.",
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Fix the path, use https://, and keep credentials out of URLs.",
    )

    def create(self, context: RuleContext) -> None:
        raw = context.skill.raw_content
        path = context.skill.skill_md_path
        if not raw or not raw.strip():
            return
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        servers = data.get("mcpServers") or data.get("servers") or data.get("mcp") or {}
        if not isinstance(servers, dict):
            return
        root = project_root(Path(path))
        loc = Location(file=path)
        for name, sd in servers.items():
            if not isinstance(sd, dict):
                continue
            for field in ("command", "cwd"):
                v = sd.get(field)
                if not isinstance(v, str) or not v:
                    continue
                relative = v.startswith(("./", "../")) or (
                    field == "cwd" and not v.startswith(("/", "~", "$"))
                )
                if relative and not (root / v).exists():
                    context.report(
                        ReportDescriptor(
                            message_id="missing_path",
                            data={"server": name, "field": field, "path": v},
                            location=loc,
                        )
                    )
            url = sd.get("url")
            if isinstance(url, str) and "://" in url:
                parts = urlsplit(url)
                host = (parts.hostname or "").lower()
                if (
                    parts.scheme == "http"
                    and host
                    and host not in _LOOPBACK
                    and not host.startswith("127.")
                ):
                    context.report(
                        ReportDescriptor(
                            message_id="insecure_url",
                            data={"server": name, "host": host},
                            location=loc,
                        )
                    )
                if parts.username or parts.password:
                    context.report(
                        ReportDescriptor(
                            message_id="userinfo_url", data={"server": name}, location=loc
                        )
                    )
