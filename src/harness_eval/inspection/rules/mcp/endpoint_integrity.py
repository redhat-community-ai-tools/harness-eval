"""Flag MCP server declarations that cannot work or leak credentials.

Three decidable conditions:
- a local `command` or `cwd` that is a relative path and does not exist in the repository;
- a `url` with an `http://` scheme to a host that is not loopback;
- a `url` carrying userinfo (`https://user:token@host`).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules._config_fs import project_root
from harness_eval.inspection.rules.mcp._shared import extract_servers
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_LOOPBACK = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}


def _is_private_host(host: str) -> bool:
    if "." not in host:
        return True  # a bare service name (docker compose, kubernetes)
    if host.endswith(
        (".local", ".internal", ".lan", ".localdomain", ".example.com", ".example.net")
    ):
        return True
    return re.match(r"^(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.", host) is not None


class McpEndpointIntegrity:
    meta = RuleMeta(
        id="mcp/endpoint-integrity",
        tier="gating",
        scope="FILE_FS",
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
        raw, path = context.source_text()
        if not raw or not raw.strip():
            return
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        servers = extract_servers(data)
        if not isinstance(servers, dict):
            return
        root = project_root(Path(path), ceiling=context.artifacts.project_root)
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
                if relative and re.search(
                    r"(^|/)(node_modules|dist|build|target|out|bin|venv|\.venv|\.[A-Za-z][\w.-]*)/",
                    v,
                ):
                    continue  # produced by a build or an install step, not committed
                if relative and not (root / v).exists() and not (Path(path).parent / v).exists():
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
                            # a compose-network name, LAN address, or .local/.internal host
                            # carries traffic inside a private network; informational only
                            severity_override=Severity.INFO if _is_private_host(host) else None,
                        )
                    )
                if parts.username or parts.password:
                    context.report(
                        ReportDescriptor(
                            message_id="userinfo_url", data={"server": name}, location=loc
                        )
                    )
