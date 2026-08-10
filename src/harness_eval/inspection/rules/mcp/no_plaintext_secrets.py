from __future__ import annotations

import json
import math

from harness_eval.core.types import ComponentType
from harness_eval.data import load_secret_prefixes
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_PLACEHOLDER_SUBSTRINGS = [
    "your_",
    "changeme",
    "change-me",
    "xxx",
    "todo",
    "example",
    "placeholder",
    "dummy",
]

_CREDENTIAL_KEY_SUBSTRINGS = ["key", "token", "secret", "password", "auth"]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_env_reference(value: str) -> bool:
    return value.startswith("$") or "${" in value


def _is_placeholder(value: str) -> bool:
    lower = value.lower()
    if lower.startswith("<") and lower.endswith(">"):
        return True
    if not value or value.isspace():
        return True
    return any(p in lower for p in _PLACEHOLDER_SUBSTRINGS)


def _key_suggests_credential(key: str) -> bool:
    lower = key.lower()
    return any(sub in lower for sub in _CREDENTIAL_KEY_SUBSTRINGS)


class McpNoPlaintextSecrets:
    meta = RuleMeta(
        id="mcp/no-plaintext-secrets",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag literal secret values committed in MCP configuration files",
        category=RuleCategory.SECURITY,
        messages={
            "literal_secret": (
                "MCP server '{{server}}': '{{key}}' appears to contain a literal secret."
                " Use an environment variable reference instead."
            ),
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Replace the literal secret with an environment variable reference.",
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

        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            return

        prefixes = load_secret_prefixes()

        for server_name, server_def in servers.items():
            if not isinstance(server_def, dict):
                continue

            # Check env values for stdio servers
            env = server_def.get("env")
            if isinstance(env, dict):
                for key, value in env.items():
                    if isinstance(value, str):
                        self._check_value(context, loc, server_name, key, value, prefixes)

            # Check headers for url servers
            headers = server_def.get("headers")
            if isinstance(headers, dict):
                for key, value in headers.items():
                    if isinstance(value, str):
                        self._check_value(context, loc, server_name, key, value, prefixes)

    def _check_value(
        self,
        context: RuleContext,
        loc: Location,
        server: str,
        key: str,
        value: str,
        prefixes: list[str],
    ) -> None:
        # Step 1: skip env references and placeholders
        if _is_env_reference(value):
            return
        if _is_placeholder(value):
            return

        # Step 2: check known credential prefixes
        for prefix in prefixes:
            if value.startswith(prefix):
                context.report(
                    ReportDescriptor(
                        message_id="literal_secret",
                        data={"server": server, "key": key},
                        location=loc,
                    )
                )
                return

        # Step 3: check sk- as a general prefix with length >= 32
        if value.startswith("sk-") and len(value) >= 32:
            context.report(
                ReportDescriptor(
                    message_id="literal_secret",
                    data={"server": server, "key": key},
                    location=loc,
                )
            )
            return

        # Step 4: entropy check with key-name guard
        if len(value) >= 20 and _key_suggests_credential(key) and _shannon_entropy(value) > 4.0:
            context.report(
                ReportDescriptor(
                    message_id="literal_secret",
                    data={"server": server, "key": key},
                    location=loc,
                )
            )
