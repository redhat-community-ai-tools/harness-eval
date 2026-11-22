from __future__ import annotations

import math
import re
from urllib.parse import parse_qs, urlparse

from harness_eval.core.types import ComponentType
from harness_eval.data import load_secret_prefixes
from harness_eval.inspection.rules.mcp._shared import extract_servers, parse_config
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
    "your-",
    "changeme",
    "change-me",
    "xxx",
    "todo",
    "example",
    "placeholder",
    "dummy",
]

_CREDENTIAL_KEY_SUBSTRINGS = ["key", "token", "secret", "password", "auth"]

# Matches --flag=value or -flag=value in CLI args
_FLAG_EQUALS_RE = re.compile(r"^-{1,2}([\w][\w-]*)=(.+)$")

# Matches VAR=value patterns in shell strings (e.g. GITHUB_TOKEN=ghp_... npx ...)
_ENV_ASSIGN_INLINE_RE = re.compile(r"(?:^|\s)([A-Z_][A-Z0-9_]*)=(\S+)")


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


def _is_credential_flag(arg: str) -> bool:
    """True when the argument looks like a CLI flag for a credential."""
    if not arg.startswith("-"):
        return False
    flag = arg.lstrip("-").lower()
    return any(sub in flag for sub in _CREDENTIAL_KEY_SUBSTRINGS)


class McpNoPlaintextSecrets:
    meta = RuleMeta(
        id="mcp/no-plaintext-secrets",
        tier="provisional",
        effect="block",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag literal secret values committed in MCP configuration files",
        category=RuleCategory.SECURITY,
        messages={
            # Diagnostic copy, not a credential.
            "literal_secret": (  # nosec B105
                "MCP server '{{server}}': '{{key}}' appears to contain a literal secret."
                " Use an environment variable reference instead."
            ),
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Replace the literal secret with an environment variable reference.",
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

            # Codex remote servers use env_http_headers to name environment
            # variables and http_headers for literal values.
            literal_headers = server_def.get("http_headers")
            if isinstance(literal_headers, dict):
                for key, value in literal_headers.items():
                    if isinstance(value, str):
                        self._check_value(context, loc, server_name, key, value, prefixes)

            # Check args for secrets (--key=value, --flag <value>, inline VAR=value)
            args = server_def.get("args")
            if isinstance(args, list):
                self._check_args(context, loc, server_name, args, prefixes)

            # Check url query string for secrets
            url = server_def.get("url")
            if isinstance(url, str):
                self._check_url(context, loc, server_name, url, prefixes)

            # Check command string for inline env assignments
            command = server_def.get("command")
            if isinstance(command, str):
                self._check_shell_string(context, loc, server_name, "command", command, prefixes)

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

    def _check_args(
        self,
        context: RuleContext,
        loc: Location,
        server: str,
        args: list[str],
        prefixes: list[str],
    ) -> None:
        """Scan CLI args for secrets in --key=value, --flag <value>, and VAR=value."""
        for i, arg in enumerate(args):
            if not isinstance(arg, str):
                continue

            handled = False

            # 1. --key=value or -key=value patterns
            eq_match = _FLAG_EQUALS_RE.match(arg)
            if eq_match:
                flag_name, value = eq_match.group(1), eq_match.group(2)
                # Use the flag name as key so entropy check fires for
                # credential-related flags; otherwise fall back to "args".
                key = f"args (--{flag_name})" if _key_suggests_credential(flag_name) else "args"
                self._check_value(context, loc, server, key, value, prefixes)
                # Also scan the extracted value for nested VAR=value patterns
                # (e.g. --env=GITHUB_TOKEN=ghp_abc).
                self._check_shell_string(context, loc, server, "args", value, prefixes)
                handled = True

            # 2. Value following a credential flag (--token <value>)
            # Guard: exclude flags that already carry an inline value via "="
            # to avoid false-positives when branch 1 already handled the arg.
            if not handled and i > 0 and not arg.startswith("-"):
                prev = args[i - 1]
                if isinstance(prev, str) and "=" not in prev and _is_credential_flag(prev):
                    self._check_value(context, loc, server, f"args ({prev})", arg, prefixes)
                    handled = True

            # 3. Inline VAR=value patterns (shell strings, e.g. sh -c)
            if not handled and _ENV_ASSIGN_INLINE_RE.search(arg):
                self._check_shell_string(context, loc, server, "args", arg, prefixes)
                handled = True

            # 4. Fallback: check the raw string for known prefixes
            if not handled:
                self._check_value(context, loc, server, "args", arg, prefixes)

    def _check_url(
        self,
        context: RuleContext,
        loc: Location,
        server: str,
        url: str,
        prefixes: list[str],
    ) -> None:
        """Scan URL query-string parameters for secrets."""
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = parse_qs(parsed.query, keep_blank_values=False)
        for key, values in params.items():
            for value in values:
                self._check_value(context, loc, server, f"url ({key})", value, prefixes)

    def _check_shell_string(
        self,
        context: RuleContext,
        loc: Location,
        server: str,
        field: str,
        text: str,
        prefixes: list[str],
    ) -> None:
        """Scan a shell string for inline VAR=value assignments."""
        for m in _ENV_ASSIGN_INLINE_RE.finditer(text):
            var_name, value = m.group(1), m.group(2)
            value = value.strip("\"'")
            self._check_value(context, loc, server, f"{field} ({var_name})", value, prefixes)
