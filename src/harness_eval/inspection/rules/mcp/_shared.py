"""Shared helpers for MCP configuration rules."""

from __future__ import annotations

from typing import Any


def extract_servers(data: dict[str, Any]) -> Any:
    """Return the MCP servers mapping from a parsed config.

    Supports the standard ``mcpServers`` key (Claude Code, Cursor, Gemini CLI),
    VS Code / Copilot ``servers``, and OpenCode's ``mcp`` key. Returns whatever
    value is under the first key present (which callers validate), or ``None``
    if none of those keys exist.
    """
    for key in ("mcpServers", "mcp_servers", "servers", "mcp"):
        if key in data:
            return data.get(key)
    # Plugin-style flat map (Claude Code plugin .mcp.json): every top-level
    # value is a server definition and there is no wrapper key.
    entries = {k: v for k, v in data.items() if not k.startswith("$")}
    if entries and all(
        isinstance(v, dict) and any(k in v for k in _TRANSPORT_KEYS) for v in entries.values()
    ):
        return entries
    return None


# Keys that identify a server definition across clients: stdio ``command``,
# HTTP/SSE ``url`` (Claude Code, Cursor, VS Code), Gemini CLI ``httpUrl``,
# explicit ``type``/``transport`` declarations.
_TRANSPORT_KEYS = ("command", "url", "httpUrl", "serverUrl", "type", "transport", "args")


def has_transport(server_def: dict[str, Any]) -> bool:
    """True when a server definition names a way to reach the server."""
    return any(bool(server_def.get(k)) for k in ("command", "url", "httpUrl", "serverUrl"))


def parse_config(raw: str) -> tuple[Any, bool]:
    """Parse an MCP config; retry as JSONC (comments, trailing commas) which
    VS Code and OpenCode accept. Returns (data, was_jsonc); (None, False) when
    neither parses."""
    import json
    import re

    try:
        return json.loads(raw), False
    except (json.JSONDecodeError, ValueError):
        pass
    stripped = re.sub(r"/\*.*?\*/", "", raw, flags=re.S)
    stripped = re.sub(r"(?m)^\s*//[^\n]*$", "", stripped)
    stripped = re.sub(r",\s*([}\]])", r"\1", stripped)
    try:
        return json.loads(stripped), True
    except (json.JSONDecodeError, ValueError):
        return None, False
