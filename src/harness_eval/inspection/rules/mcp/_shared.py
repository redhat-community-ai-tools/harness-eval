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
    for key in ("mcpServers", "servers", "mcp"):
        if key in data:
            return data.get(key)
    return None
