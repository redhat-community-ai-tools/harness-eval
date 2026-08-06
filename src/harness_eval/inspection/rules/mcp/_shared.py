"""Shared helpers for MCP configuration rules."""

from __future__ import annotations

from typing import Any


def extract_servers(data: dict[str, Any]) -> Any:
    """Return the MCP servers mapping from a parsed config.

    Supports the standard ``mcpServers`` key (Claude Code, Cursor, Gemini CLI)
    and OpenCode's ``mcp`` key. Returns whatever value is under the first key
    present (which callers validate), or ``None`` if neither key exists.
    """
    if "mcpServers" in data:
        return data.get("mcpServers")
    if "mcp" in data:
        return data.get("mcp")
    return None
