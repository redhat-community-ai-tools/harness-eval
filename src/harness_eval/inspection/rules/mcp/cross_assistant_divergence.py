"""Flag an MCP server that two assistants configure differently.

Multi-assistant setups routinely declare the same server in ``.mcp.json``
(Claude Code), ``.cursor/mcp.json`` (Cursor), ``.vscode/mcp.json`` (Copilot),
``.gemini/settings.json`` (Gemini CLI), and ``opencode.json`` (OpenCode). When
the declarations drift, the assistants run different commands, versions, or
endpoints under one name, and only one of them was reviewed. This is the MCP
counterpart of cross-assistant context-file divergence and is decidable by
comparing two files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

# Relative path -> (top-level key holding the server map, assistant label)
_MCP_CONFIG_FILES: list[tuple[str, str, str]] = [
    (".mcp.json", "mcpServers", "Claude Code"),
    (".cursor/mcp.json", "mcpServers", "Cursor"),
    (".vscode/mcp.json", "servers", "Copilot"),
    (".gemini/settings.json", "mcpServers", "Gemini CLI"),
    ("opencode.json", "mcp", "OpenCode"),
    ("opencode.jsonc", "mcp", "OpenCode"),
    (".windsurf/mcp_config.json", "mcpServers", "Windsurf"),
    (".codex/config.json", "mcpServers", "Codex CLI"),
]

_COMPARE_KEYS = ("command", "args", "url", "type", "transport")


def _load_servers(path: Path, key: str) -> dict[str, dict[str, Any]] | None:
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError):
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # jsonc: strip // comments crudely and retry
        stripped = "\n".join(line.split("//")[0] for line in text.splitlines())
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict):
        return None
    servers = data.get(key)
    if not isinstance(servers, dict):
        return None
    return {k: v for k, v in servers.items() if isinstance(v, dict)}


def _normalise(server: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields that determine what the server runs."""
    out: dict[str, Any] = {}
    for k in _COMPARE_KEYS:
        if k in server:
            v = server[k]
            out[k] = [str(a) for a in v] if isinstance(v, list) else str(v)
    # OpenCode nests the command as a list under "command"
    if isinstance(server.get("command"), list):
        out["command"] = " ".join(str(a) for a in server["command"])
        if "args" in out:
            out["command"] = out["command"] + " " + " ".join(out["args"])
            del out["args"]
    elif "command" in out and "args" in out:
        out["command"] = str(out["command"]) + " " + " ".join(out["args"])
        del out["args"]
    return out


def _find_project_root(start: Path) -> Path:
    current = start.resolve().parent
    for _ in range(12):
        for rel, _key, _label in _MCP_CONFIG_FILES:
            if (current / rel).is_file():
                return current
        if (current / ".git").exists() or (current / "CLAUDE.md").is_file():
            return current
        if current.parent == current:
            break
        current = current.parent
    return start.resolve().parent


class McpCrossAssistantDivergence:
    meta = RuleMeta(
        id="mcp/cross-assistant-divergence",
        scope="PAIRWISE",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag an MCP server that is declared with a different command, args, or"
            " URL in two assistants' configuration files"
        ),
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "divergence": (
                "MCP server '{{server}}' is declared differently in {{file_a}} ({{assistant_a}})"
                " and {{file_b}} ({{assistant_b}}): {{diff}}."
            ),
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion=(
            "Reconcile the declarations so every assistant runs the same server, or"
            " generate one configuration from the other."
        ),
    )

    def create(self, context: RuleContext) -> None:
        this_path = Path(context.source_text()[1])
        root = _find_project_root(this_path)

        key = f"mcp_cross_assistant_divergence_checked:{root}"
        if context.scan_state.get(key):
            return
        context.scan_state[key] = True

        found: list[tuple[str, str, dict[str, dict[str, Any]]]] = []
        for rel, k, label in _MCP_CONFIG_FILES:
            p = root / rel
            if p.is_file():
                servers = _load_servers(p, k)
                if servers:
                    found.append((rel, label, servers))
        if len(found) < 2:
            return

        reported: set[tuple[str, str, str]] = set()
        for i in range(len(found)):
            for j in range(i + 1, len(found)):
                rel_a, label_a, srv_a = found[i]
                rel_b, label_b, srv_b = found[j]
                for name in sorted(set(srv_a) & set(srv_b)):
                    na, nb = _normalise(srv_a[name]), _normalise(srv_b[name])
                    if na == nb:
                        continue
                    sig = (name, rel_a, rel_b)
                    if sig in reported:
                        continue
                    reported.add(sig)
                    diffs = []
                    for fld in sorted(set(na) | set(nb)):
                        if na.get(fld) != nb.get(fld):
                            diffs.append(f"{fld} '{na.get(fld, '')}' vs '{nb.get(fld, '')}'")
                    context.report(
                        ReportDescriptor(
                            message_id="divergence",
                            data={
                                "server": name,
                                "file_a": rel_a,
                                "assistant_a": label_a,
                                "file_b": rel_b,
                                "assistant_b": label_b,
                                "diff": "; ".join(diffs)[:300],
                            },
                            location=Location(file=str(root / rel_a)),
                        )
                    )
