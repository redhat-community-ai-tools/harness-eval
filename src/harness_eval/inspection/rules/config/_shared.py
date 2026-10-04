from __future__ import annotations

from typing import Any

from harness_eval.inspection.rules.mcp._shared import parse_config


def parsed_config(raw: str) -> dict[str, Any] | None:
    """Parse JSON, JSONC, or TOML and require an object at the root."""
    data, _ = parse_config(raw)
    return data if isinstance(data, dict) else None


OPENCODE_EFFECTS = frozenset({"allow", "ask", "deny"})

# V1 names a tool where V2 names an action; only the shell differs.
_OPENCODE_V1_ACTIONS = {"bash": "shell"}


def opencode_permission_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return OpenCode permission rules in V2 order and shape.

    V2 writes ``permissions`` as a list of ``{action, resource, effect}``. V1
    writes ``permission`` as one effect for everything, or as an object that
    maps a tool to an effect or to ``{pattern: effect}``. Both evaluate the
    last matching rule, so V1 is flattened in document order.
    """
    v2 = data.get("permissions")
    if isinstance(v2, list):
        return [rule for rule in v2 if isinstance(rule, dict)]

    v1 = data.get("permission")
    if isinstance(v1, str):
        return [{"action": "*", "resource": "*", "effect": v1}]
    if not isinstance(v1, dict):
        return []
    rules: list[dict[str, Any]] = []
    for tool, value in v1.items():
        action = _OPENCODE_V1_ACTIONS.get(str(tool), str(tool))
        if isinstance(value, str):
            rules.append({"action": action, "resource": "*", "effect": value})
        elif isinstance(value, dict):
            rules.extend(
                {"action": action, "resource": str(pattern), "effect": effect}
                for pattern, effect in value.items()
            )
    return rules
