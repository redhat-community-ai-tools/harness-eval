from __future__ import annotations

from typing import Any

from harness_eval.inspection.rules.mcp._shared import parse_config


def parsed_config(raw: str) -> dict[str, Any] | None:
    """Parse JSON, JSONC, or TOML and require an object at the root."""
    data, _ = parse_config(raw)
    return data if isinstance(data, dict) else None
