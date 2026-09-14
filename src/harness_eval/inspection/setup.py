"""Build the typed inspection view of a discovered setup.

Discovery owns canonical component identity.  This module performs the one
type-specific parse needed by rules and attaches each payload back to its
canonical ``ParsedComponent``.  Keeping this bridge explicit prevents callers
from independently reparsing the same setup in different layers.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from harness_eval.core.types import ComponentType, ParsedComponent, Setup
from harness_eval.inspection.parsers import (
    parse_agent,
    parse_claude_md,
    parse_command,
    parse_hooks,
    parse_mcp_config_file,
    parse_skill,
)
from harness_eval.inspection.types import ParsedFile


@dataclass(frozen=True)
class ParsedSetup:
    """A discovered setup plus its single, typed parse pass."""

    setup: Setup
    components: tuple[ParsedComponent, ...]
    parsed_by_type: dict[ComponentType, tuple[ParsedFile, ...]]

    def core_by_type(self, component_type: ComponentType) -> tuple[ParsedComponent, ...]:
        return tuple(c for c in self.components if c.component_type == component_type)

    def parsed(self, component_type: ComponentType) -> tuple[ParsedFile, ...]:
        return self.parsed_by_type.get(component_type, ())


def _parse_component(component: ParsedComponent) -> ParsedFile | None:
    """Parse one component using the canonical discovered path."""
    parsers = {
        ComponentType.SKILL: lambda: parse_skill(component.path),
        ComponentType.COMMAND: lambda: parse_command(component.path),
        ComponentType.CLAUDE_MD: lambda: parse_claude_md(component.path),
        ComponentType.HOOKS: lambda: parse_hooks(component.path),
        ComponentType.AGENT: lambda: parse_agent(component.path),
        ComponentType.MCP_CONFIG: lambda: parse_mcp_config_file(component.path),
    }
    parser = parsers.get(component.component_type)
    return parser() if parser else None


def parse_setup(setup: Setup) -> ParsedSetup:
    """Parse every lintable component once and attach its typed payload."""
    components: list[ParsedComponent] = []
    parsed_by_type: dict[ComponentType, list[ParsedFile]] = {}

    for component in setup.components:
        parsed = _parse_component(component)
        enriched = replace(component, parsed=parsed) if parsed is not None else component
        components.append(enriched)
        if parsed is not None:
            parsed_by_type.setdefault(component.component_type, []).append(parsed)

    return ParsedSetup(
        setup=setup,
        components=tuple(components),
        parsed_by_type={key: tuple(value) for key, value in parsed_by_type.items()},
    )


__all__ = ["ParsedSetup", "parse_setup"]
