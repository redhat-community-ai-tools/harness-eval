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
from harness_eval.inspection.types import (
    ParsedAgent,
    ParsedClaudeMd,
    ParsedCommand,
    ParsedFile,
    ParsedHooks,
    ParsedMcpConfig,
    ParsedSkill,
)


@dataclass(frozen=True)
class ParsedSetup:
    """A discovered setup plus its single, typed parse pass.

    Each per-type tuple is in discovery order and lines up index-for-index
    with ``core_by_type`` for the same component type.
    """

    setup: Setup
    components: tuple[ParsedComponent, ...]
    skills: tuple[ParsedSkill, ...] = ()
    commands: tuple[ParsedCommand, ...] = ()
    claude_mds: tuple[ParsedClaudeMd, ...] = ()
    hooks: tuple[ParsedHooks, ...] = ()
    agents: tuple[ParsedAgent, ...] = ()
    mcp_configs: tuple[ParsedMcpConfig, ...] = ()

    def core_by_type(self, component_type: ComponentType) -> tuple[ParsedComponent, ...]:
        return tuple(c for c in self.components if c.component_type == component_type)

    def parsed(self, component_type: ComponentType) -> tuple[ParsedFile, ...]:
        """Parsed payloads for *component_type*; empty for types no rule parses."""
        by_type: dict[ComponentType, tuple[ParsedFile, ...]] = {
            ComponentType.SKILL: self.skills,
            ComponentType.COMMAND: self.commands,
            ComponentType.CLAUDE_MD: self.claude_mds,
            ComponentType.HOOKS: self.hooks,
            ComponentType.AGENT: self.agents,
            ComponentType.MCP_CONFIG: self.mcp_configs,
        }
        return by_type.get(component_type, ())


def parse_setup(setup: Setup) -> ParsedSetup:
    """Parse every lintable component once and attach its typed payload."""
    components: list[ParsedComponent] = []
    skills: list[ParsedSkill] = []
    commands: list[ParsedCommand] = []
    claude_mds: list[ParsedClaudeMd] = []
    hooks: list[ParsedHooks] = []
    agents: list[ParsedAgent] = []
    mcp_configs: list[ParsedMcpConfig] = []

    for component in setup.components:
        parsed: ParsedFile | None = None
        ctype = component.component_type
        if ctype is ComponentType.SKILL:
            parsed = parse_skill(component.path)
            skills.append(parsed)
        elif ctype is ComponentType.COMMAND:
            parsed = parse_command(component.path)
            commands.append(parsed)
        elif ctype is ComponentType.CLAUDE_MD:
            parsed = parse_claude_md(component.path)
            claude_mds.append(parsed)
        elif ctype is ComponentType.HOOKS:
            parsed = parse_hooks(component.path)
            hooks.append(parsed)
        elif ctype is ComponentType.AGENT:
            parsed = parse_agent(component.path)
            agents.append(parsed)
        elif ctype is ComponentType.MCP_CONFIG:
            parsed = parse_mcp_config_file(component.path)
            mcp_configs.append(parsed)
        components.append(replace(component, parsed=parsed) if parsed is not None else component)

    return ParsedSetup(
        setup=setup,
        components=tuple(components),
        skills=tuple(skills),
        commands=tuple(commands),
        claude_mds=tuple(claude_mds),
        hooks=tuple(hooks),
        agents=tuple(agents),
        mcp_configs=tuple(mcp_configs),
    )


__all__ = ["ParsedSetup", "parse_setup"]
