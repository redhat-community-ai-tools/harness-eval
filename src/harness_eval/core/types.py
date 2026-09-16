"""Core types for harness-eval."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness_eval.inspection.types import ParsedFile


class ComponentType(StrEnum):
    SKILL = "skill"
    COMMAND = "command"
    CLAUDE_MD = "claude_md"
    HOOKS = "hooks"
    AGENT = "agent"
    MCP_CONFIG = "mcp_config"
    RULE = "rule"
    OUTPUT_STYLE = "output_style"
    UNCATEGORIZED = "uncategorized"


class ComponentScope(StrEnum):
    PROJECT = "project"
    USER_GLOBAL = "user_global"
    USER_PROJECT = "user_project"


class ScanLimitExceeded(ValueError):
    """Raised when a setup exceeds configured resource limits."""


@dataclass(frozen=True)
class ScanLimits:
    """Resource limits applied to the files a scan will read.

    Only files in the discoverer inventory (instruction files, skills,
    commands, hooks, agents, MCP configs) count toward these limits; unrelated
    repository content such as build outputs or datasets never does.
    """

    max_file_bytes: int = 10_000_000
    max_total_bytes: int = 250_000_000
    max_files: int = 100_000
    max_depth: int = 50


@dataclass(frozen=True)
class ParsedComponent:
    """A parsed component with its raw content and metadata."""

    component_type: ComponentType
    name: str
    path: str
    content: str
    frontmatter: dict[str, object] | None = None
    token_count: int = 0
    scope: ComponentScope = ComponentScope.PROJECT
    source_tool: str | None = None
    # Type-specific parsed payload attached by ``inspection.setup.parse_setup``.
    # Discovery never sets it; keeping it on the canonical component means
    # discovery and inspection share one component identity.
    parsed: ParsedFile | None = None


@dataclass(frozen=True)
class Setup:
    """A complete agent setup discovered from a directory."""

    name: str
    path: str
    fingerprint: str
    components: list[ParsedComponent] = field(default_factory=list)
    total_tokens: int = 0
    detected_tools: tuple[str, ...] = ()

    def by_type(self, component_type: ComponentType) -> list[ParsedComponent]:
        return [c for c in self.components if c.component_type == component_type]
