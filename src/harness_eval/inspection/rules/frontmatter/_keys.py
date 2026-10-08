"""Frontmatter keys each Claude Code component type reads, and the helpers the
near-miss rules share. Only Claude Code is covered: other clients have their
own vocabularies, so the rules stay silent for them."""

from __future__ import annotations

import re

from harness_eval.core.types import ComponentType

# Keys Claude Code documents for each component. A key outside this list is
# not a finding (a client may add keys faster than this file); only a key that
# collapses onto one of these after normalization is.
KNOWN_KEYS: dict[ComponentType, frozenset[str]] = {
    ComponentType.SKILL: frozenset(
        {
            "name",
            "description",
            "license",
            "allowed-tools",
            "compatibility",
            "metadata",
            "version",
            "model",
            "context",
            "agent",
            "argument-hint",
            "user-invocable",
            "disable-model-invocation",
            "hooks",
            "paths",
            "effort",
        }
    ),
    ComponentType.COMMAND: frozenset(
        {
            "name",
            "description",
            "allowed-tools",
            "argument-hint",
            "model",
            "context",
            "agent",
            "disable-model-invocation",
            "hooks",
            "paths",
            "effort",
        }
    ),
    ComponentType.AGENT: frozenset(
        {
            "name",
            "description",
            "tools",
            "disallowedTools",
            "model",
            "permissionMode",
            "skills",
            "hooks",
            "color",
            "memory",
            "maxTurns",
            "mcpServers",
            "isolation",
            "background",
            "effort",
        }
    ),
}

_SEPARATORS = re.compile(r"[-_\s]")


def normalize_key(key: str) -> str:
    """Case- and separator-insensitive form: ``allowed_tools`` -> ``allowedtools``."""
    return _SEPARATORS.sub("", key).lower()


def claude_only(source_tool: str | None) -> bool:
    return source_tool in (None, "claude")


def split_tool_entries(value: object) -> list[str]:
    """Tool entries from a frontmatter value: a space- or comma-delimited string
    (separators inside parentheses do not split: ``Bash(git commit:*)`` is one
    entry), or a list of strings. Anything else yields nothing."""
    if isinstance(value, str):
        return _split_outside_parens(value)
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
        return out
    return []


def _split_outside_parens(text: str) -> list[str]:
    entries: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        if depth == 0 and (ch == "," or ch.isspace()):
            if current:
                entries.append("".join(current))
                current = []
            continue
        current.append(ch)
    if current:
        entries.append("".join(current))
    return entries


def tool_base_name(entry: str) -> str:
    """``Bash(git:*)`` -> ``Bash``."""
    return entry.split("(", 1)[0].strip()
