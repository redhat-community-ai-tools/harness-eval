"""Per-format mappers from a harness file into the normalized harness model.

A harness format is identified by the discoverer's ``source_tool``. Each
mapper turns the parsed YAML mapping of one file into ``HarnessFields``;
rules only ever see the normalized model, so adding a format means adding a
mapper (and a discoverer), not rules.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class HarnessHostFile:
    src: str
    dest: str
    optional: bool = False
    expand: bool = False


@dataclass(frozen=True)
class HarnessRef:
    """A path-typed field of a harness, as written, with where it came from."""

    field: str
    value: str
    # Checked as a directory (skills, plugins, agent_input) rather than a file.
    directory: bool = False
    # The runtime tolerates a missing target (optional host files). Never reported.
    optional: bool = False


@dataclass
class HarnessFields:
    """Format-neutral view of one harness definition."""

    root_dir: Path
    # True when the tree at root_dir is a complete scaffold rather than one
    # layer of a composed configuration (an overlay or an org config layer
    # whose references are satisfied by other layers at dispatch time).
    # Path-existence checks are only decidable when this is True.
    layer_complete: bool = False
    instructions: str | None = None
    model: str | None = None
    policy: str | None = None
    scripts: dict[str, str] = field(default_factory=dict)
    skills: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    host_files: list[HarnessHostFile] = field(default_factory=list)
    output_schema: str | None = None
    output_file: str | None = None
    env: dict[str, dict[str, str]] = field(default_factory=dict)
    base: str | None = None
    agent_input: str | None = None
    runtime_fetch: bool = False
    platform_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Every path-typed reference in declaration order, after format-specific
    # normalization (for fullsend: ``${FULLSEND_DIR}/x`` becomes ``x``).
    refs: list[HarnessRef] = field(default_factory=list)
    # Strings whose presence in the agent's instructions prove it was told
    # about the output contract (the output file name, the schema name, the
    # environment variables or helper tool the runtime exposes for it). Empty
    # when the harness declares no output contract.
    output_contract_tokens: list[str] = field(default_factory=list)
    # Root-level instruction files the runtime gives every agent, relative to
    # root_dir, in addition to ``instructions`` and the listed skills.
    shared_instruction_files: list[str] = field(default_factory=list)


Mapper = Callable[[dict[str, Any], Path], HarnessFields]

_MAPPERS: dict[str, Mapper] = {}


def register_mapper(source_tool: str, mapper: Mapper) -> None:
    _MAPPERS[source_tool] = mapper


def mapper_for(source_tool: str | None) -> Mapper | None:
    if not _MAPPERS:
        # Built-in formats register on first use.
        from harness_eval.inspection.harness_formats import fullsend  # noqa: F401

    return _MAPPERS.get(source_tool or "")


__all__ = [
    "HarnessFields",
    "HarnessHostFile",
    "HarnessRef",
    "Mapper",
    "mapper_for",
    "register_mapper",
]
