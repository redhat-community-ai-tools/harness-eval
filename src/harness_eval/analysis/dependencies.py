"""Dependency mapping: which components reference which, and are any broken?"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from harness_eval.core.types import ComponentType, Setup


@dataclass
class DependencyEdge:
    """A reference from one component to another."""

    source_type: str
    source_name: str
    target_type: str
    target_name: str
    exists: bool


@dataclass
class DependencyReport:
    """Dependency analysis results."""

    edges: list[DependencyEdge] = field(default_factory=list)
    broken_refs: list[DependencyEdge] = field(default_factory=list)
    orphan_components: list[str] = field(default_factory=list)


_SKILL_REF_PATTERNS = [
    re.compile(r"skills?[/\\](\w[\w-]*)"),
    re.compile(r"/(\w[\w-]*)\s+skill"),
    re.compile(r"skill\s+['\"](\w[\w-]*)['\"]"),
]


def analyze_dependencies(setup: Setup) -> DependencyReport:
    """Map dependencies between components and find broken references."""
    known_skills = {c.name for c in setup.by_type(ComponentType.SKILL)}
    known_commands = {c.name for c in setup.by_type(ComponentType.COMMAND)}
    all_known = known_skills | known_commands

    edges: list[DependencyEdge] = []

    for comp in setup.by_type(ComponentType.AGENT):
        if comp.frontmatter:
            referenced = comp.frontmatter.get("skills", []) or []
            if isinstance(referenced, str):
                referenced = [s.strip() for s in referenced.split(",")]
            for skill_name in referenced:
                if not skill_name:
                    continue
                exists = skill_name in known_skills
                edges.append(
                    DependencyEdge(
                        source_type="agent",
                        source_name=comp.name,
                        target_type="skill",
                        target_name=skill_name,
                        exists=exists,
                    )
                )

    for comp in setup.components:
        if comp.component_type in (ComponentType.MCP_CONFIG, ComponentType.HOOKS):
            continue
        for pattern in _SKILL_REF_PATTERNS:
            for match in pattern.finditer(comp.content):
                ref_name = match.group(1)
                if ref_name in all_known and ref_name != comp.name:
                    edges.append(
                        DependencyEdge(
                            source_type=comp.component_type.value,
                            source_name=comp.name,
                            target_type="skill" if ref_name in known_skills else "command",
                            target_name=ref_name,
                            exists=True,
                        )
                    )

    seen = set()
    deduped: list[DependencyEdge] = []
    for e in edges:
        key = (e.source_type, e.source_name, e.target_type, e.target_name)
        if key not in seen:
            seen.add(key)
            deduped.append(e)

    broken = [e for e in deduped if not e.exists]

    referenced_names = set()
    for e in deduped:
        referenced_names.add(e.target_name)

    orphans = []
    # Skills are activated by description matching, not by explicit references,
    # so an unreferenced skill is not orphaned. Only flag commands and agents.
    orphan_types = (ComponentType.COMMAND, ComponentType.AGENT)
    for comp in setup.components:
        if comp.component_type not in orphan_types:
            continue
        if comp.name not in referenced_names and len(setup.components) > 3:
            orphans.append(f"{comp.component_type.value}/{comp.name}")

    return DependencyReport(
        edges=deduped,
        broken_refs=broken,
        orphan_components=orphans,
    )
