from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.content._skill_refs import extract_references
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


def _find_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    visited: set[str] = set()
    on_stack: set[str] = set()
    cycles: list[list[str]] = []
    path: list[str] = []

    def dfs(node: str) -> None:
        visited.add(node)
        on_stack.add(node)
        path.append(node)

        for neighbor in graph.get(node, set()):
            if neighbor not in graph:
                continue
            if neighbor not in visited:
                dfs(neighbor)
            elif neighbor in on_stack:
                cycle_start = path.index(neighbor)
                cycle = path[cycle_start:] + [neighbor]
                cycles.append(cycle)

        path.pop()
        on_stack.discard(node)

    for node in graph:
        if node not in visited:
            dfs(node)

    return cycles


class CircularReferences:
    meta = RuleMeta(
        id="content/circular-references",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect circular reference chains between skills and commands",
        category=RuleCategory.CONTENT,
        messages={
            "cycle": "Circular reference detected: {{cycle}}",
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Break the circular reference chain by removing one link.",
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("circular_refs_checked"):
            return
        context.scan_state["circular_refs_checked"] = True

        graph: dict[str, set[str]] = {}
        file_map: dict[str, str] = {}

        for skill in context.all_skills:
            if skill.body:
                refs = extract_references(skill.body, skill.dir_name)
                graph[skill.dir_name] = refs
                file_map[skill.dir_name] = skill.skill_md_path

        for cmd in context.all_commands:
            if cmd.body:
                refs = extract_references(cmd.body, cmd.dir_name)
                graph[cmd.dir_name] = refs
                file_map[cmd.dir_name] = cmd.command_md_path

        seen_cycles: set[str] = set()
        for cycle in _find_cycles(graph):
            key = " -> ".join(sorted(set(cycle[:-1])))
            if key in seen_cycles:
                continue
            seen_cycles.add(key)

            first = cycle[0]
            context.report(
                ReportDescriptor(
                    message_id="cycle",
                    data={"cycle": " -> ".join(cycle)},
                    location=Location(file=file_map.get(first, ""), start_line=1),
                )
            )
