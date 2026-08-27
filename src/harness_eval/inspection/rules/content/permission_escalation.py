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


class PermissionEscalation:
    meta = RuleMeta(
        id="content/permission-escalation",
        scope="SETUP",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Skills should not gain capabilities through transitive references",
        category=RuleCategory.CONTENT,
        messages={
            "escalation": (
                "Skill '{{source}}' references '{{target}}' which has"
                " '{{tool}}' access that '{{source}}' does not"
                " -- potential transitive escalation"
            ),
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Add the required tool to the source skill or remove the reference.",
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("permission_escalation_checked"):
            return
        context.scan_state["permission_escalation_checked"] = True

        all_skills = context.all_skills
        if len(all_skills) < 2:
            return

        # Build maps: skill name -> allowed tools, skill name -> references
        tools_map: dict[str, list[str]] = {}
        refs_map: dict[str, set[str]] = {}
        file_map: dict[str, str] = {}
        skill_names: set[str] = set()

        for skill in all_skills:
            name = skill.dir_name
            skill_names.add(name)
            allowed_tools = skill.frontmatter.get("allowed-tools", [])
            if isinstance(allowed_tools, list):
                tools_map[name] = allowed_tools
            else:
                tools_map[name] = []
            file_map[name] = skill.skill_md_path

            if skill.body:
                refs_map[name] = extract_references(skill.body, name)
            else:
                refs_map[name] = set()

        # Check for escalation: skill A references skill B, and B has tool X
        # that A does NOT have — B escalates A's privileges transitively
        reported: set[tuple[str, str, str]] = set()
        for source in skill_names:
            source_tools = tools_map.get(source, [])
            for target in refs_map.get(source, set()):
                if target not in skill_names:
                    continue
                target_tools = tools_map.get(target, [])
                for tool in target_tools:
                    if tool not in source_tools:
                        key = (source, tool, target)
                        if key in reported:
                            continue
                        reported.add(key)
                        context.report(
                            ReportDescriptor(
                                message_id="escalation",
                                data={
                                    "source": source,
                                    "tool": tool,
                                    "target": target,
                                },
                                location=Location(
                                    file=file_map.get(source, ""),
                                    start_line=1,
                                ),
                            )
                        )
