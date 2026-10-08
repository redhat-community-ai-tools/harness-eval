from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import TYPE_CHECKING

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

if TYPE_CHECKING:
    from harness_eval.inspection.types import ParsedSkill


class DuplicateSkillId:
    meta = RuleMeta(
        id="cross/duplicate-skill-id",
        tier="provisional",
        effect="block",
        scope="SETUP",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect ambiguous duplicate skill IDs across supported discovery roots",
        category=RuleCategory.CROSS_COMPONENT,
        messages={
            "divergent": (
                "Skill ID '{{skill}}' resolves to {{count}} different SKILL.md files with different"
                " content; client search order can select different instructions"
            ),
            "identical": (
                "Skill ID '{{skill}}' is duplicated in {{count}} discovery roots with identical content"
            ),
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Keep one canonical skill ID or give client-specific variants unique names.",
    )

    def create(self, context: RuleContext) -> None:
        if not context.artifacts.mark_once("duplicate_skill_id_checked"):
            return
        groups: dict[str, list[ParsedSkill]] = defaultdict(list)
        for skill in context.all_skills:
            groups[skill.dir_name].append(skill)
        for skill_id, skills in groups.items():
            paths = {skill.skill_md_path for skill in skills}
            if len(paths) < 2:
                continue
            digests = {
                hashlib.sha256(skill.raw_content.encode("utf-8", errors="replace")).hexdigest()
                for skill in skills
            }
            message_id = "identical" if len(digests) == 1 else "divergent"
            context.report(
                ReportDescriptor(
                    message_id=message_id,
                    data={"skill": skill_id, "count": len(paths)},
                    location=Location(file=skills[0].skill_md_path, start_line=1),
                    severity_override=Severity.INFO if message_id == "identical" else None,
                )
            )
