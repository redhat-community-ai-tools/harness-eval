from __future__ import annotations

import re

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_SKILL_REF_PATTERNS = [
    re.compile(
        r"(?:invokes?|calls?|triggers?|runs?|uses?)\s+(?:the\s+)?(?:skill\s+)?[\"'`/](\w[\w-]{2,})[\"'`]?",
        re.IGNORECASE,
    ),
    re.compile(r"(?:^|\s)/(\w[\w-]{2,})(?:\s|$|[),.\]])", re.IGNORECASE | re.MULTILINE),
]


class CommandReferencesNonexistentSkill:
    meta = RuleMeta(
        id="command/references-nonexistent-skill",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect commands that reference skills which do not exist",
        category=RuleCategory.CONTENT,
        messages={
            "missing_skill": "Command '{{command}}' references skill '{{skill}}' but no SKILL.md found for it",
        },
        target_type=ComponentType.COMMAND,
        default_suggestion="Create the missing skill or remove the reference.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.command
        if cmd is None or not cmd.body or not context.all_skills:
            return

        known_skills = {s.dir_name for s in context.all_skills}
        referenced: set[str] = set()

        for pattern in _SKILL_REF_PATTERNS:
            for match in pattern.finditer(cmd.body):
                name = match.group(1)
                if name != cmd.dir_name and len(name) > 1:
                    referenced.add(name)

        for skill_name in referenced:
            if skill_name not in known_skills:
                context.report(
                    ReportDescriptor(
                        message_id="missing_skill",
                        data={"command": cmd.dir_name, "skill": skill_name},
                        location=Location(file=cmd.command_md_path, start_line=1),
                    )
                )
