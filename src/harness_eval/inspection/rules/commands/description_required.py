from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class CommandDescriptionRequired:
    meta = RuleMeta(
        id="command/description-required",
        tier="gating",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Commands must have a description in frontmatter for the UI menu",
        category=RuleCategory.FRONTMATTER,
        messages={
            "missing": "Command is missing 'description' in frontmatter — it won't show properly in the UI menu",
        },
        target_type=ComponentType.COMMAND,
        default_suggestion="Add a 'description' field to the command frontmatter.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.command
        if cmd is None or cmd.parse_errors:
            return

        desc = cmd.frontmatter.get("description", "")
        loc = Location(file=cmd.command_md_path, start_line=1)

        if not desc:
            context.report(ReportDescriptor(message_id="missing", location=loc))


class CommandDescriptionQuality:
    meta = RuleMeta(
        id="command/description-quality",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Command descriptions should say what the command does in more than two words",
        category=RuleCategory.FRONTMATTER,
        messages={
            "too_vague": "Description '{{desc}}' is too short or vague — should clearly say what the command does",
        },
        target_type=ComponentType.COMMAND,
        default_suggestion="Expand the description so it says what the command does.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.command
        if cmd is None or cmd.parse_errors:
            return

        desc = cmd.frontmatter.get("description", "")
        if not isinstance(desc, str) or not desc.strip():
            return
        if len(desc.split()) <= 2:
            context.report(
                ReportDescriptor(
                    message_id="too_vague",
                    data={"desc": desc},
                    location=Location(file=cmd.command_md_path, start_line=1),
                )
            )
