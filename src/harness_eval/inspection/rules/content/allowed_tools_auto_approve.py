from __future__ import annotations

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_HIGH_RISK = {"bash", "bash(*)"}
_MEDIUM_RISK = {"write", "edit", "notebookedit"}


class AllowedToolsAutoApprove:
    meta = RuleMeta(
        id="content/allowed-tools-auto-approve",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag allowed-tools entries that auto-approve dangerous tools. "
            "allowed-tools removes the human confirmation prompt; it widens "
            "the blast radius, not narrows it."
        ),
        category=RuleCategory.SECURITY,
        messages={
            "auto_approve_high": (
                "allowed-tools includes '{{tool}}', which auto-approves shell "
                "execution without user confirmation. This is not a sandbox; it "
                "removes the safety prompt."
            ),
            "auto_approve_medium": (
                "allowed-tools includes '{{tool}}', which auto-approves file "
                "writes without user confirmation."
            ),
        },
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.frontmatter:
            return

        allowed = skill.frontmatter.get("allowed-tools")
        if not allowed or not isinstance(allowed, list):
            return

        loc = Location(file=skill.skill_md_path)

        for tool in allowed:
            if not isinstance(tool, str):
                continue
            tool_lower = tool.lower().strip()

            if tool_lower in _HIGH_RISK or tool_lower.startswith("bash("):
                context.report(
                    ReportDescriptor(
                        message_id="auto_approve_high",
                        data={"tool": tool},
                        location=loc,
                        severity_override=Severity.WARNING,
                    )
                )
            elif tool_lower in _MEDIUM_RISK:
                context.report(
                    ReportDescriptor(
                        message_id="auto_approve_medium",
                        data={"tool": tool},
                        location=loc,
                    )
                )
