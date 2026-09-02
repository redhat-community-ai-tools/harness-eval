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


class HooksValidStructure:
    meta = RuleMeta(
        id="hooks/valid-structure",
        tier="gating",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Flag hook definitions that have no command, which the runtime ignores",
        category=RuleCategory.STRUCTURAL,
        messages={
            "missing_command": "Hook for event '{{event}}' has no command defined",
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Add a 'command' field to the hook definition.",
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None:
            return

        for hook in hooks_data.hooks:
            event = hook.get("event", "unknown")
            command = hook.get("command", "")
            if not command:
                context.report(
                    ReportDescriptor(
                        message_id="missing_command",
                        data={"event": event},
                        location=Location(file=hooks_data.file_path),
                    )
                )
