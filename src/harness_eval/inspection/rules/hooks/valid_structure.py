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
            "missing_command": "Hook for event '{{event}}' has no command or other valid handler defined",
            "invalid_version": "Copilot hook files require top-level version: 1",
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Add a 'command' field to the hook definition.",
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None:
            return

        if context.source_tool == "copilot":
            import json

            try:
                root = json.loads(hooks_data.raw_content)
            except (json.JSONDecodeError, ValueError):
                root = {}
            if isinstance(root, dict) and root.get("version") != 1:
                context.report(
                    ReportDescriptor(
                        message_id="invalid_version",
                        location=Location(file=hooks_data.file_path),
                    )
                )

        for hook in hooks_data.hooks:
            event = hook.get("event", "unknown")
            command = hook.get("command", "")
            handler_type = hook.get("type")
            valid_non_command = context.source_tool == "copilot" and (
                (handler_type == "http" and isinstance(hook.get("url"), str))
                or (handler_type == "prompt" and isinstance(hook.get("prompt"), str))
            )
            if not command and not valid_non_command:
                context.report(
                    ReportDescriptor(
                        message_id="missing_command",
                        data={"event": event},
                        location=Location(file=hooks_data.file_path),
                    )
                )
