from __future__ import annotations

import re
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.paths import safe_join


class HooksScriptBoundary:
    meta = RuleMeta(
        id="hooks/script-boundary",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Hook scripts must resolve within the project directory",
        category=RuleCategory.SECURITY,
        messages={
            "outside_project": (
                "Hook for event '{{event}}' references script '{{script}}' "
                "that resolves outside the project directory"
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Move the hook script inside the project directory.",
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None:
            return

        project_root = Path(hooks_data.file_path).parent.parent
        loc = Location(file=hooks_data.file_path)

        for hook in hooks_data.hooks:
            event = hook.get("event", "unknown")
            command = hook.get("command", "")
            if not command:
                continue

            script_match = re.search(r"[\w./-]+\.(?:py|sh|bash)\b", command)
            if not script_match:
                continue

            script_ref = script_match.group(0)
            if Path(script_ref).is_absolute():
                context.report(
                    ReportDescriptor(
                        message_id="outside_project",
                        data={"event": event, "script": script_ref},
                        location=loc,
                    )
                )
                continue

            if safe_join(project_root, script_ref) is None:
                context.report(
                    ReportDescriptor(
                        message_id="outside_project",
                        data={"event": event, "script": script_ref},
                        location=loc,
                    )
                )
