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

_DANGEROUS_PATTERNS = [
    (re.compile(r"\brm\s+-rf\b"), "rm -rf"),
    (re.compile(r"\bgit\s+push\s+--force\b"), "git push --force"),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "git reset --hard"),
    (re.compile(r"\bcurl\b.*\|\s*(?:bash|sh)\b"), "curl pipe to shell"),
    (re.compile(r"\bwget\b.*\|\s*(?:bash|sh)\b"), "wget pipe to shell"),
]


class HooksValidStructure:
    meta = RuleMeta(
        id="hooks/valid-structure",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Validate hook definitions for structure and dangerous patterns",
        category=RuleCategory.SECURITY,
        messages={
            "missing_command": "Hook for event '{{event}}' has no command defined",
            "dangerous_pattern": "Hook for event '{{event}}' contains dangerous pattern: '{{pattern}}'",
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
            loc = Location(file=hooks_data.file_path)

            if not command:
                context.report(
                    ReportDescriptor(
                        message_id="missing_command",
                        data={"event": event},
                        location=loc,
                    )
                )
                continue

            for pattern, label in _DANGEROUS_PATTERNS:
                if pattern.search(command):
                    context.report(
                        ReportDescriptor(
                            message_id="dangerous_pattern",
                            data={"event": event, "pattern": label},
                            location=loc,
                        )
                    )
