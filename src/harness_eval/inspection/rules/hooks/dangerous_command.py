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
    (re.compile(r"\bchmod\s+777\b"), "chmod 777"),
    (re.compile(r"\bdd\s+if="), "dd if="),
    (re.compile(r"\bmkfs\b"), "mkfs"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "fork bomb"),
    (re.compile(r"\bgit\s+push\s+--force\b"), "git push --force"),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "git reset --hard"),
    (re.compile(r"\bcurl\b.*\|\s*(?:bash|sh)\b"), "curl pipe to shell"),
    (re.compile(r"\bwget\b.*\|\s*(?:bash|sh)\b"), "wget pipe to shell"),
]


class HooksDangerousCommand:
    meta = RuleMeta(
        id="hooks/dangerous-command",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag hooks containing dangerous shell commands",
        category=RuleCategory.SECURITY,
        messages={
            "dangerous_command": "Hook for event '{{event}}' contains dangerous command: '{{pattern}}'",
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Replace the dangerous command with a safer alternative.",
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None:
            return

        for hook in hooks_data.hooks:
            event = hook.get("event", "unknown")
            command = hook.get("command", "")
            if not command:
                continue

            loc = Location(file=hooks_data.file_path)

            for pattern, label in _DANGEROUS_PATTERNS:
                if pattern.search(command):
                    context.report(
                        ReportDescriptor(
                            message_id="dangerous_command",
                            data={"event": event, "pattern": label},
                            location=loc,
                        )
                    )
