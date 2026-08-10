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

_SENSITIVE_VAR = r"\$\w*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|PRIVATE)\w*"

_ENV_LEAK_PATTERNS = [
    (
        re.compile(rf"\b(?:echo|printf)\s+.*{_SENSITIVE_VAR}", re.IGNORECASE),
        "echo/printf with sensitive env var",
    ),
    (re.compile(r"\bprintenv\b"), "printenv"),
    (re.compile(r"\benv\s*\|\s*grep\b"), "env | grep"),
    (re.compile(r"\bset\s*\|\s*grep\b"), "set | grep"),
]


class HooksEnvLeakage:
    meta = RuleMeta(
        id="hooks/env-leakage",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Flag hooks that may leak environment variables",
        category=RuleCategory.SECURITY,
        messages={
            "env_leakage": "Hook for event '{{event}}' may leak environment variables: '{{pattern}}'",
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Remove env var printing or redirect output away from the agent.",
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

            for pattern, label in _ENV_LEAK_PATTERNS:
                if pattern.search(command):
                    context.report(
                        ReportDescriptor(
                            message_id="env_leakage",
                            data={"event": event, "pattern": label},
                            location=loc,
                        )
                    )
                    break
