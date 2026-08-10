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

_NETWORK_PATTERNS = [
    (re.compile(r"\bcurl\b"), "curl"),
    (re.compile(r"\bwget\b"), "wget"),
    (re.compile(r"\b(?:nc|netcat)\b"), "netcat"),
]


class HooksNetworkAccess:
    meta = RuleMeta(
        id="hooks/network-access",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Flag hooks that make network calls",
        category=RuleCategory.SECURITY,
        messages={
            "network_access": "Hook for event '{{event}}' makes a network call: '{{pattern}}'",
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Remove the network call or move it to a user-approved script.",
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

            for pattern, label in _NETWORK_PATTERNS:
                if pattern.search(command):
                    context.report(
                        ReportDescriptor(
                            message_id="network_access",
                            data={"event": event, "pattern": label},
                            location=loc,
                        )
                    )
                    break
