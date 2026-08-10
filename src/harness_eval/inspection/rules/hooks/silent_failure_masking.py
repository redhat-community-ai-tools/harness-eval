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

_SUPPRESSION_PATTERNS = [
    (re.compile(r"2>\s*/dev/null"), "stderr redirected to /dev/null"),
    (re.compile(r"\|\|\s*(?:true|:)\s*(?:;|$|&&|\|)"), "|| true (error silently swallowed)"),
    (re.compile(r"\bset\s+\+e\b"), "set +e (errors ignored)"),
    (re.compile(r"\btrap\s+['\"]?\s*['\"]?\s+ERR\b"), "trap '' ERR (error trap cleared)"),
    (re.compile(r"except\s*:\s*(?:pass|\.\.\.)\s*$", re.MULTILINE), "bare except: pass"),
]

_SENSITIVE_OPS = [
    re.compile(r"\bcurl\b|\bwget\b|\bfetch\b"),
    re.compile(r"\bchmod\b|\bchown\b"),
    re.compile(r"\brm\b"),
    re.compile(r"\bgit\s+push\b"),
    re.compile(r"\bsudo\b"),
    re.compile(r"\beval\b"),
]


def _has_sensitive_op(command: str) -> bool:
    return any(p.search(command) for p in _SENSITIVE_OPS)


class HooksSilentFailureMasking:
    meta = RuleMeta(
        id="hooks/silent-failure-masking",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag hooks that silently suppress errors, especially when combined"
            " with security-relevant operations"
        ),
        category=RuleCategory.SECURITY,
        messages={
            "suppression": ("Hook for event '{{event}}' silently suppresses errors: {{pattern}}."),
            "suppression_with_sensitive_op": (
                "Hook for event '{{event}}' silently suppresses errors ({{pattern}})"
                " while performing a security-relevant operation."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Remove error suppression or add explicit error handling.",
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
            sensitive = _has_sensitive_op(command)

            for pattern, label in _SUPPRESSION_PATTERNS:
                if pattern.search(command):
                    msg_id = "suppression_with_sensitive_op" if sensitive else "suppression"
                    context.report(
                        ReportDescriptor(
                            message_id=msg_id,
                            data={"event": event, "pattern": label},
                            location=loc,
                            severity_override=Severity.ERROR if sensitive else None,
                        )
                    )
                    break
