from __future__ import annotations

import json
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

_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sudo\b", re.I), "privilege escalation (sudo)"),
    (re.compile(r"\bsu\b", re.I), "privilege escalation (su)"),
    (re.compile(r"chmod\s+777\b"), "world-writable permissions (chmod 777)"),
    (re.compile(r"\bshred\b", re.I), "destructive filesystem (shred)"),
    (re.compile(r"\bmkfs\b", re.I), "destructive filesystem (mkfs)"),
    (re.compile(r"\bdd\b.*\bof=", re.I), "raw disk write (dd)"),
    (re.compile(r"crontab\b", re.I), "persistence mechanism (crontab)"),
    (re.compile(r"launchctl\b", re.I), "persistence mechanism (launchctl)"),
    (re.compile(r"systemctl\s+enable\b", re.I), "persistence mechanism (systemctl enable)"),
    (re.compile(r"curl.*\|\s*(?:ba)?sh\b", re.I), "piped remote execution (curl|sh)"),
    (re.compile(r"wget.*\|\s*(?:ba)?sh\b", re.I), "piped remote execution (wget|sh)"),
    (re.compile(r"terraform\s+destroy\b", re.I), "infrastructure destruction (terraform destroy)"),
    (re.compile(r"kubectl\s+delete\b", re.I), "infrastructure destruction (kubectl delete)"),
]


class HooksDangerousPermissionGrant:
    meta = RuleMeta(
        id="security/dangerous-permission-grant",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Flag permissions.allow entries that grant access to destructive, "
            "privilege-escalating, or persistence-creating command patterns."
        ),
        category=RuleCategory.SECURITY,
        messages={
            "dangerous_grant": (
                "permissions.allow grants '{{entry}}': {{label}}. "
                "This auto-approves a dangerous operation without user confirmation."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Remove the entry from permissions.allow or narrow the pattern.",
    )

    def create(self, context: RuleContext) -> None:
        hooks_data = context.hooks
        if hooks_data is None:
            return

        raw = hooks_data.raw_content
        if not raw or not raw.strip():
            return

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(data, dict):
            return

        permissions = data.get("permissions", {})
        if not isinstance(permissions, dict):
            return

        allow = permissions.get("allow", [])
        if not isinstance(allow, list):
            return

        loc = Location(file=hooks_data.file_path)

        for entry in allow:
            if not isinstance(entry, str):
                continue
            for pattern, label in _DANGEROUS_PATTERNS:
                if pattern.search(entry):
                    context.report(
                        ReportDescriptor(
                            message_id="dangerous_grant",
                            data={"entry": entry, "label": label},
                            location=loc,
                        )
                    )
                    break
