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

_DANGEROUS_PATTERNS = [
    (re.compile(r"\brm\s+-rf\b"), "rm -rf", None),
    (re.compile(r"\bgit\s+push\s+--force\b"), "git push --force", None),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "git reset --hard", None),
    (re.compile(r"\bcurl\b.*\|\s*(?:bash|sh)\b"), "curl pipe to shell", "curl"),
    (re.compile(r"\bwget\b.*\|\s*(?:bash|sh)\b"), "wget pipe to shell", "wget"),
    (re.compile(r"\bcurl\b"), "network access (curl)", "curl"),
    (re.compile(r"\bwget\b"), "network access (wget)", "wget"),
    (re.compile(r"\bnc\s+-"), "network access (netcat)", None),
    (re.compile(r"\bncat\b"), "network access (ncat)", None),
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
            "script_missing": "Hook for event '{{event}}' references script '{{script}}' which does not exist",
        },
        target_type=ComponentType.HOOKS,
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

            matched_groups: set[str] = set()
            for pattern, label, group in _DANGEROUS_PATTERNS:
                if group and group in matched_groups:
                    continue
                if pattern.search(command):
                    if group:
                        matched_groups.add(group)
                    context.report(
                        ReportDescriptor(
                            message_id="dangerous_pattern",
                            data={"event": event, "pattern": label},
                            location=loc,
                        )
                    )

            script_match = re.search(r"[\w./-]+\.(?:py|sh|bash)\b", command)
            if script_match:
                script_path = Path(script_match.group(0))
                if not script_path.is_absolute():
                    project_root = Path(hooks_data.file_path).parent.parent
                    if not (project_root / script_path).exists():
                        context.report(
                            ReportDescriptor(
                                message_id="script_missing",
                                data={"event": event, "script": str(script_path)},
                                location=loc,
                            )
                        )
