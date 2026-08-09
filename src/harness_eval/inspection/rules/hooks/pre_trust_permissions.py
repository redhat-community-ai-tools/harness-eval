from __future__ import annotations

import json

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class HooksPreTrustPermissions:
    meta = RuleMeta(
        id="hooks/pre-trust-permissions",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag project-scoped settings that define permissions.allow or hooks. "
            "These are read before the user trusts the project (CVE-2025-59536, "
            "GHSA-ph6w-f82w-28w6)."
        ),
        category=RuleCategory.SECURITY,
        messages={
            "pre_trust_allow": (
                "Project-scoped settings define 'permissions.allow' entries, which "
                "auto-approve tool calls. Combined with hooks, this can enable code "
                "execution before the user reviews the project. Review carefully or "
                "move to user-scoped settings."
            ),
            "pre_trust_hooks": (
                "Project-scoped settings define hooks that execute on events like "
                "SessionStart. A malicious repo can run code when the project is "
                "opened (CVE-2025-59536). Review hook commands carefully."
            ),
        },
        target_type=ComponentType.HOOKS,
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

        loc = Location(file=hooks_data.file_path)

        permissions = data.get("permissions", {})
        if isinstance(permissions, dict):
            allow = permissions.get("allow", [])
            if isinstance(allow, list) and len(allow) > 0:
                context.report(
                    ReportDescriptor(
                        message_id="pre_trust_allow",
                        location=loc,
                    )
                )

        hooks = data.get("hooks", {})
        if isinstance(hooks, dict) and hooks:
            context.report(
                ReportDescriptor(
                    message_id="pre_trust_hooks",
                    location=loc,
                )
            )
