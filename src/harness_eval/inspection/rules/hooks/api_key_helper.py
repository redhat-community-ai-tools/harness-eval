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


class HooksApiKeyHelper:
    meta = RuleMeta(
        id="hooks/api-key-helper",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Flag project-scoped settings defining apiKeyHelper. "
            "A repo-controlled helper can intercept or exfiltrate API keys."
        ),
        category=RuleCategory.SECURITY,
        messages={
            "api_key_helper": (
                "Project-scoped settings define 'apiKeyHelper'. This lets the repo "
                "control how API keys are resolved, enabling interception or "
                "exfiltration. Remove from project config; configure in user-scoped "
                "settings only."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Move apiKeyHelper to user-scoped settings.",
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

        if "apiKeyHelper" in data:
            context.report(
                ReportDescriptor(
                    message_id="api_key_helper",
                    location=Location(file=hooks_data.file_path),
                )
            )
