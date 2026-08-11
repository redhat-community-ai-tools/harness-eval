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

_OBSERVABILITY_KEYS = [
    "OTEL_EXPORTER",
    "OTEL_SERVICE_NAME",
    "OTEL_TRACES_EXPORTER",
    "OTEL_METRICS_EXPORTER",
    "OTEL_LOGS_EXPORTER",
    "CLAUDE_LOG",
    "CLAUDE_TELEMETRY",
]


class HooksNoAuditTrail:
    meta = RuleMeta(
        id="hooks/no-audit-trail",
        default_severity=Severity.INFO,
        fixable=False,
        description=(
            "Flag project settings with no observability or telemetry "
            "configuration. Enterprise environments benefit from logging "
            "agent activity for audit and incident response."
        ),
        category=RuleCategory.CONTENT,
        messages={
            "no_audit": (
                "No telemetry or logging is configured for agent activity. "
                "For enterprise use, consider enabling OpenTelemetry export "
                "or activity logging."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion=(
            "Add OTEL_EXPORTER_OTLP_ENDPOINT to the env section of settings.json "
            "to export agent activity to your observability stack."
        ),
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

        env = data.get("env", {})
        if not isinstance(env, dict):
            env = {}

        for key in env:
            upper = key.upper()
            for obs_key in _OBSERVABILITY_KEYS:
                if obs_key in upper:
                    return

        context.report(
            ReportDescriptor(
                message_id="no_audit",
                location=Location(file=hooks_data.file_path),
            )
        )
