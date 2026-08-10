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

_BASE_URL_PATTERN = re.compile(
    r"(?:ANTHROPIC|OPENAI|GOOGLE|AZURE_OPENAI)_BASE_URL\b",
    re.IGNORECASE,
)

_BASE_URL_EXACT = re.compile(
    r"^(?:ANTHROPIC|OPENAI|GOOGLE|AZURE_OPENAI)_BASE_URL$",
    re.IGNORECASE,
)


class HooksBaseUrlOverride:
    meta = RuleMeta(
        id="hooks/base-url-override",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Flag project-scoped settings that override LLM provider base URLs. "
            "CVE-2026-21852: malicious ANTHROPIC_BASE_URL redirected API traffic "
            "and exfiltrated the API key."
        ),
        category=RuleCategory.SECURITY,
        messages={
            "base_url_override": (
                "Project-scoped settings override '{{var}}'. A malicious repo can "
                "redirect API traffic to an attacker-controlled server and capture "
                "API keys (CVE-2026-21852). Remove this from project config; set it "
                "in user-scoped settings or environment instead."
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

        reported_vars: set[str] = set()

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            data = None

        if isinstance(data, dict):
            env = data.get("env", {})
            if isinstance(env, dict):
                for key in env:
                    if _BASE_URL_EXACT.match(key):
                        context.report(
                            ReportDescriptor(
                                message_id="base_url_override",
                                data={"var": key},
                                location=Location(file=hooks_data.file_path),
                            )
                        )
                        reported_vars.add(key.upper())

        for line_num, line in enumerate(raw.split("\n"), 1):
            m = _BASE_URL_PATTERN.search(line)
            if m:
                var = m.group(0)
                if var.upper() not in reported_vars:
                    context.report(
                        ReportDescriptor(
                            message_id="base_url_override",
                            data={"var": var},
                            location=Location(file=hooks_data.file_path, start_line=line_num),
                        )
                    )
                    reported_vars.add(var.upper())
