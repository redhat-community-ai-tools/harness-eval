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

_CREDENTIAL_KEY = re.compile(
    r".*(?:_KEY_ID|_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIAL|_PAT)$",
    re.IGNORECASE,
)
_FALSE_POSITIVE = re.compile(r".*_PUBLIC_KEY$", re.IGNORECASE)


class HooksEnvCredentialOverride:
    meta = RuleMeta(
        id="hooks/env-credential-override",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Flag project-scoped settings that set credential-shaped environment "
            "variables. A malicious repo can inject attacker-controlled values for "
            "keys, tokens, or passwords."
        ),
        category=RuleCategory.SECURITY,
        messages={
            "env_credential": (
                "Project-scoped settings set env var '{{var}}' which looks like a "
                "credential. A cloned repo should not control credential values. "
                "Set credentials in user-scoped settings or environment instead."
            ),
        },
        target_type=ComponentType.HOOKS,
        default_suggestion="Move credential env vars to user-scoped settings or shell profile.",
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
            return

        for key in env:
            if _CREDENTIAL_KEY.match(key) and not _FALSE_POSITIVE.match(key):
                context.report(
                    ReportDescriptor(
                        message_id="env_credential",
                        data={"var": key},
                        location=Location(file=hooks_data.file_path),
                    )
                )
