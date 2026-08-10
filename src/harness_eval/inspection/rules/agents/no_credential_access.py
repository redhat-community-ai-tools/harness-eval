from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.security._shared import (
    extract_content_and_path,
    scan_lines_for_credential_patterns,
)
from harness_eval.inspection.rules.security.no_credential_access import (
    _DANGEROUS_COMMANDS,
    _SENSITIVE_ENV_VARS,
    _SENSITIVE_PATHS,
)
from harness_eval.inspection.types import (
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class AgentNoCredentialAccess:
    meta: RuleMeta = RuleMeta(
        id="agent/no-credential-access",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Agent definition should not reference sensitive file paths or environment variables",
        category=RuleCategory.SECURITY,
        messages={
            "sensitive_path": "References sensitive path '{{match}}' at line {{line}}",
            "sensitive_env": "References sensitive environment variable '{{match}}' at line {{line}}",
            "dangerous_command": "Contains dangerous command '{{match}}' at line {{line}}",
        },
        target_type=ComponentType.AGENT,
        frameworks={"owasp_llm": "LLM06", "owasp_agentic": "AG05"},
        default_suggestion="Remove direct credential access from the agent instructions.",
    )

    def create(self, context: RuleContext) -> None:
        result = extract_content_and_path(context, ComponentType.AGENT)
        if result is None:
            return
        content, file_path = result
        scan_lines_for_credential_patterns(
            content,
            file_path,
            context,
            [
                ("sensitive_path", _SENSITIVE_PATHS),
                ("sensitive_env", _SENSITIVE_ENV_VARS),
                ("dangerous_command", _DANGEROUS_COMMANDS),
            ],
            code_block_msg="skip",
        )
