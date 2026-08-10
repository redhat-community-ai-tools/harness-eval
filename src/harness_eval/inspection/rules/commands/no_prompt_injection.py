from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.security._shared import (
    extract_content_and_path,
    scan_lines_for_patterns,
)
from harness_eval.inspection.rules.security.no_prompt_injection import _INJECTION_PATTERNS
from harness_eval.inspection.types import (
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class CommandNoPromptInjection:
    meta: RuleMeta = RuleMeta(
        id="command/no-prompt-injection",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Command definition should not contain prompt injection patterns",
        category=RuleCategory.SECURITY,
        messages={
            "injection_detected": "Line {{line}} contains a word pattern ('{{label}}') that could be used to manipulate the AI assistant. Check if this is intentional content or an actual risk.",
            "injection_in_code_block": "Line {{line}} contains '{{label}}' inside a code block — likely safe (documentation or example).",
            "injection_in_example": "Line {{line}} contains '{{label}}' in a quote or example — likely safe.",
        },
        target_type=ComponentType.COMMAND,
        frameworks={"owasp_llm": "LLM01", "mitre_atlas": "AML.T0051"},
        default_suggestion="Remove or rephrase the flagged text.",
    )

    def create(self, context: RuleContext) -> None:
        result = extract_content_and_path(context, ComponentType.COMMAND)
        if result is None:
            return
        content, file_path = result
        scan_lines_for_patterns(
            content,
            file_path,
            context,
            _INJECTION_PATTERNS,
            detected_msg="injection_detected",
            code_block_msg="injection_in_code_block",
            example_msg="injection_in_example",
        )
