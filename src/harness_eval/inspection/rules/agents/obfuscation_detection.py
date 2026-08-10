from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.security._shared import (
    extract_content_and_path,
    scan_lines_for_patterns,
)
from harness_eval.inspection.rules.security.obfuscation_detection import _OBFUSCATION_PATTERNS
from harness_eval.inspection.types import (
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class AgentObfuscationDetection:
    meta: RuleMeta = RuleMeta(
        id="agent/obfuscation",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Agent definition should not contain code obfuscation patterns",
        category=RuleCategory.SECURITY,
        messages={
            "obfuscation_detected": "Line {{line}} contains an obfuscation pattern ('{{label}}'). This may hide malicious behavior.",
            "obfuscation_in_code_block": "Line {{line}} contains '{{label}}' inside a code block (likely safe).",
        },
        target_type=ComponentType.AGENT,
        frameworks={"owasp_llm": "LLM02", "mitre_atlas": "AML.T0054"},
        default_suggestion="Replace obfuscated content with plain text.",
    )

    def create(self, context: RuleContext) -> None:
        result = extract_content_and_path(context, ComponentType.AGENT)
        if result is None:
            return
        content, file_path = result
        scan_lines_for_patterns(
            content,
            file_path,
            context,
            _OBFUSCATION_PATTERNS,
            detected_msg="obfuscation_detected",
            code_block_msg="obfuscation_in_code_block",
        )
