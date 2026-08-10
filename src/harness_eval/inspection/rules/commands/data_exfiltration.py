from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.security._shared import (
    extract_content_and_path,
    scan_lines_for_patterns,
)
from harness_eval.inspection.rules.security.data_exfiltration import _EXFIL_PATTERNS
from harness_eval.inspection.types import (
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class CommandDataExfiltration:
    meta: RuleMeta = RuleMeta(
        id="command/data-exfiltration",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Command definition should not contain data exfiltration patterns",
        category=RuleCategory.SECURITY,
        messages={
            "exfil_detected": "Line {{line}} contains a data exfiltration pattern ('{{label}}'). This is a critical security risk.",
            "exfil_in_code_block": "Line {{line}} contains '{{label}}' inside a code block (likely safe).",
        },
        target_type=ComponentType.COMMAND,
        frameworks={"owasp_llm": "LLM06", "owasp_agentic": "AG04"},
        default_suggestion="Remove the network call or credential access from the command.",
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
            _EXFIL_PATTERNS,
            detected_msg="exfil_detected",
            code_block_msg="exfil_in_code_block",
        )
