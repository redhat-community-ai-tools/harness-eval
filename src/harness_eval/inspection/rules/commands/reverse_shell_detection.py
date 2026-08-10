from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.security._shared import (
    extract_content_and_path,
    scan_lines_for_patterns,
)
from harness_eval.inspection.rules.security.reverse_shell_detection import (
    _REVERSE_SHELL_PATTERNS,
)
from harness_eval.inspection.types import (
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class CommandReverseShellDetection:
    meta: RuleMeta = RuleMeta(
        id="command/reverse-shell",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Command definition should not contain reverse shell patterns",
        category=RuleCategory.SECURITY,
        messages={
            "shell_detected": "Line {{line}} contains a reverse shell pattern ('{{label}}'). This is a critical security risk.",
            "shell_in_code_block": "Line {{line}} contains '{{label}}' inside a code block (likely safe).",
        },
        target_type=ComponentType.COMMAND,
        frameworks={"owasp_agentic": "AG04", "mitre_atlas": "AML.T0054"},
        default_suggestion="Remove the reverse shell pattern from the command.",
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
            _REVERSE_SHELL_PATTERNS,
            detected_msg="shell_detected",
            code_block_msg="shell_in_code_block",
        )
