"""Flag agent instructions that persist data across sessions without scoping constraints."""

from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.security._shared import (
    extract_content_and_path,
    scan_lines_for_patterns,
)
from harness_eval.inspection.rules.security.memory_write_unscoped import MEMORY_PATTERNS
from harness_eval.inspection.types import (
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class AgentMemoryWriteUnscoped:
    meta = RuleMeta(
        id="agent/memory-write-unscoped",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Agent instructions persist data across sessions without scoping constraints",
        category=RuleCategory.SECURITY,
        messages={
            "memory_unscoped": (
                "Line {{line}} contains '{{label}}'."
                " Unscoped memory writes risk cross-session data poisoning."
            ),
            "memory_in_code_block": (
                "Line {{line}} contains '{{label}}' inside a code block (likely safe)."
            ),
            "memory_in_example": (
                "Line {{line}} contains '{{label}}' in a quote or example (likely safe)."
            ),
        },
        target_type=ComponentType.AGENT,
        frameworks={"owasp_agentic": "ASI06"},
        default_suggestion="Scope memory writes to a specific namespace or session.",
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
            MEMORY_PATTERNS,
            detected_msg="memory_unscoped",
            code_block_msg="memory_in_code_block",
            example_msg="memory_in_example",
        )
