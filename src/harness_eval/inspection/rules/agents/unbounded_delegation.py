"""Flag agent instructions that spawn subagents or delegate without recursion bounds."""

from __future__ import annotations

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.security._shared import (
    extract_content_and_path,
    scan_lines_for_patterns,
)
from harness_eval.inspection.rules.security.unbounded_delegation import DELEGATION_PATTERNS
from harness_eval.inspection.types import (
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class AgentUnboundedDelegation:
    meta = RuleMeta(
        id="agent/unbounded-delegation",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Agent instructions spawn subagents or delegate without recursion bounds",
        category=RuleCategory.SECURITY,
        messages={
            "unbounded": (
                "Line {{line}} contains '{{label}}'."
                " Unbounded agent delegation risks cascading failures."
            ),
            "unbounded_in_code_block": (
                "Line {{line}} contains '{{label}}' inside a code block (likely safe)."
            ),
            "unbounded_in_example": (
                "Line {{line}} contains '{{label}}' in a quote or example (likely safe)."
            ),
        },
        target_type=ComponentType.AGENT,
        frameworks={"owasp_agentic": "ASI08"},
        default_suggestion="Add a recursion depth limit to the delegation chain.",
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
            DELEGATION_PATTERNS,
            detected_msg="unbounded",
            code_block_msg="unbounded_in_code_block",
            example_msg="unbounded_in_example",
        )
