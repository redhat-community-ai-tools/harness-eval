"""Flag instructions that spawn subagents or delegate without recursion bounds."""

from __future__ import annotations

import re

from harness_eval.inspection.rules.security._shared import (
    extract_all_skill_md_content,
    scan_lines_for_patterns,
)
from harness_eval.inspection.types import (
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

DELEGATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("spawn agent", re.compile(r"\b(spawn|launch|create)\b[^.!?\n]*\bagent\b", re.I)),
    ("Agent tool", re.compile(r"\bAgent\s+tool\b")),
    ("delegate to subagent", re.compile(r"\bdelegate\b[^.!?\n]*\b(sub)?agent\b", re.I)),
    ("fork agent", re.compile(r"\bfork\b[^.!?\n]*\bagent\b", re.I)),
    ("fan-out agents", re.compile(r"\bfan.?out\b[^.!?\n]*\bagent", re.I)),
]


class UnboundedDelegation:
    meta = RuleMeta(
        id="security/unbounded-delegation",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Instructions spawn subagents or delegate without recursion bounds",
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
        frameworks={"owasp_agentic": "ASI08"},
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            scan_lines_for_patterns(
                content,
                file_path,
                context,
                DELEGATION_PATTERNS,
                detected_msg="unbounded",
                code_block_msg="unbounded_in_code_block",
                example_msg="unbounded_in_example",
            )
