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

_COERCIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "forced compliance",
        re.compile(r"\b(?:you\s+must|must\s+always)\s+(?:comply|obey|follow)\b", re.I),
    ),
    (
        "refusal suppression",
        re.compile(r"\b(?:never|do\s+not|don'?t)\s+(?:refuse|decline|reject)\b", re.I),
    ),
    (
        "unconditional obedience",
        re.compile(r"\balways\s+(?:obey|comply\s+with|follow)\s+(?:all|any|every)\b", re.I),
    ),
    (
        "safety override directive",
        re.compile(
            r"\b(?:override|disable|turn\s+off)\s+(?:safety|guard|filter|restriction)s?\b", re.I
        ),
    ),
    (
        "restriction removal",
        re.compile(
            r"\b(?:remove|lift|drop)\s+(?:all\s+)?(?:restrictions?|limitations?|constraints?)\b",
            re.I,
        ),
    ),
]


class CoerciveOverride:
    meta = RuleMeta(
        id="security/coercive-override",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect patterns forcing the agent to comply unconditionally",
        category=RuleCategory.SECURITY,
        messages={
            "coercive_detected": "Line {{line}} contains a coercive override pattern ('{{label}}'). This undermines the agent's safety behavior.",
            "coercive_in_code_block": "Line {{line}} contains '{{label}}' inside a code block (likely safe).",
            "coercive_in_example": "Line {{line}} contains '{{label}}' in a quote or example (likely safe).",
        },
        frameworks={"owasp_llm": "LLM01", "owasp_agentic": "AG01"},
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            scan_lines_for_patterns(
                content,
                file_path,
                context,
                _COERCIVE_PATTERNS,
                detected_msg="coercive_detected",
                code_block_msg="coercive_in_code_block",
                example_msg="coercive_in_example",
            )
