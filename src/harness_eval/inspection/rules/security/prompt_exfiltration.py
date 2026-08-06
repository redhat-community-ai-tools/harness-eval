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

_EXFIL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "output system prompt",
        re.compile(
            r"(?:output|print|display|show|share)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|configuration)\b",
            re.I,
        ),
    ),
    (
        "include instructions in output",
        re.compile(
            r"include\s+(?:your|the)\s+(?:instructions|rules|constraints)\s+in\s+(?:the\s+)?(?:output|response)\b",
            re.I,
        ),
    ),
    (
        "leak config file",
        re.compile(
            r"(?:print|output|include|share|send)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:CLAUDE|GEMINI|AGENTS)\.md\b",
            re.I,
        ),
    ),
    (
        "leak config file (read with exfil intent)",
        re.compile(
            r"(?:read|cat)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:CLAUDE|GEMINI|AGENTS)\.md\b.*(?:to\s+the\s+user|in\s+(?:your|the)\s+(?:response|output))",
            re.I,
        ),
    ),
    (
        "expose tool list",
        re.compile(
            r"(?:list|reveal|show|output)\s+(?:all\s+)?(?:your\s+)?(?:available\s+)?(?:tools|skills|commands|capabilities)\s+(?:to|in)\s+(?:the\s+)?(?:user|output|response)\b",
            re.I,
        ),
    ),
]


class PromptExfiltration:
    meta = RuleMeta(
        id="security/prompt-exfiltration",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect instructions that leak system prompts or configuration to outputs",
        category=RuleCategory.SECURITY,
        messages={
            "exfil_detected": "Line {{line}} contains a prompt exfiltration pattern ('{{label}}'). System instructions should not be exposed in outputs.",
            "exfil_in_code_block": "Line {{line}} contains '{{label}}' inside a code block (likely safe).",
            "exfil_in_example": "Line {{line}} contains '{{label}}' in a quote or example (likely safe).",
            "exfil_negated": "Line {{line}} contains '{{label}}' preceded by negation (likely a restriction, not exfiltration).",
        },
        frameworks={"owasp_llm": "LLM07"},
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            scan_lines_for_patterns(
                content,
                file_path,
                context,
                _EXFIL_PATTERNS,
                detected_msg="exfil_detected",
                code_block_msg="exfil_in_code_block",
                example_msg="exfil_in_example",
                negation_msg="exfil_negated",
            )
