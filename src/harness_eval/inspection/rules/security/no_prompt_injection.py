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

_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "ignore previous instructions",
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    ),
    ("disregard prior", re.compile(r"disregard\s+(all\s+)?(prior|previous|above)", re.I)),
    (
        "you are now (with override)",
        re.compile(r"you\s+are\s+now\s+(?:a|an|the)\s+.*(?:ignore|forget|disregard)", re.I),
    ),
    ("system prompt override", re.compile(r"system\s*prompt\s*(override|injection|change)", re.I)),
    (
        "override instructions",
        re.compile(r"override\s+(all\s+)?(instructions|rules|guidelines)", re.I),
    ),
    ("new instructions", re.compile(r"new\s+instructions?\s*:", re.I)),
    ("jailbreak attempt", re.compile(r"(do\s+anything\s+now|developer\s+mode)", re.I)),
    (
        "prompt leak",
        re.compile(r"(reveal|show|print|output)\s+(your|the)\s+(system\s+)?prompt", re.I),
    ),
    ("role hijack", re.compile(r"forget\s+(everything|all|your)\s+(you|instructions|rules)", re.I)),
    ("hidden instruction", re.compile(r"<\s*(?:system|instruction|hidden)\s*>", re.I)),
    (
        "role play (with override)",
        re.compile(
            r"pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an|the)\s+.*(?:ignore|forget|disregard|override)",
            re.I,
        ),
    ),
    (
        "encoding evasion (pipe to shell)",
        re.compile(r"base64\s+(?:-d|--decode).*?\|\s*(?:bash|sh|eval)", re.I),
    ),
    ("repeat after me", re.compile(r"repeat\s+after\s+me", re.I)),
    (
        "bypass safety",
        re.compile(r"(?:ignore\s+safety|bypass\s+(?:filter|safety|restriction))", re.I),
    ),
    ("output control", re.compile(r"output\s+the\s+following\s+exactly", re.I)),
    (
        "markdown image exfiltration",
        re.compile(r"!\[.*?\]\(https?://[^\)]*[\?&](?:q|query|prompt|input|cmd)=", re.I),
    ),
]


class NoPromptInjection:
    meta: RuleMeta = RuleMeta(
        id="security/no-prompt-injection",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Skill content should not contain prompt injection patterns",
        category=RuleCategory.SECURITY,
        messages={
            "injection_detected": "Line {{line}} contains a word pattern ('{{label}}') that could be used to manipulate the AI assistant. Check if this is intentional content or an actual risk.",
            "injection_in_code_block": "Line {{line}} contains '{{label}}' inside a code block -- likely safe (documentation or example).",
            "injection_in_example": "Line {{line}} contains '{{label}}' in a quote or example -- likely safe.",
            "injection_negated": "Line {{line}} contains '{{label}}' preceded by negation (likely a safety guardrail, not injection).",
        },
        frameworks={"owasp_llm": "LLM01", "mitre_atlas": "AML.T0051"},
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            scan_lines_for_patterns(
                content,
                file_path,
                context,
                _INJECTION_PATTERNS,
                detected_msg="injection_detected",
                code_block_msg="injection_in_code_block",
                example_msg="injection_in_example",
                negation_msg="injection_negated",
            )
