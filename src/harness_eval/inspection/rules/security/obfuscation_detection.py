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

_OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "eval with decode",
        re.compile(r"eval\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode)\s*\(", re.I),
    ),
    ("char code construction", re.compile(r"String\.fromCharCode\s*\(", re.I)),
    ("hex escape sequence", re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")),
    ("unicode escape sequence", re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")),
    ("tag characters", re.compile(r"[\U000e0000-\U000e007f]")),
    ("python dynamic exec", re.compile(r"exec\s*\(\s*(?:compile|__import__)\s*\(", re.I)),
    ("char code round-trip", re.compile(r"charCodeAt\b.*\bfromCharCode\b", re.I)),
]


class ObfuscationDetection:
    meta: RuleMeta = RuleMeta(
        id="security/obfuscation",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Skill content should not contain code obfuscation patterns",
        category=RuleCategory.SECURITY,
        messages={
            "obfuscation_detected": "Line {{line}} contains an obfuscation pattern ('{{label}}'). This may hide malicious behavior.",
            "obfuscation_in_code_block": "Line {{line}} contains '{{label}}' inside a code block — likely documentation, but verify.",
        },
        frameworks={"owasp_llm": "LLM02", "mitre_atlas": "AML.T0054"},
        default_suggestion="Replace obfuscated content with plain text.",
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            scan_lines_for_patterns(
                content,
                file_path,
                context,
                _OBFUSCATION_PATTERNS,
                detected_msg="obfuscation_detected",
                code_block_msg="obfuscation_in_code_block",
            )
