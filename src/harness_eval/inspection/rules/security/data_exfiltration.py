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
    ("curl post file contents", re.compile(r"curl\s+.*-d\s+[\"']?\$\(cat\b", re.I)),
    ("curl with command substitution", re.compile(r"curl\s+.*--data.*\$\(", re.I)),
    ("wget post data", re.compile(r"wget\s+--post-data", re.I)),
    ("dns tunneling dig", re.compile(r"\bdig\s+.*\bTXT\b", re.I)),
    ("dns tunneling nslookup", re.compile(r"\bnslookup\s+.*-type=TXT", re.I)),
    (
        "webhook exfiltration",
        re.compile(r"(?:curl|wget|fetch)\s+.*(?:webhook|hooks\.|pipedream|requestbin|ngrok)", re.I),
    ),
    ("base64 pipe to network", re.compile(r"base64\s+.*\|\s*(?:curl|wget|nc)\b", re.I)),
    ("archive pipe to network", re.compile(r"tar\s+.*\|\s*(?:curl|wget|nc|ssh)\b", re.I)),
]


class DataExfiltration:
    meta: RuleMeta = RuleMeta(
        id="security/data-exfiltration",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Skill content should not contain data exfiltration patterns",
        category=RuleCategory.SECURITY,
        messages={
            "exfil_detected": "Line {{line}} contains a data exfiltration pattern ('{{label}}'). This is a critical security risk.",
            "exfil_in_code_block": "Line {{line}} contains '{{label}}' inside a code block — likely documentation, but verify.",
        },
        frameworks={"owasp_llm": "LLM06", "owasp_agentic": "AG04"},
        default_suggestion="Remove the network call or the credential access from the same component.",
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
            )
