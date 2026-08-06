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

_REVERSE_SHELL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("bash reverse shell", re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/", re.I)),
    ("netcat exec", re.compile(r"\bnc\s+.*-e\s+/bin/", re.I)),
    ("ncat exec", re.compile(r"\bncat\s+.*--exec", re.I)),
    ("python socket shell", re.compile(r"python[23]?\s+-c\s+.*(?:socket|subprocess)", re.I)),
    ("perl socket shell", re.compile(r"perl\s+-e\s+.*(?:socket|Socket)", re.I)),
    ("ruby socket shell", re.compile(r"ruby\s+-rsocket\s+-e", re.I)),
    ("php socket shell", re.compile(r"php\s+-r\s+.*fsockopen", re.I)),
    ("socat exec", re.compile(r"\bsocat\s+.*exec:", re.I)),
    ("named pipe shell", re.compile(r"\bmknod\s+.*\bp\b.*(?:/bin/sh|bash)", re.I)),
    ("named pipe shell (mkfifo)", re.compile(r"\bmkfifo\b.*\bcat\b.*\b(?:sh|bash)\b", re.I)),
    ("powershell reverse shell", re.compile(r"\bpowershell\s+.*(?:Net\.Sockets|TCPClient)", re.I)),
]


class ReverseShellDetection:
    meta: RuleMeta = RuleMeta(
        id="security/reverse-shell",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Skill content should not contain reverse shell patterns",
        category=RuleCategory.SECURITY,
        messages={
            "shell_detected": "Line {{line}} contains a reverse shell pattern ('{{label}}'). This is a critical security risk.",
            "shell_in_code_block": "Line {{line}} contains '{{label}}' inside a code block — likely documentation, but verify.",
        },
        frameworks={"owasp_agentic": "AG04", "mitre_atlas": "AML.T0054"},
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            scan_lines_for_patterns(
                content,
                file_path,
                context,
                _REVERSE_SHELL_PATTERNS,
                detected_msg="shell_detected",
                code_block_msg="shell_in_code_block",
            )
