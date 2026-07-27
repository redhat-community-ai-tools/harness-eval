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

_PERSISTENCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("write to claude config", re.compile(r"(?:write|append|modify|update)\s+.*\.claude/", re.I)),
    ("write to cursor config", re.compile(r"(?:write|append|modify|update)\s+.*\.cursor/", re.I)),
    (
        "modify settings.json",
        re.compile(r"(?:write|append|modify|update)\s+.*settings\.json\b", re.I),
    ),
    (
        "append to instruction file",
        re.compile(r"(?:append|add|inject)\s+.*(?:CLAUDE|GEMINI|AGENTS)\.md\b", re.I),
    ),
    (
        "hidden state file",
        re.compile(r"(?:write|create|save)\s+.*\.(?:cache|state|persist|hidden)\b", re.I),
    ),
    ("modify hook config", re.compile(r"(?:write|modify|update)\s+.*hooks\.json\b", re.I)),
]


class StealthPersistence:
    meta = RuleMeta(
        id="security/stealth-persistence",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect instructions writing to config directories or persistent state",
        category=RuleCategory.SECURITY,
        messages={
            "persist_detected": "Line {{line}} contains a stealth persistence pattern ('{{label}}'). Instructions should not modify agent configuration files.",
            "persist_in_code_block": "Line {{line}} contains '{{label}}' inside a code block (likely safe).",
        },
        frameworks={"owasp_agentic": "AG04", "mitre_atlas": "AML.T0054"},
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            scan_lines_for_patterns(
                content,
                file_path,
                context,
                _PERSISTENCE_PATTERNS,
                detected_msg="persist_detected",
                code_block_msg="persist_in_code_block",
            )
