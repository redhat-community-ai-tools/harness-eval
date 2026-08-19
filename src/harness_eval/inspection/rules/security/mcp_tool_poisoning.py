from __future__ import annotations

import math
import re
from collections import Counter

from harness_eval.inspection.rules.security._shared import (
    extract_all_skill_md_content,
)
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_BASE64_RAW_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_PATH_PREFIXES = (  # nosec B108 — detection pattern for suspicious paths, not temp file usage
    "./",
    "../",
    "~/",
    "/home",
    "/usr",
    "/etc",
    "/var",
    "/tmp",
    "/opt",
    "/bin",
)

_ENTROPY_THRESHOLD = 4.5


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_likely_base64(text: str) -> bool:
    if "/" in text or "\\" in text:
        return False
    if any(text.startswith(p) for p in _PATH_PREFIXES):
        return False
    if "." in text and text.count(".") >= 2:
        return False
    return _shannon_entropy(text) >= _ENTROPY_THRESHOLD


_HIDDEN_INSTRUCTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "HTML comment with instruction",
        re.compile(r"<!--\s*(?:system|instruction|ignore|override|you\s+are)", re.I),
    ),
    ("markdown comment", re.compile(r"\[//\]:\s*#\s*\(.*(?:ignore|override|instruction)", re.I)),
    ("base64 blob in text", re.compile(r"data:text/[^;]+;base64,")),
    (
        "data URI with script",
        re.compile(r"data:\s*(?:text/javascript|application/javascript|text/html)", re.I),
    ),
]

_ZERO_WIDTH_CHARS = {
    "​": "zero-width space",
    "‌": "zero-width non-joiner",
    "‍": "zero-width joiner",
    "⁠": "word joiner",
    "﻿": "BOM / zero-width no-break space",
    "­": "soft hyphen",
}

# nosec B613 — bidi chars below are intentional detection signatures for trojan-source attacks
_RTL_OVERRIDE_CHARS = {
    "‪": "LRE",  # nosec B613
    "‫": "RLE",  # nosec B613
    "‬": "PDF",  # nosec B613
    "‭": "LRO",  # nosec B613
    "‮": "RLO",  # nosec B613
    "⁦": "LRI",  # nosec B613
    "⁧": "RLI",  # nosec B613
    "⁨": "FSI",  # nosec B613
    "⁩": "PDI",  # nosec B613
}

_TOKEN_RE = re.compile(r"[A-Za-z0-9_Ѐ-ӿͰ-Ͽ]+")


def _is_mixed_script_token(char: str, line: str) -> bool:
    """Return True if *char* appears in a token that also contains ASCII letters."""
    for m in _TOKEN_RE.finditer(line):
        token = m.group()
        if char in token and re.search(r"[A-Za-z]", token):
            return True
    return False


_HOMOGLYPH_MAP: dict[str, str] = {
    "А": "A (Cyrillic)",
    "В": "B (Cyrillic)",
    "С": "C (Cyrillic)",
    "Е": "E (Cyrillic)",
    "Н": "H (Cyrillic)",
    "К": "K (Cyrillic)",
    "М": "M (Cyrillic)",
    "О": "O (Cyrillic)",
    "Р": "P (Cyrillic)",
    "Т": "T (Cyrillic)",
    "Х": "X (Cyrillic)",
    "а": "a (Cyrillic)",
    "е": "e (Cyrillic)",
    "о": "o (Cyrillic)",
    "р": "p (Cyrillic)",
    "с": "c (Cyrillic)",
    "у": "y (Cyrillic)",
    "х": "x (Cyrillic)",
    "Α": "A (Greek)",
    "Β": "B (Greek)",
    "Ε": "E (Greek)",
    "Η": "H (Greek)",
    "Κ": "K (Greek)",
    "Μ": "M (Greek)",
    "Ο": "O (Greek)",
    "Ρ": "P (Greek)",
    "Τ": "T (Greek)",
    "Χ": "X (Greek)",
    "ο": "o (Greek)",
}


class McpToolPoisoning:
    meta: RuleMeta = RuleMeta(
        id="security/mcp-tool-poisoning",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect hidden instructions, Unicode deception, and suspicious embedded content",
        category=RuleCategory.SECURITY,
        messages={
            "mcp_hidden_instruction": "Line {{line}}: {{label}}. Hidden instructions can manipulate agent behavior.",
            "mcp_unicode_deception": "Line {{line}}: contains {{label}} (U+{{codepoint}}). Unicode deception can disguise malicious content as benign.",
            "mcp_suspicious_default": "Line {{line}}: {{label}}. Suspicious content pattern detected.",
        },
        frameworks={"owasp_llm": "LLM05", "owasp_agentic": "AG03"},
        default_suggestion="Pin the MCP server package and validate its tool descriptions.",
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            self._scan_content(context, content, file_path)

    def _scan_content(self, context: RuleContext, content: str, file_path: str) -> None:
        lines = content.split("\n")

        for i, line in enumerate(lines):
            pattern_matched = False
            for label, pattern in _HIDDEN_INSTRUCTION_PATTERNS:
                if pattern.search(line):
                    context.report(
                        ReportDescriptor(
                            message_id="mcp_hidden_instruction",
                            data={"label": label, "line": str(i + 1)},
                            location=Location(
                                file=file_path,
                                start_line=i + 1,
                            ),
                        )
                    )
                    pattern_matched = True
                    break

            if not pattern_matched:
                m = _BASE64_RAW_RE.search(line)
                if m and _is_likely_base64(m.group()):
                    context.report(
                        ReportDescriptor(
                            message_id="mcp_hidden_instruction",
                            data={"label": "base64 blob in text", "line": str(i + 1)},
                            location=Location(
                                file=file_path,
                                start_line=i + 1,
                            ),
                        )
                    )

            for char, char_name in _ZERO_WIDTH_CHARS.items():
                if char in line:
                    context.report(
                        ReportDescriptor(
                            message_id="mcp_unicode_deception",
                            data={
                                "label": char_name,
                                "codepoint": f"{ord(char):04X}",
                                "line": str(i + 1),
                            },
                            location=Location(
                                file=file_path,
                                start_line=i + 1,
                            ),
                        )
                    )

            for char, char_name in _RTL_OVERRIDE_CHARS.items():
                if char in line:
                    context.report(
                        ReportDescriptor(
                            message_id="mcp_unicode_deception",
                            data={
                                "label": f"RTL override ({char_name})",
                                "codepoint": f"{ord(char):04X}",
                                "line": str(i + 1),
                            },
                            location=Location(
                                file=file_path,
                                start_line=i + 1,
                            ),
                        )
                    )

            for char, char_name in _HOMOGLYPH_MAP.items():
                if char in line and _is_mixed_script_token(char, line):
                    context.report(
                        ReportDescriptor(
                            message_id="mcp_unicode_deception",
                            data={
                                "label": f"homoglyph: looks like {char_name}",
                                "codepoint": f"{ord(char):04X}",
                                "line": str(i + 1),
                            },
                            location=Location(
                                file=file_path,
                                start_line=i + 1,
                            ),
                            severity_override=Severity.WARNING,
                        )
                    )
