from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.security._shared import (
    extract_component_texts,
)
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

# Every component type whose body the model reads as instructions. The same
# hidden-text tricks work in all of them: a SKILL.md, a slash command, an agent
# definition, or the instruction file itself (CLAUDE.md, AGENTS.md, Cursor
# rules, Copilot instructions). Pillar Security's "Rules File Backdoor" (March
# 2025) hid its payload in Cursor and Copilot rule files, not in a skill.
_INSTRUCTION_TARGETS = (
    ComponentType.SKILL,
    ComponentType.COMMAND,
    ComponentType.AGENT,
    ComponentType.CLAUDE_MD,
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

# Zero-width joiner and non-joiner have legitimate uses: emoji sequences
# (U+200D between emoji) and Persian, Arabic or Indic text (U+200C between
# letters). Exempt plausible joining contexts, not every non-ASCII context:
# isolated runs between spaces can themselves encode hidden text.
_CONTEXT_SENSITIVE_ZERO_WIDTH = {"\u200c", "\u200d"}

# Unicode "tag" characters (U+E0001, U+E0020..U+E007F) are invisible copies of
# ASCII. Text written in them is not rendered but is read by the model: the
# "ASCII smuggling" vector Pillar's Rules File Backdoor research referenced.
_TAG_CHAR_LOW = 0xE0020
_TAG_CHAR_HIGH = 0xE007F
# The three RGI emoji tag sequences in Unicode UTS #51. Remove only these
# exact sequences from tag inspection; adjacent or malformed tags remain.
_TAG_FLAGS_RE = re.compile(
    "|".join(
        re.escape("\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in code) + "\U000e007f")
        for code in ("gbeng", "gbsct", "gbwls")
    )
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9_Ѐ-ӿͰ-Ͽ]+")


def _emoji_base(char: str) -> bool:
    return bool(char) and (0x1F000 <= ord(char) <= 0x1FAFF or 0x2600 <= ord(char) <= 0x27BF)


def _joining_context(line: str, idx: int, char: str) -> bool:
    before = line[idx - 1] if idx else ""
    after = line[idx + 1] if idx + 1 < len(line) else ""
    if not before or not after:
        return False
    if char == "\u200d":
        left = idx - 1
        while left >= 0 and (
            line[left] in {"\ufe0e", "\ufe0f"} or 0x1F3FB <= ord(line[left]) <= 0x1F3FF
        ):
            left -= 1
        if left >= 0 and _emoji_base(line[left]) and _emoji_base(after):
            return True
    # Virama followed by a consonant is a normal Indic joining context.
    if unicodedata.combining(before) == 9 and after.isalpha() and not after.isascii():
        return True
    left, right = idx - 1, idx + 1
    while left >= 0 and unicodedata.category(line[left]).startswith("M"):
        left -= 1
    while right < len(line) and unicodedata.category(line[right]).startswith("M"):
        right += 1
    if left < 0 or right >= len(line):
        return False
    before, after = line[left], line[right]
    if not before.isalpha() or not after.isalpha():
        return False
    for script in ("ARABIC", "SYRIAC", "NKO", "MANDAIC", "MONGOLIAN"):
        if all(unicodedata.name(c, "").startswith(script + " ") for c in (before, after)):
            return True
    return False


def _has_unexplained_joiner(char: str, line: str) -> bool:
    """Report if any occurrence lacks a plausible typographic context."""
    start = 0
    while (idx := line.find(char, start)) != -1:
        if not _joining_context(line, idx, char):
            return True
        start = idx + 1
    return False


def _tag_chars(line: str) -> list[str]:
    text = _TAG_FLAGS_RE.sub("", line)
    return [c for c in text if ord(c) == 0xE0001 or _TAG_CHAR_LOW <= ord(c) <= _TAG_CHAR_HIGH]


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
        effect="signal",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Detect hidden instructions, invisible or deceptive Unicode, and "
            "suspicious embedded content in skills, commands, agents and "
            "instruction files (CLAUDE.md, AGENTS.md, Cursor rules, Copilot instructions)"
        ),
        category=RuleCategory.SECURITY,
        messages={
            "mcp_hidden_instruction": "Line {{line}}: {{label}}. Hidden instructions can manipulate agent behavior.",
            "mcp_unicode_deception": "Line {{line}}: contains {{label}} (U+{{codepoint}}). Unicode deception can disguise malicious content as benign.",
            "mcp_suspicious_default": "Line {{line}}: {{label}}. Suspicious content pattern detected.",
        },
        frameworks={"owasp_llm": "LLM05", "owasp_agentic": "AG03"},
        default_suggestion=(
            "Open the file in an editor that shows invisible characters and remove "
            "the hidden text, or reject the change. If the file came from a "
            "third-party skill or MCP server, pin its version and review it."
        ),
        target_type=_INSTRUCTION_TARGETS,
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_component_texts(context):
            self._scan_content(context, content, file_path)

    def _scan_content(self, context: RuleContext, content: str, file_path: str) -> None:
        # A byte-order mark at the very start of a file is an editor artifact,
        # not hidden text. Everywhere else U+FEFF is a zero-width no-break
        # space and stays reportable.
        if content.startswith("\ufeff"):
            content = content[1:]
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
                if char not in line:
                    continue
                if char in _CONTEXT_SENSITIVE_ZERO_WIDTH and not _has_unexplained_joiner(
                    char, line
                ):
                    continue
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

            tag_chars = _tag_chars(line)
            if tag_chars:
                context.report(
                    ReportDescriptor(
                        message_id="mcp_unicode_deception",
                        data={
                            "label": (
                                f"{len(tag_chars)} invisible Unicode tag character(s) "
                                "(ASCII smuggling)"
                            ),
                            "codepoint": f"{ord(tag_chars[0]):04X}",
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
