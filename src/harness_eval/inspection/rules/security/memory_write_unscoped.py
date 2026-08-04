"""Flag instructions that persist data across sessions without scoping constraints."""

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

MEMORY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("save to memory", re.compile(r"\b(save|write|store)\b[^.!?\n]*\bmemory\b", re.I)),
    ("persist to memory", re.compile(r"\bpersist\b[^.!?\n]*\bmemory\b", re.I)),
    (
        "cross-session persistence",
        re.compile(r"\bremember\b[^.!?\n]*\bacross\b[^.!?\n]*\bsession", re.I),
    ),
    ("store for later", re.compile(r"\bstore\b[^.!?\n]*\bfor\s+later\b", re.I)),
    (
        "persist between sessions",
        re.compile(r"\bpersist\b[^.!?\n]*\bbetween\b[^.!?\n]*\bsession", re.I),
    ),
    ("scratchpad write", re.compile(r"\b(write|update|save)\b[^.!?\n]*\bscratchpad\b", re.I)),
    ("memory MCP tool", re.compile(r"\bmcp__memory\b", re.I)),
]


class MemoryWriteUnscoped:
    meta = RuleMeta(
        id="security/memory-write-unscoped",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Instructions persist data across sessions without scoping constraints",
        category=RuleCategory.SECURITY,
        messages={
            "memory_unscoped": (
                "Line {{line}} contains '{{label}}'."
                " Unscoped memory writes risk cross-session data poisoning."
            ),
            "memory_in_code_block": (
                "Line {{line}} contains '{{label}}' inside a code block (likely safe)."
            ),
            "memory_in_example": (
                "Line {{line}} contains '{{label}}' in a quote or example (likely safe)."
            ),
        },
        frameworks={"owasp_agentic": "ASI06"},
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            scan_lines_for_patterns(
                content,
                file_path,
                context,
                MEMORY_PATTERNS,
                detected_msg="memory_unscoped",
                code_block_msg="memory_in_code_block",
                example_msg="memory_in_example",
            )
