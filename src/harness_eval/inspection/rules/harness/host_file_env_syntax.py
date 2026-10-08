"""A host file delivered as a ``.env`` file is sourced by the sandbox shell
(fullsend: ``for f in .env.d/*.env; do . "$f"; done``). A line that is not a
``KEY=value`` assignment or a comment is then executed as a command or aborts
the sourcing, so the agent starts without the variables that follow it."""

from __future__ import annotations

import re

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.paths import safe_join

_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=")


def malformed_env_lines(text: str) -> list[tuple[int, str]]:
    """(line number, line) for every line that is neither blank, a comment,
    an assignment, nor the continuation of a quoted value."""
    bad: list[tuple[int, str]] = []
    open_quote: str | None = None
    for i, line in enumerate(text.splitlines(), start=1):
        if open_quote is not None:
            if line.count(open_quote) % 2 == 1:
                open_quote = None
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not _ASSIGNMENT_RE.match(line):
            bad.append((i, stripped))
            continue
        value = line.split("=", 1)[1]
        for q in ('"', "'"):
            if value.count(q) % 2 == 1:
                open_quote = q
                break
    return bad


class HarnessHostFileEnvSyntax:
    meta = RuleMeta(
        id="harness/host-file-env-syntax",
        tier="provisional",
        effect="block",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "A host file delivered as a .env file must contain only KEY=value assignments "
            "and comments; the sandbox sources it with the shell"
        ),
        category=RuleCategory.STRUCTURAL,
        messages={
            "malformed_line": (
                "Host file '{{src}}' line {{line}} is not a KEY=value assignment: '{{text}}'. "
                "The sandbox sources .env files with the shell, so this line runs as a command "
                "or stops the sourcing."
            ),
        },
        target_type=ComponentType.HARNESS,
        default_suggestion="Make every line a KEY=value assignment or a # comment.",
    )

    def create(self, context: RuleContext) -> None:
        harness = context.harness
        if harness is None or harness.fields is None:
            return
        f = harness.fields
        seen: set[str] = set()
        for ref in f.refs:
            if "host_files[" not in ref.field or not ref.value.endswith(".env"):
                continue
            if ref.value in seen:
                continue
            seen.add(ref.value)
            target = safe_join(f.root_dir, ref.value)
            if target is None or not target.is_file():
                continue
            try:
                text = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, text_line in malformed_env_lines(text)[:5]:
                context.report(
                    ReportDescriptor(
                        message_id="malformed_line",
                        data={"src": ref.value, "line": line_no, "text": text_line[:80]},
                        location=Location(file=str(target), start_line=line_no),
                    )
                )
