"""Flag `@path` imports in context files that do not resolve.

Claude Code expands `@path` in CLAUDE.md to the file's contents. A missing
target is skipped silently, so the agent runs without the imported
instructions and nobody is told. Resolution follows the runtime: relative to
the context file's directory, with `~` for the home directory.
"""

from __future__ import annotations

import re
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

# `@path` at line start or after whitespace; not an email, not a decorator in a code fence.
_IMPORT_RE = re.compile(r"(?:^|(?<=\s))@((?:\.{0,2}/|~/)?[\w][\w./-]*)", re.M)
_FENCE_RE = re.compile(r"```.*?```", re.S)


_FILE_EXT = (".md", ".txt", ".mdc", ".markdown", ".rst", ".json", ".yaml", ".yml", ".toml")
_SCOPED_PKG_RE = re.compile(
    r"^[\w-]+/[\w.-]+$"
)  # @scope/name, no extension: an npm package, not a path


def imports_in(text: str) -> list[str]:
    """Return ``@path`` imports the Claude Code runtime would try to load.

    The runtime accepts relative paths (``@docs/x.md``, ``@./x.md``), absolute
    and home paths. Prose is full of other ``@`` tokens that are not imports:
    scoped npm packages (``@scope/pkg``), Python decorators
    (``@app.on_event(...)``), and handles. An import therefore must either
    start with ``./``, ``../``, ``~/`` or ``/``, or name a file with a
    document extension; a bare ``@scope/name`` with no extension is a package.
    """
    text = _FENCE_RE.sub("", text)
    out = []
    for m in _IMPORT_RE.finditer(text):
        ref = m.group(1).rstrip(".,;:)")
        end = m.end()
        if end < len(text) and text[end] == "(":
            continue  # decorator
        if "@" in ref or ref.startswith(("http", "www")):
            continue
        explicit = ref.startswith(("./", "../", "~/"))
        has_ext = ref.lower().endswith(_FILE_EXT)
        if ref.startswith("/") and not has_ext:
            continue  # "@/lib/utils" is a TypeScript path alias, not an import
        if not explicit and not has_ext:
            continue
        if not explicit and _SCOPED_PKG_RE.match(ref) and not has_ext:
            continue
        out.append(ref)
    return out


class ClaudeMdIncludeExists:
    meta = RuleMeta(
        id="claude-md/include-exists",
        tier="gating",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag @path imports in a context file whose target does not exist",
        category=RuleCategory.STRUCTURAL,
        messages={
            "missing": "Import '@{{ref}}' does not resolve (looked for {{resolved}}); the runtime skips it silently."
        },
        target_type=ComponentType.CLAUDE_MD,
        default_suggestion="Fix the path or remove the import.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.claude_md
        if cmd is None or not cmd.raw_content:
            return
        base = Path(cmd.file_path).resolve().parent
        for ref in imports_in(cmd.raw_content):
            target = Path(ref).expanduser() if ref.startswith("~") else (base / ref)
            if ref.startswith("~"):
                continue  # home-relative imports are per-machine by design; not checkable in a clone
            if not target.exists():
                context.report(
                    ReportDescriptor(
                        message_id="missing",
                        data={"ref": ref, "resolved": str(target)},
                        location=Location(file=cmd.file_path),
                    )
                )
