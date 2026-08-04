from __future__ import annotations

import re
from pathlib import Path

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.paths import safe_join

_MD_LINK_PATTERN = re.compile(r"\[.*?\]\(([^)]+)\)")
_BACKTICK_PATH_PATTERN = re.compile(r"`([^`]*/[^`]+\.\w{1,5})`")
_DIR_REF_PATTERN = re.compile(r"(?:scripts|references|assets)/[\w./-]+")

_VERSION_RE = re.compile(r"^\d+(\.\d+)+$")
_GIT_REF_RE = re.compile(r"(\.\.\.?|@\{|HEAD|upstream|origin|main|master)")
_TEMPLATE_VAR_RE = re.compile(r"\$\{|\$[A-Z_][A-Z0-9_]*|<[a-z_-]+>|\{\{")
_GLOB_RE = re.compile(r"[*?]")
_COMMAND_RE = re.compile(r"^(git|bash|uv|npm|curl|grep|tail|mv|cat|echo|find|sed|awk)\s")
_PLACEHOLDER_RE = re.compile(r"[A-Z]{3,4}[A-Z0-9]*-")
_KNOWN_EXTENSIONS = frozenset(
    {
        "py",
        "sh",
        "js",
        "ts",
        "go",
        "rs",
        "java",
        "rb",
        "c",
        "h",
        "cpp",
        "md",
        "txt",
        "yml",
        "yaml",
        "json",
        "toml",
        "cfg",
        "ini",
        "env",
        "html",
        "css",
        "sql",
        "xml",
        "csv",
        "log",
        "conf",
        "lock",
        "mdc",
        "jsx",
        "tsx",
        "vue",
        "svelte",
    }
)


def _is_not_a_file_ref(ref: str) -> bool:
    if _VERSION_RE.match(ref):
        return True
    if _GIT_REF_RE.search(ref):
        return True
    if _TEMPLATE_VAR_RE.search(ref):
        return True
    if _GLOB_RE.search(ref):
        return True
    if _COMMAND_RE.match(ref):
        return True
    if " " in ref and not ref.startswith(("scripts/", "references/", "assets/")):
        return True
    if ref.startswith("~"):
        return True
    if _PLACEHOLDER_RE.match(ref):
        return True
    ext = ref.rsplit(".", 1)[-1].lower() if "." in ref else ""
    return bool(ext and ext not in _KNOWN_EXTENSIONS)


def _fenced_lines(lines: list[str]) -> set[int]:
    """Return set of line indices that are inside fenced code blocks."""
    fenced: set[int] = set()
    in_fence = False
    for i, line in enumerate(lines):
        if line.strip().startswith("```"):
            in_fence = not in_fence
        elif in_fence:
            fenced.add(i)
    return fenced


class BrokenReferences:
    meta: RuleMeta = RuleMeta(
        id="content/broken-references",
        default_severity=Severity.ERROR,
        fixable=False,
        description="File references in skill content must point to existing files",
        category=RuleCategory.CONTENT,
        messages={
            "broken_ref": "Referenced file '{{ref}}' does not exist",
        },
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.body:
            return

        skill_dir = Path(skill.dir_path)
        project_root = context.scan_state.get("project_root")
        project_root_path = Path(project_root) if project_root else None

        lines = skill.body.split("\n")
        fenced = _fenced_lines(lines)
        checked: set[str] = set()

        for i, line in enumerate(lines):
            if i in fenced:
                continue

            refs_on_line: list[str] = []
            for match in _MD_LINK_PATTERN.finditer(line):
                refs_on_line.append(match.group(1).strip())
            line_without_md_links = _MD_LINK_PATTERN.sub("", line)
            for match in _BACKTICK_PATH_PATTERN.finditer(line_without_md_links):
                refs_on_line.append(match.group(1).strip())
            for match in _DIR_REF_PATTERN.finditer(line_without_md_links):
                refs_on_line.append(match.group(0).strip())

            for ref in refs_on_line:
                if ref.startswith(("http://", "https://", "#", "mailto:")):
                    continue
                if _is_not_a_file_ref(ref):
                    continue
                if ref in checked:
                    continue
                checked.add(ref)

                ref_path = safe_join(skill_dir, ref)
                if ref_path is not None and ref_path.exists():
                    continue

                scripts_path = safe_join(skill_dir / "scripts", ref)
                if scripts_path is not None and scripts_path.exists():
                    continue

                if project_root_path:
                    root_path = safe_join(project_root_path, ref)
                    if root_path is not None and root_path.exists():
                        continue
                    if ".." in ref:
                        resolved = (skill_dir / ref).resolve()
                        root_resolved = project_root_path.resolve()
                        if str(resolved).startswith(str(root_resolved)) and resolved.exists():
                            continue

                context.report(
                    ReportDescriptor(
                        message_id="broken_ref",
                        data={"ref": ref},
                        location=Location(
                            file=skill.skill_md_path,
                            start_line=skill.body_start_line + i,
                        ),
                    )
                )
