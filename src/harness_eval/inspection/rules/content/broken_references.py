from __future__ import annotations

import re
from pathlib import Path
from typing import Any

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
_DIR_REF_PATTERN = re.compile(r"(?<![\w./])(?:scripts|references|assets)/[\w./-]+")

_VERSION_RE = re.compile(r"^\d+(\.\d+)+$")
_GIT_REF_RE = re.compile(r"(\.\.\.?|@\{|HEAD|upstream|origin|main|master)")
_TEMPLATE_VAR_RE = re.compile(r"\$\{|\$[A-Z_][A-Z0-9_]*|<[a-z_-]+>|\{\{")
_GLOB_RE = re.compile(r"[*?]")
_COMMAND_RE = re.compile(r"^(git|bash|uv|npm|curl|grep|tail|mv|cat|echo|find|sed|awk)\s")
_PLACEHOLDER_RE = re.compile(r"[A-Z]{3,4}[A-Z0-9]*-")
_GLOB_DIR_RE = re.compile(r"^([^*?{]+?)(?:/\*\*?.*)?$")

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


_TRAILING_PUNCT_RE = re.compile(r"[.,;:!?)]+$")
_NON_ASCII_SEGMENT_RE = re.compile(r"[^\x00-\x7f]")
_ANTI_PATTERN_LINE_RE = re.compile(r"(?i)\banti-pattern\b")
_EXAMPLE_MARKER_RE = re.compile(r"(?i)(?:e\.g\.|(?:for example|pattern in|such as)\b)")
_DATE_PLACEHOLDER_RE = re.compile(r"YYYY|MM-DD|<[^>]+>")
_PLACEHOLDER_NAMES = frozenset({"url", "path", "file", "filename", "name"})


def _strip_trailing_punctuation(ref: str) -> str:
    return _TRAILING_PUNCT_RE.sub("", ref)


def _is_not_a_file_ref(ref: str) -> bool:
    if "=" in ref:
        return True
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
    if ref.endswith("/") or ref.endswith("-"):
        return True
    if ref.lower() in _PLACEHOLDER_NAMES:
        return True
    if _DATE_PLACEHOLDER_RE.search(ref):
        return True
    if _PLACEHOLDER_RE.match(ref):
        return True
    if any(_NON_ASCII_SEGMENT_RE.search(seg) for seg in ref.split("/")):
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


def _paths_base_dirs(frontmatter: dict[str, Any]) -> list[str]:
    """Extract base directories from a skill's paths frontmatter field."""
    raw = frontmatter.get("paths")
    if not raw:
        return []
    entries = [raw] if isinstance(raw, str) else list(raw)
    dirs: list[str] = []
    for entry in entries:
        m = _GLOB_DIR_RE.match(entry.strip())
        if m:
            base = m.group(1).rstrip("/")
            if base and base != ".":
                dirs.append(base)
    return dirs


def _exists_under_path_bases(project_root: Path, bases: list[str], ref: str) -> bool:
    """True if *ref* exists anywhere under a skill's `paths` bases.

    Domain-knowledge skills name files relative to a package (`config/config.py`
    under `paths: global_utils/**`), not relative to the skill directory.
    """
    if not bases or ".." in Path(ref).parts or ref.startswith("/"):
        return False
    for d in bases:
        base = project_root / d
        if not base.is_dir():
            continue
        try:
            for match in base.rglob(ref):
                if match.is_file() or match.is_dir():
                    return True
        except OSError:
            continue
    return False


def _absolute_outside_project(ref: str, project_root: Path | None) -> bool:
    path = Path(ref)
    if not path.is_absolute():
        return False
    if project_root is None:
        return True
    try:
        path.resolve().relative_to(project_root.resolve())
    except ValueError:
        return True
    return False


class BrokenReferences:
    meta: RuleMeta = RuleMeta(
        id="content/broken-references",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description="File references in skill content must point to existing files",
        category=RuleCategory.CONTENT,
        messages={
            "broken_ref": "Referenced file '{{ref}}' does not exist",
        },
        default_suggestion="Fix or remove the broken file reference.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
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
            if _ANTI_PATTERN_LINE_RE.search(line):
                continue

            example_marker = _EXAMPLE_MARKER_RE.search(line)

            refs_on_line: list[str] = []
            for match in _MD_LINK_PATTERN.finditer(line):
                refs_on_line.append(match.group(1).strip())
            line_without_md_links = _MD_LINK_PATTERN.sub("", line)
            for match in _BACKTICK_PATH_PATTERN.finditer(line):
                if example_marker is not None and match.start() >= example_marker.start():
                    continue
                refs_on_line.append(match.group(1).strip())
            for match in _DIR_REF_PATTERN.finditer(line_without_md_links):
                refs_on_line.append(match.group(0).strip())

            for raw_ref in refs_on_line:
                if raw_ref.startswith(("http://", "https://", "#", "mailto:")):
                    continue
                ref = _strip_trailing_punctuation(raw_ref)
                if not ref:
                    continue
                if _is_not_a_file_ref(ref):
                    continue
                if _absolute_outside_project(ref, project_root_path):
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

                    paths_dirs = _paths_base_dirs(skill.frontmatter)
                    if any(
                        (p := safe_join(project_root_path / d, ref)) is not None and p.exists()
                        for d in paths_dirs
                    ):
                        continue
                    if _exists_under_path_bases(project_root_path, paths_dirs, ref):
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
