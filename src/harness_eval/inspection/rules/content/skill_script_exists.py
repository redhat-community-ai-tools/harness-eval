from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)
from harness_eval.utils.paths import safe_join

# `${CLAUDE_SKILL_DIR}` and `${CLAUDE_PLUGIN_ROOT}` are substituted by the
# client before the skill body reaches the model, so a path written after one
# of them names a file at a known location. Only the braced form is
# substituted; `$CLAUDE_SKILL_DIR` is left to the shell and is not checked.
_ANCHORED_PATH_RE = re.compile(r"\$\{(CLAUDE_SKILL_DIR|CLAUDE_PLUGIN_ROOT)\}/([\w.@+/-]+)")

# The path goes on into a glob, a placeholder or another variable, so what the
# regex captured is only its literal prefix.
_PATH_CONTINUES = frozenset("*?<{$[")

_TRAILING_PUNCT_RE = re.compile(r"[.,;:]+$")

# Files a skill runs. Data and output files (`state.json`, `report.md`) may be
# written at run time into the skill directory, so their absence is not a fact
# about the repository.
_SCRIPT_EXTENSIONS = frozenset(
    {"py", "sh", "bash", "zsh", "js", "mjs", "cjs", "ts", "rb", "pl", "php", "ps1"}
)

# File names used when a skill explains how to write a skill.
_PLACEHOLDER_STEMS = frozenset(
    {
        "foo",
        "bar",
        "baz",
        "example",
        "sample",
        "placeholder",
        "script",
        "script_name",
        "script-name",
        "my_script",
        "my-script",
        "your_script",
        "your-script",
        "name",
        "file",
        "filename",
    }
)


def _plugin_root(skill_dir: Path, project_root: Path | None) -> Path | None:
    """The nearest ancestor of *skill_dir* that is a plugin root.

    `${CLAUDE_PLUGIN_ROOT}` only has a value for a skill shipped in a plugin.
    For any other skill the location it names cannot be known from the files.
    """
    stop = project_root.resolve() if project_root is not None else None
    current = skill_dir.resolve()
    for _ in range(12):
        if (current / ".claude-plugin" / "plugin.json").is_file():
            return current
        if current == stop or current.parent == current:
            return None
        current = current.parent
    return None


def _resolve(base: Path, rel: str, project_root: Path | None) -> Path | None:
    """Resolve *rel* under *base*, or None when the result cannot be verified.

    `..` may leave the skill directory (a script shared by sibling skills) as
    long as the result stays inside the scanned project. A path that leaves
    the project (a monorepo sibling, a shared plugin directory) is not proven
    missing by its absence here, so it is not checked.
    """
    root = project_root if project_root is not None else base
    try:
        base_from_root = base.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    joined = os.path.normpath(os.path.join(base_from_root.as_posix(), rel))
    if joined == ".." or joined.startswith("../") or os.path.isabs(joined):
        return None
    return safe_join(root, joined)


class SkillScriptExists:
    meta: RuleMeta = RuleMeta(
        id="content/skill-script-exists",
        tier="provisional",
        effect="block",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "A script a skill runs through ${CLAUDE_SKILL_DIR} or ${CLAUDE_PLUGIN_ROOT} must exist"
        ),
        category=RuleCategory.CONTENT,
        messages={
            "missing_script": "Skill runs '{{ref}}' but this file does not exist",
        },
        default_suggestion="Add the script, or fix the path the skill runs.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None or not skill.raw_content:
            return

        skill_dir = Path(skill.dir_path)
        project_root = context.scan_state.get("project_root")
        project_root_path = Path(project_root) if project_root else None
        plugin_root: Path | None = None
        plugin_root_known = False
        checked: set[tuple[str, str]] = set()

        for lineno, line in enumerate(skill.raw_content.split("\n"), 1):
            for match in _ANCHORED_PATH_RE.finditer(line):
                if match.end() < len(line) and line[match.end()] in _PATH_CONTINUES:
                    continue
                variable = match.group(1)
                rel = _TRAILING_PUNCT_RE.sub("", match.group(2))
                name = PurePosixPath(rel).name
                stem, _, extension = name.rpartition(".")
                if extension.lower() not in _SCRIPT_EXTENSIONS:
                    continue
                if stem.lower() in _PLACEHOLDER_STEMS:
                    continue
                if (variable, rel) in checked:
                    continue
                checked.add((variable, rel))

                if variable == "CLAUDE_SKILL_DIR":
                    base: Path | None = skill_dir
                else:
                    if not plugin_root_known:
                        plugin_root = _plugin_root(skill_dir, project_root_path)
                        plugin_root_known = True
                    base = plugin_root
                if base is None:
                    continue

                resolved = _resolve(base, rel, project_root_path)
                if resolved is None or resolved.exists():
                    continue

                context.report(
                    ReportDescriptor(
                        message_id="missing_script",
                        data={"ref": f"${{{variable}}}/{rel}"},
                        location=Location(file=skill.skill_md_path, start_line=lineno),
                    )
                )
