from __future__ import annotations

import os
import re

from harness_eval.inspection.rules.quality._patterns import (
    TAUTOLOGICAL_PATTERNS,
    has_project_specificity,
)
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_CONFIG_TOOL_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        ".editorconfig",
        "indentation style",
        re.compile(
            r"(?:use|prefer|set)\s+(?:\d[- ]space|tab)\s+indent",
            re.I,
        ),
    ),
    (
        ".editorconfig",
        "trailing whitespace",
        re.compile(r"(?:remove|trim|strip)\s+trailing\s+(?:whitespace|spaces)", re.I),
    ),
    (
        ".editorconfig",
        "final newline",
        re.compile(r"(?:ensure|add|include)\s+(?:a\s+)?final\s+newline", re.I),
    ),
    (
        ".prettierrc",
        "code formatting",
        re.compile(
            r"(?:use|prefer)\s+(?:single|double)\s+quotes",
            re.I,
        ),
    ),
    (
        ".prettierrc",
        "semicolons",
        re.compile(r"(?:always\s+)?(?:use|add|include|omit)\s+semicolons", re.I),
    ),
    (
        ".prettierrc",
        "trailing commas",
        re.compile(r"(?:use|add|include)\s+trailing\s+commas", re.I),
    ),
    (
        ".eslintrc",
        "lint rules",
        re.compile(
            r"(?:no|avoid|don'?t\s+use)\s+(?:var\b|console\.log|unused\s+variables)",
            re.I,
        ),
    ),
    (
        "tsconfig.json",
        "strict mode",
        re.compile(r"(?:enable|use)\s+(?:typescript\s+)?strict\s+mode", re.I),
    ),
    (
        "pyproject.toml",
        "line length",
        re.compile(r"(?:keep|limit|set)\s+(?:line\s+)?length\s+(?:to|at|under)\s+\d+", re.I),
    ),
]

_CONFIG_FILES = {
    ".editorconfig": [".editorconfig"],
    ".prettierrc": [
        ".prettierrc",
        ".prettierrc.json",
        ".prettierrc.yml",
        ".prettierrc.yaml",
        ".prettierrc.js",
        "prettier.config.js",
        "prettier.config.cjs",
    ],
    ".eslintrc": [
        ".eslintrc",
        ".eslintrc.json",
        ".eslintrc.yml",
        ".eslintrc.js",
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.ts",
    ],
    "tsconfig.json": ["tsconfig.json"],
    "pyproject.toml": ["pyproject.toml"],
}


def _find_project_root(skill_path: str) -> str | None:
    path = os.path.dirname(os.path.abspath(skill_path))
    for _ in range(10):
        if os.path.isdir(os.path.join(path, ".git")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return None


def _config_exists(project_root: str, config_key: str) -> bool:
    candidates = _CONFIG_FILES.get(config_key, [])
    return any(os.path.isfile(os.path.join(project_root, c)) for c in candidates)


class RedundantGuidance:
    meta = RuleMeta(
        id="quality/redundant-guidance",
        default_severity=Severity.WARNING,
        fixable=False,
        description=(
            "Detect instructions that are redundant with model defaults or project tooling"
        ),
        category=RuleCategory.CONTENT,
        messages={
            "default_behavior": (
                "Line {{line}}: '{{label}}' — the model does this by default. "
                "Either remove or add project-specific detail."
            ),
            "tooling_redundant": (
                "Line {{line}}: '{{label}}' — already enforced by {{config}} "
                "in this project. Remove to avoid contradictions."
            ),
        },
        default_suggestion="Remove the instruction or add project-specific detail.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.body:
            return

        project_root = _find_project_root(skill.skill_md_path)

        present_configs: set[str] = set()
        if project_root:
            for config_key in _CONFIG_FILES:
                if _config_exists(project_root, config_key):
                    present_configs.add(config_key)

        from harness_eval.inspection.rules._context import ContextTracker

        lines = skill.body.split("\n")
        tracker = ContextTracker()

        for i, line in enumerate(lines):
            tracker.update(line)

            if tracker.is_fenced():
                continue

            if self._check_tooling(context, skill, line, i, present_configs):
                continue

            if has_project_specificity(line):
                continue

            for label, pattern in TAUTOLOGICAL_PATTERNS:
                if pattern.search(line):
                    context.report(
                        ReportDescriptor(
                            message_id="default_behavior",
                            data={
                                "label": label,
                                "line": str(skill.body_start_line + i),
                            },
                            location=Location(
                                file=skill.skill_md_path,
                                start_line=skill.body_start_line + i,
                            ),
                        )
                    )
                    break

    def _check_tooling(
        self,
        context: RuleContext,
        skill,  # noqa: ANN001
        line: str,
        line_idx: int,
        present_configs: set[str],
    ) -> bool:
        if not present_configs:
            return False

        for config_key, label, pattern in _CONFIG_TOOL_PATTERNS:
            if config_key in present_configs and pattern.search(line):
                context.report(
                    ReportDescriptor(
                        message_id="tooling_redundant",
                        data={
                            "label": label,
                            "config": config_key,
                            "line": str(skill.body_start_line + line_idx),
                        },
                        location=Location(
                            file=skill.skill_md_path,
                            start_line=skill.body_start_line + line_idx,
                        ),
                    )
                )
                return True
        return False
