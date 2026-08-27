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

_SKILL_REF_PATTERNS = [
    re.compile(
        r"(?:invokes?|calls?|triggers?|runs?|uses?)\s+(?:the\s+)?skill\s+[\"'`/](\w[\w-]{2,})[\"'`]?",
        re.IGNORECASE,
    ),
    re.compile(r"(?:^|\s)/(\w[\w-]{2,})(?:\s|$|[),.\]])", re.IGNORECASE | re.MULTILINE),
]

_INSTALL_CMD = re.compile(
    r"(?:pip|pip3|pipx|uv|npm|yarn|pnpm|cargo|brew|apt|apt-get|dnf|go)"
    r"\s+(?:install|add|run|tool\s+install|--from)\s+([\w][\w.-]*)"
    r"|(?:uvx|npx)\s+([\w][\w.-]*)",
    re.IGNORECASE,
)

_PATH_CONTINUATION = re.compile(r"/(?=[/]?)(\w[\w-]{2,})(?=[/.])")


class CommandReferencesNonexistentSkill:
    meta = RuleMeta(
        id="command/references-nonexistent-skill",
        scope="PAIRWISE",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Detect commands that reference skills which do not exist",
        category=RuleCategory.CONTENT,
        messages={
            "missing_skill": "Command '{{command}}' references skill '{{skill}}' but no SKILL.md found for it",
        },
        target_type=ComponentType.COMMAND,
        default_suggestion="Create the missing skill or remove the reference.",
    )

    def create(self, context: RuleContext) -> None:
        cmd = context.command
        if cmd is None or not cmd.body or not context.all_skills:
            return

        known_skills = {s.dir_name for s in context.all_skills}

        installed_binaries: set[str] = set()
        for m in _INSTALL_CMD.finditer(cmd.body):
            name = m.group(1) or m.group(2)
            if name:
                installed_binaries.add(name.lower())
        path_segments = {m.group(1).lower() for m in _PATH_CONTINUATION.finditer(cmd.body)}

        referenced: set[str] = set()

        in_code_fence = False
        for line in cmd.body.split("\n"):
            stripped = line.strip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_code_fence = not in_code_fence
                continue

            for pat_idx, pattern in enumerate(_SKILL_REF_PATTERNS):
                for match in pattern.finditer(line):
                    name = match.group(1)
                    if name == cmd.dir_name or len(name) <= 1:
                        continue
                    if pat_idx == 1 and in_code_fence:
                        continue
                    if pat_idx == 1 and name.lower() in path_segments:
                        continue
                    if name.lower() in installed_binaries:
                        continue
                    referenced.add(name)

        for skill_name in referenced:
            if skill_name not in known_skills:
                context.report(
                    ReportDescriptor(
                        message_id="missing_skill",
                        data={"command": cmd.dir_name, "skill": skill_name},
                        location=Location(file=cmd.command_md_path, start_line=1),
                    )
                )
