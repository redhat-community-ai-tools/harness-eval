"""Flag symlinks inside a skill directory that resolve outside the repository.

Discovery follows a symlink like any file, so `skills/foo/scripts/run.sh ->
/tmp/evil` puts content outside review into a component that runs with the
agent's privileges. Decidable from the filesystem.
"""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules._config_fs import is_within, project_root
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)


class StructuralSymlinkEscape:
    meta = RuleMeta(
        id="structural/symlink-escape",
        tier="gating",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag a symlink inside a skill directory whose target lies outside the repository",
        category=RuleCategory.SECURITY,
        messages={
            "escape": "'{{link}}' is a symlink to '{{target}}', outside the repository; its content is not under review."
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Replace the symlink with a committed copy of the file.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        skill_dir = Path(skill.skill_md_path).parent
        root = project_root(skill_dir)
        for p in skill_dir.rglob("*"):
            if p.is_symlink():
                target = p.resolve()
                if not is_within(target, root):
                    context.report(
                        ReportDescriptor(
                            message_id="escape",
                            data={"link": str(p.relative_to(skill_dir)), "target": str(target)},
                            location=Location(file=str(p)),
                        )
                    )
