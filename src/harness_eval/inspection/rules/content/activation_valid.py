from __future__ import annotations

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
from harness_eval.utils.parsing import parse_frontmatter_rich


class InstructionActivationValid:
    meta = RuleMeta(
        id="content/activation-valid",
        tier="gating",
        scope="FILE",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Validate activation metadata required by path-scoped instruction files",
        category=RuleCategory.STRUCTURAL,
        messages={
            "copilot_apply_to": (
                "Copilot .instructions.md files require a non-empty string applyTo glob in frontmatter"
            ),
        },
        target_type=ComponentType.CLAUDE_MD,
        tools=("copilot",),
        default_suggestion="Add valid activation metadata so the client can apply this instruction file.",
    )

    def create(self, context: RuleContext) -> None:
        target = context.claude_md
        if target is None or context.source_tool != "copilot":
            return
        if not Path(target.file_path).name.endswith(".instructions.md"):
            return
        parsed = parse_frontmatter_rich(target.raw_content)
        apply_to = parsed.frontmatter.get("applyTo")
        if not isinstance(apply_to, str) or not apply_to.strip():
            context.report(
                ReportDescriptor(
                    message_id="copilot_apply_to",
                    location=Location(file=target.file_path, start_line=1),
                )
            )
