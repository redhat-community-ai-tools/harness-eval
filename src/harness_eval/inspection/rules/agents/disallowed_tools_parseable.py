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

_VALID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+(\(.*\))?$")


class DisallowedToolsParseable:
    meta: RuleMeta = RuleMeta(
        id="agent/disallowed-tools-parseable",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Each disallowedTools entry must follow ToolName or ToolName(pattern) format",
        category=RuleCategory.FRONTMATTER,
        messages={
            "unparseable": "disallowedTools entry '{{entry}}' does not match expected format: ToolName or ToolName(pattern)",
        },
        target_type=ComponentType.AGENT,
    )

    def create(self, context: RuleContext) -> None:
        agent = context.agent
        if not agent or not agent.disallowed_tools:
            return

        for entry in agent.disallowed_tools:
            if not _VALID_PATTERN.match(entry):
                context.report(
                    ReportDescriptor(
                        message_id="unparseable",
                        data={"entry": entry},
                        location=Location(
                            file=agent.agent_md_path,
                            start_line=agent.frontmatter_start_line or 1,
                        ),
                    )
                )
