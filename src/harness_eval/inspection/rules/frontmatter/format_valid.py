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


class FormatValid:
    meta: RuleMeta = RuleMeta(
        id="frontmatter/format-valid",
        tier="gating",
        effect="block",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Frontmatter must be valid YAML with the fields the Agent Skills spec requires",
        category=RuleCategory.FRONTMATTER,
        messages={
            "no_frontmatter": (
                "No YAML frontmatter: the Agent Skills specification requires a"
                " frontmatter block with 'name' and 'description'. Claude Code still"
                " loads the file as skill body and falls back to the directory name"
                " and the first paragraph; spec-conformant consumers may reject it."
            ),
            "missing_name": "Field 'name' is missing from frontmatter",
            "name_type": "Field 'name' must be a string",
            "name_format": (
                "Skill name '{{name}}' must be 1-64 lowercase letters, numbers, and"
                " single hyphens, with no leading or trailing hyphen"
            ),
            "name_mismatch": "Skill name '{{name}}' does not match directory '{{directory}}'",
            "description_type": "Field 'description' must be a string",
            "compatibility_type": "Field 'compatibility' must be a string of at most 500 characters",
            "metadata_type": "Field 'metadata' must be a mapping of string keys to string values",
            "allowed_tools_type": "Field 'allowed-tools' must be a space-delimited string in the Agent Skills specification",
        },
        default_suggestion="Fix the YAML frontmatter syntax errors.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        loc = Location(
            file=skill.skill_md_path,
            start_line=skill.frontmatter_start_line or 1,
        )

        if not skill.raw_content:
            return

        if not skill.raw_frontmatter and not skill.parse_errors:
            context.report(ReportDescriptor(message_id="no_frontmatter", location=loc))
            return

        if skill.parse_errors:
            return

        name = skill.frontmatter.get("name")
        if name is None:
            # every current client defaults the name to the directory; the spec
            # requires the field, so this is advisory rather than a load failure
            context.report(
                ReportDescriptor(
                    message_id="missing_name", location=loc, severity_override=Severity.INFO
                )
            )
        elif not isinstance(name, str):
            context.report(ReportDescriptor(message_id="name_type", location=loc))
        else:
            valid_name = re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
            if not valid_name or not 1 <= len(name) <= 64:
                context.report(
                    ReportDescriptor(message_id="name_format", data={"name": name}, location=loc)
                )
            directory = Path(skill.dir_path).name
            # OpenCode V2 treats name as a display label and derives identity
            # from the path; portable Agent Skills and other clients require a match.
            if context.source_tool != "opencode" and name != directory:
                context.report(
                    ReportDescriptor(
                        message_id="name_mismatch",
                        data={"name": name, "directory": directory},
                        location=loc,
                    )
                )

        description = skill.frontmatter.get("description")
        if description is not None and not isinstance(description, str):
            context.report(ReportDescriptor(message_id="description_type", location=loc))

        compatibility = skill.frontmatter.get("compatibility")
        if compatibility is not None and (
            not isinstance(compatibility, str) or len(compatibility) > 500
        ):
            context.report(ReportDescriptor(message_id="compatibility_type", location=loc))

        metadata = skill.frontmatter.get("metadata")
        if metadata is not None and (
            not isinstance(metadata, dict)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in metadata.items())
        ):
            context.report(ReportDescriptor(message_id="metadata_type", location=loc))

        allowed_tools = skill.frontmatter.get("allowed-tools")
        if allowed_tools is not None and not isinstance(allowed_tools, str):
            context.report(
                ReportDescriptor(
                    message_id="allowed_tools_type",
                    location=loc,
                    severity_override=Severity.INFO,
                )
            )
