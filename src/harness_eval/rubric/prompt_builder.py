"""Prompt templates for LLM-based rubric issue detection."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.rubric.types import IssueCategory

_PROMPTS_DIR = Path(__file__).parent / "prompts"

SYSTEM_PROMPT = (_PROMPTS_DIR / "system.md").read_text().strip()
ISSUE_TEMPLATE = (_PROMPTS_DIR / "issue-template.md").read_text()
BATCH_TEMPLATE = (_PROMPTS_DIR / "batch-template.md").read_text()


def _untrusted_json(value: str) -> str:
    """Serialize untrusted prompt data without allowing delimiter injection."""
    return json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def build_issue_prompt(
    component_type: str,
    component_name: str,
    content: str,
    categories: list[IssueCategory],
    context: str | None = None,
) -> str:
    cats_text = "\n".join(f"- **{c.name}**: {c.description}" for c in categories)

    return ISSUE_TEMPLATE.format(
        component_type=component_type,
        component_name=_untrusted_json(component_name),
        content=_untrusted_json(content),
        context=_untrusted_json(context) if context is not None else "null",
        categories_section=cats_text,
    )


def build_batch_prompt(
    components: list[tuple[str, str, str]],
    categories: list[IssueCategory],
    context: str | None = None,
) -> str:
    cats_text = "\n".join(f"- **{c.name}**: {c.description}" for c in categories)

    parts = []
    for i, (comp_type, comp_name, comp_content) in enumerate(components, 1):
        parts.append(
            f"## Component {i}: {_untrusted_json(comp_name)} "
            f"(type: {_untrusted_json(comp_type)})\n\n"
            f"<component-json>{_untrusted_json(comp_content)}</component-json>"
        )
    components_section = "\n\n".join(parts)

    return BATCH_TEMPLATE.format(
        count=len(components),
        components_section=components_section,
        context=_untrusted_json(context) if context is not None else "null",
        categories_section=cats_text,
    )
