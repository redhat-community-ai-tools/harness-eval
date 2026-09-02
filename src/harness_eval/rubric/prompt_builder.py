"""Prompt templates for LLM-based rubric issue detection."""

from __future__ import annotations

from pathlib import Path

from harness_eval.rubric.types import IssueCategory

_PROMPTS_DIR = Path(__file__).parent / "prompts"

SYSTEM_PROMPT = (_PROMPTS_DIR / "system.md").read_text().strip()
ISSUE_TEMPLATE = (_PROMPTS_DIR / "issue-template.md").read_text()
BATCH_TEMPLATE = (_PROMPTS_DIR / "batch-template.md").read_text()


def build_issue_prompt(
    component_type: str,
    component_name: str,
    content: str,
    categories: list[IssueCategory],
    context: str | None = None,
) -> str:
    cats_text = "\n".join(f"- **{c.name}**: {c.description}" for c in categories)

    context_section = ""
    if context:
        context_section = f"### Context (other components in the setup):\n{context}\n"

    return ISSUE_TEMPLATE.format(
        component_type=component_type,
        component_name=component_name,
        content=content,
        context_section=context_section,
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
            f"## Component {i}: {comp_name} (type: {comp_type})\n\n```\n{comp_content}\n```"
        )
    components_section = "\n\n".join(parts)

    context_section = ""
    if context:
        context_section = f"### Context (other components in the setup):\n{context}\n"

    return BATCH_TEMPLATE.format(
        count=len(components),
        components_section=components_section,
        context_section=context_section,
        categories_section=cats_text,
    )
