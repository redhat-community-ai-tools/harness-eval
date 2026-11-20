"""Trigger overlap analysis: detect skills that would load simultaneously."""

from __future__ import annotations

from dataclasses import dataclass, field

from harness_eval.core.types import ComponentType, Setup
from harness_eval.utils.similarity import build_similarity_matrix

TRIGGER_OVERLAP_THRESHOLD = 0.50


@dataclass
class TriggerReport:
    """Trigger overlap analysis results."""

    skill_count: int = 0
    skills_with_description: int = 0
    skills_without_description: int = 0
    overlap_pairs: list[tuple[str, str, float]] = field(default_factory=list)
    missing_use_when: list[str] = field(default_factory=list)


def analyze_triggers(setup: Setup) -> TriggerReport:
    """Analyze skill trigger descriptions for overlap and quality."""
    skills = setup.by_type(ComponentType.SKILL)
    report = TriggerReport(skill_count=len(skills))

    descriptions: dict[str, str] = {}

    for comp in skills:
        desc = ""
        if comp.frontmatter and isinstance(comp.frontmatter.get("description"), str):
            desc = comp.frontmatter["description"]

        if desc:
            report.skills_with_description += 1
            descriptions[comp.name] = desc

            desc_lower = desc.lower()
            use_when_phrases = [
                "use when",
                "use for",
                "applies to",
                "relevant for",
                "triggered by",
                "invoke when",
            ]
            if not any(phrase in desc_lower for phrase in use_when_phrases):
                report.missing_use_when.append(comp.name)
        else:
            report.skills_without_description += 1

    matrix = build_similarity_matrix(descriptions)
    report.overlap_pairs = matrix.pairs_above(TRIGGER_OVERLAP_THRESHOLD)
    report.overlap_pairs.sort(key=lambda x: x[2], reverse=True)

    return report
