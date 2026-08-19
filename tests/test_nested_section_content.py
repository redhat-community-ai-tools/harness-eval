"""Tests for nested-section suppression in quality/unfinished-content."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint


def _make_skill(tmp_path: Path, body: str) -> str:
    skill_dir = tmp_path / "test-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(f"---\nname: test-skill\ndescription: test\n---\n\n{body}")
    return str(skill_dir)


def test_parent_with_subsection_no_empty(tmp_path: Path) -> None:
    body = "## Parent\n\n### Child\n\nThis child has content.\n"
    result = lint(_make_skill(tmp_path, body))
    empty_findings = [
        d
        for d in result.diagnostics
        if d.rule_id == "quality/unfinished-content" and "no content" in d.message
    ]
    assert not empty_findings


def test_empty_sibling_still_fires(tmp_path: Path) -> None:
    body = "## Empty\n\n## Next\n\nThis section has content.\n"
    result = lint(_make_skill(tmp_path, body))
    empty_findings = [
        d
        for d in result.diagnostics
        if d.rule_id == "quality/unfinished-content" and "no content" in d.message
    ]
    assert any("Empty" in d.message for d in empty_findings)
