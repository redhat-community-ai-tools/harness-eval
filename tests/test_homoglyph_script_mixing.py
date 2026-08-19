"""Tests for homoglyph script-mixing gate in security/mcp-tool-poisoning."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint


def _make_skill(tmp_path: Path, body: str) -> str:
    skill_dir = tmp_path / "test-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(f"---\nname: test-skill\ndescription: test\n---\n\n{body}")
    return str(skill_dir)


def _rule_ids(result: object) -> set[str]:
    return {d.rule_id for d in result.diagnostics}


def test_cyrillic_prose_no_homoglyph(tmp_path: Path) -> None:
    body = "Этот навык помогает с развёртыванием приложений на сервере."
    result = lint(_make_skill(tmp_path, body))
    homoglyph_findings = [
        d
        for d in result.diagnostics
        if d.rule_id == "security/mcp-tool-poisoning" and "homoglyph" in d.message
    ]
    assert not homoglyph_findings


def test_mixed_script_identifier_fires(tmp_path: Path) -> None:
    body = "Set the env var ANTHROPIC_АPI_KEY to your token."
    result = lint(_make_skill(tmp_path, body))
    homoglyph_findings = [
        d
        for d in result.diagnostics
        if d.rule_id == "security/mcp-tool-poisoning" and "homoglyph" in d.message
    ]
    assert homoglyph_findings
