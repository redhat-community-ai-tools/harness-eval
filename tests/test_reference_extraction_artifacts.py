"""Tests for reference extraction calibration in content/broken-references."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint


def _make_skill(tmp_path: Path, body: str, extra_files: dict[str, str] | None = None) -> str:
    skill_dir = tmp_path / "test-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(f"---\nname: test-skill\ndescription: test\n---\n\n{body}")
    for name, content in (extra_files or {}).items():
        path = skill_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return str(skill_dir)


def test_env_assignment_not_reported(tmp_path: Path) -> None:
    body = "Set `MERMAID=plugins/x.ts` before running.\n"
    result = lint(_make_skill(tmp_path, body))
    broken = [d for d in result.diagnostics if d.rule_id == "content/broken-references"]
    assert not broken


def test_trailing_period_resolves(tmp_path: Path) -> None:
    body = "Run `scripts/sync_docs.py.`\n"
    result = lint(_make_skill(tmp_path, body, {"scripts/sync_docs.py": "# ok"}))
    broken = [d for d in result.diagnostics if d.rule_id == "content/broken-references"]
    assert not broken


def test_genuinely_missing_still_reported(tmp_path: Path) -> None:
    body = "See `scripts/missing.py` for details.\n"
    result = lint(_make_skill(tmp_path, body))
    broken = [d for d in result.diagnostics if d.rule_id == "content/broken-references"]
    assert broken
