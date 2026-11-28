"""Tests for reference extraction calibration in content/broken-references."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint
from harness_eval.inspection.types import Severity


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


def _broken(result: object) -> list:
    return [
        d
        for d in result.diagnostics  # type: ignore[attr-defined]
        if d.rule_id == "content/broken-references"
    ]


def test_skill_resource_path_is_an_error(tmp_path: Path) -> None:
    result = lint(_make_skill(tmp_path, "Run `scripts/missing.py` first.\n"))
    (finding,) = _broken(result)
    assert finding.message_id == "broken_ref"
    assert finding.severity == Severity.ERROR


def test_markdown_link_target_is_an_error(tmp_path: Path) -> None:
    result = lint(_make_skill(tmp_path, "See [the guide](docs/guide.md).\n"))
    (finding,) = _broken(result)
    assert finding.message_id == "broken_ref"
    assert finding.severity == Severity.ERROR


def test_runtime_output_path_is_unverified(tmp_path: Path) -> None:
    """A backticked path outside the skill's resource dirs may be a file the
    skill writes; it is reported, but not as a defect."""
    result = lint(_make_skill(tmp_path, "The judge writes `output/score.json`.\n"))
    (finding,) = _broken(result)
    assert finding.message_id == "unverified_ref"
    assert finding.severity == Severity.WARNING


def test_dot_slash_resource_path_is_still_an_error(tmp_path: Path) -> None:
    result = lint(_make_skill(tmp_path, "Run `./scripts/missing.sh` first.\n"))
    (finding,) = _broken(result)
    assert finding.message_id == "broken_ref"


def test_prose_slash_word_is_unverified(tmp_path: Path) -> None:
    """`references/gold` in "references/gold standards" is prose, not a path."""
    result = lint(_make_skill(tmp_path, "Which files are inputs vs references/gold standards.\n"))
    assert [f.message_id for f in _broken(result)] == ["unverified_ref"]


def test_unquoted_resource_file_is_an_error(tmp_path: Path) -> None:
    result = lint(_make_skill(tmp_path, "Then run scripts/deploy.sh to publish.\n"))
    (finding,) = _broken(result)
    assert finding.message_id == "broken_ref"


def test_configured_error_does_not_raise_unverified(tmp_path: Path) -> None:
    """Setting the rule to error raises real broken references, not unverified ones."""
    result = lint(
        _make_skill(tmp_path, "The judge writes `output/score.json`.\n"),
        config_rules={"content/broken-references": "error"},
    )
    (finding,) = _broken(result)
    assert finding.severity == Severity.WARNING
