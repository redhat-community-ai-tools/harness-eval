"""harness-gate command: runs only gating-tier rules and exits 1 on errors and warnings."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from harness_eval.cli import cli
from harness_eval.config.presets import gate_rules


def _make_skill(root: Path, body: str) -> None:
    skill = root / "skills" / "foo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(body)


def test_gate_passes_on_clean_setup(tmp_path: Path) -> None:
    _make_skill(
        tmp_path,
        "---\nname: foo\ndescription: Does a clearly useful thing when needed.\n---\n\nBody.\n",
    )
    result = CliRunner().invoke(cli, ["harness-gate", str(tmp_path)])
    assert result.exit_code == 0, result.output


def test_gate_fails_on_gating_finding(tmp_path: Path) -> None:
    # No frontmatter triggers frontmatter/format-valid (a gating rule).
    _make_skill(tmp_path, "Just a body, no frontmatter.\n")
    result = CliRunner().invoke(cli, ["harness-gate", str(tmp_path)])
    assert result.exit_code == 1
    assert "frontmatter/format-valid" in result.output


def test_gate_json_format(tmp_path: Path) -> None:
    _make_skill(tmp_path, "Just a body, no frontmatter.\n")
    result = CliRunner().invoke(cli, ["harness-gate", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1
    findings = json.loads(result.output)
    assert findings and all({"rule", "file", "message"} <= f.keys() for f in findings)


def test_include_provisional_is_superset() -> None:
    assert set(gate_rules()) <= set(gate_rules(include_provisional=True))


def test_gate_exclude_skips_matching_skill(tmp_path: Path) -> None:
    _make_skill(
        tmp_path,
        "---\nname: foo\ndescription: Does a clearly useful thing when needed.\n---\n\nBody.\n",
    )
    bad = tmp_path / "skills" / "bad"
    bad.mkdir()
    (bad / "SKILL.md").write_text("Just a body, no frontmatter.\n")

    failed = CliRunner().invoke(cli, ["harness-gate", str(tmp_path)])
    assert failed.exit_code == 1

    passed = CliRunner().invoke(
        cli, ["harness-gate", str(tmp_path), "--exclude", "skills/bad/SKILL.md"]
    )
    assert passed.exit_code == 0, passed.output
