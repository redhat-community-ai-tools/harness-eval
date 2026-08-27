"""Tests for cross/overpermissive-grants rule.

The rule targets the settings component directly, so it runs on setups that
have a settings.json and no skills. It reports three classes: Bash(*), bare
high-risk tools, and wildcard grants on commands that execute arbitrary code.
A short prefix is not evidence of anything, so Bash(git:*) is silent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness_eval.inspection.engine import lint_hooks
from harness_eval.inspection.rules.cross.overpermissive_grants import _classify_entry

RULE_ID = "cross/overpermissive-grants"
RULE_CONFIG = {RULE_ID: "warning"}


def _make_settings(tmp_path: Path, allow_list: list[str], name: str = "settings.json") -> Path:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(exist_ok=True)
    p = claude_dir / name
    p.write_text(json.dumps({"permissions": {"allow": allow_list}}))
    return p


def _lint(settings_path: Path, scan_state: dict | None = None) -> list:
    result = lint_hooks(str(settings_path), RULE_CONFIG, scan_state=scan_state)
    return [d for d in result.diagnostics if d.rule_id == RULE_ID]


class TestClassification:
    @pytest.mark.parametrize(
        "entry",
        [
            "Bash(awk:*)",
            "Bash(sed:*)",
            "Bash(find:*)",
            "Bash(python:*)",
            "Bash(python3:*)",
            "Bash(python3 -c:*)",
            "Bash(perl -e:*)",
            "Bash(node:*)",
            "Bash(npx:*)",
            "Bash(npx *)",
            "Bash(xargs:*)",
            "Bash(env:*)",
            "Bash(sudo:*)",
            "Bash(docker run:*)",
            "Bash(/usr/bin/python3:*)",
            "Bash(curl:*)",
        ],
    )
    def test_arbitrary_exec_grants_flagged(self, entry: str) -> None:
        result = _classify_entry(entry)
        assert result is not None, entry
        assert "arbitrary command execution" in result[0]

    @pytest.mark.parametrize(
        "entry",
        [
            "Bash(git:*)",
            "Bash(ls:*)",
            "Bash(npm:*)",
            "Bash(cat:*)",
            "Bash(pip:*)",
            "Bash(git commit:*)",
            "Bash(pytest:*)",
            "Bash(python -m pytest:*)",
            "Bash(npm run build)",
            "Read",
            "Grep",
            "Read(src/**)",
        ],
    )
    def test_scoped_or_benign_grants_silent(self, entry: str) -> None:
        assert _classify_entry(entry) is None, entry

    def test_bash_star_is_unrestricted(self) -> None:
        assert "unrestricted shell" in _classify_entry("Bash(*)")[0]

    @pytest.mark.parametrize("entry", ["Bash", "Edit", "Write", "WebFetch"])
    def test_bare_high_risk_tools(self, entry: str) -> None:
        assert "covers all invocations" in _classify_entry(entry)[0]


class TestOverpermissiveGrants:
    def test_runs_without_skills(self, tmp_path: Path) -> None:
        """A settings-only setup must still be checked."""
        p = _make_settings(tmp_path, ["Bash(awk:*)"])
        diags = _lint(p)
        assert len(diags) == 1
        assert "awk" in diags[0].message

    def test_flags_bash_star(self, tmp_path: Path) -> None:
        p = _make_settings(tmp_path, ["Bash(*)"])
        diags = _lint(p)
        assert len(diags) == 1
        assert "unrestricted shell" in diags[0].message

    def test_flags_bare_bash(self, tmp_path: Path) -> None:
        assert len(_lint(_make_settings(tmp_path, ["Bash"]))) == 1

    def test_no_flag_short_benign_prefix(self, tmp_path: Path) -> None:
        assert _lint(_make_settings(tmp_path, ["Bash(git:*)", "Bash(ls:*)", "Bash(npm:*)"])) == []

    def test_flags_long_interpreter_prefix(self, tmp_path: Path) -> None:
        diags = _lint(_make_settings(tmp_path, ["Bash(python:*)", "Bash(find:*)"]))
        assert {d.message.split("'")[1] for d in diags} == {"Bash(python:*)", "Bash(find:*)"}

    def test_multiple_entries(self, tmp_path: Path) -> None:
        assert len(_lint(_make_settings(tmp_path, ["Bash(*)", "Edit", "Bash(awk:*)", "Read"]))) == 3

    def test_no_flag_empty_allow(self, tmp_path: Path) -> None:
        assert _lint(_make_settings(tmp_path, [])) == []

    def test_settings_local_also_checked(self, tmp_path: Path) -> None:
        p = _make_settings(tmp_path, ["Read"])
        _make_settings(tmp_path, ["Bash(*)"], name="settings.local.json")
        diags = _lint(p)
        assert len(diags) == 1
        assert "settings.local.json" in diags[0].message

    def test_scan_state_runs_once(self, tmp_path: Path) -> None:
        p = _make_settings(tmp_path, ["Bash(*)"])
        state: dict = {}
        assert len(_lint(p, state)) == 1
        assert _lint(p, state) == []

    def test_malformed_settings_ignored(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        p = claude_dir / "settings.json"
        p.write_text("{not json")
        assert _lint(p) == []
