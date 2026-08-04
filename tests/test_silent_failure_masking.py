"""Tests for hooks/silent-failure-masking rule."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint_hooks

RULE_ID = "hooks/silent-failure-masking"
RULE_CONFIG = {RULE_ID: "warning"}


def _make_hooks(tmp_path: Path, event: str, command: str) -> str:
    settings = {"hooks": {event: [{"hooks": [{"type": "command", "command": command}]}]}}
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(settings))
    return str(path)


class TestSilentFailureMasking:
    def test_flags_stderr_devnull(self, tmp_path: Path) -> None:
        path = _make_hooks(tmp_path, "PostToolUse", "check.sh 2>/dev/null")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "/dev/null" in diags[0].message

    def test_flags_or_true(self, tmp_path: Path) -> None:
        path = _make_hooks(tmp_path, "PostToolUse", "run.sh || true")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1

    def test_flags_set_plus_e(self, tmp_path: Path) -> None:
        path = _make_hooks(tmp_path, "PreToolUse", "set +e; do_stuff")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1

    def test_flags_or_colon(self, tmp_path: Path) -> None:
        path = _make_hooks(tmp_path, "Stop", "cleanup.sh || :")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1

    def test_escalates_with_sensitive_op(self, tmp_path: Path) -> None:
        path = _make_hooks(tmp_path, "PostToolUse", "curl http://example.com 2>/dev/null")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert diags[0].severity.value == "error"
        assert "security-relevant" in diags[0].message

    def test_no_flag_clean_hook(self, tmp_path: Path) -> None:
        path = _make_hooks(tmp_path, "PostToolUse", "echo done")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_no_flag_empty_command(self, tmp_path: Path) -> None:
        path = _make_hooks(tmp_path, "PostToolUse", "")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_flags_trap_err(self, tmp_path: Path) -> None:
        """trap '' ERR should be flagged."""
        path = _make_hooks(tmp_path, "PreToolUse", "trap '' ERR; do_stuff")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
        assert "trap" in diags[0].message.lower() or "ERR" in diags[0].message

    def test_sensitive_op_without_suppression_not_flagged(self, tmp_path: Path) -> None:
        """curl without error suppression should not fire this rule."""
        path = _make_hooks(tmp_path, "PostToolUse", "curl https://example.com/api")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 0

    def test_only_reports_once_per_hook(self, tmp_path: Path) -> None:
        """Multiple suppression patterns in same command should report once (break)."""
        # This command has both "2>/dev/null" and "|| true"
        path = _make_hooks(tmp_path, "PostToolUse", "run.sh 2>/dev/null || true")
        result = lint_hooks(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == RULE_ID]
        assert len(diags) == 1
