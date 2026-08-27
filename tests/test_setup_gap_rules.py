"""Tests for setup gap detection rules (92 -> 96)."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.parsers import parse_hooks
from harness_eval.inspection.registry import _registry
from harness_eval.inspection.rules import register_all_rules
from harness_eval.inspection.types import ReportDescriptor, RuleContext, Severity


def _ensure_rules() -> None:
    if not _registry:
        register_all_rules()


def _make_hooks_context(
    tmp_path: Path, settings_data: dict
) -> tuple[RuleContext, list[ReportDescriptor]]:
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps(settings_data))
    hooks = parse_hooks(str(settings_file))
    reports: list[ReportDescriptor] = []
    from harness_eval.inspection.parsers import parse_skill

    dummy_skill = parse_skill(str(tmp_path))
    ctx = RuleContext(
        skill=dummy_skill,
        report=reports.append,
        severity=Severity.ERROR,
        target=hooks,
    )
    return ctx, reports


class TestNoCommitGuard:
    def test_hooks_without_commit_guard_fires(self, tmp_path: Path) -> None:
        _ensure_rules()
        from harness_eval.inspection.rules.hooks.no_commit_guard import HooksNoCommitGuard

        rule = HooksNoCommitGuard()
        ctx, reports = _make_hooks_context(
            tmp_path,
            {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": ["echo hi"]}]}},
        )
        rule.create(ctx)
        assert len(reports) == 1

    def test_commit_guard_present_clean(self, tmp_path: Path) -> None:
        from harness_eval.inspection.rules.hooks.no_commit_guard import HooksNoCommitGuard

        rule = HooksNoCommitGuard()
        ctx, reports = _make_hooks_context(
            tmp_path,
            {
                "hooks": {
                    "PreToolUse": [{"matcher": "Bash(git commit*)", "hooks": ["gitleaks protect"]}]
                }
            },
        )
        rule.create(ctx)
        assert len(reports) == 0

    def test_no_hooks_section_clean(self, tmp_path: Path) -> None:
        from harness_eval.inspection.rules.hooks.no_commit_guard import HooksNoCommitGuard

        rule = HooksNoCommitGuard()
        ctx, reports = _make_hooks_context(tmp_path, {"env": {"FOO": "bar"}})
        rule.create(ctx)
        assert len(reports) == 0


class TestDangerousPermissionGrant:
    def test_flags_sudo(self, tmp_path: Path) -> None:
        _ensure_rules()
        from harness_eval.inspection.rules.hooks.dangerous_permission_grant import (
            HooksDangerousPermissionGrant,
        )

        rule = HooksDangerousPermissionGrant()
        ctx, reports = _make_hooks_context(
            tmp_path, {"permissions": {"allow": ["Bash(sudo apt install *)"]}}
        )
        rule.create(ctx)
        assert len(reports) == 1
        assert "privilege escalation" in (reports[0].data or {}).get("label", "")

    def test_flags_curl_pipe_bash(self, tmp_path: Path) -> None:
        from harness_eval.inspection.rules.hooks.dangerous_permission_grant import (
            HooksDangerousPermissionGrant,
        )

        rule = HooksDangerousPermissionGrant()
        ctx, reports = _make_hooks_context(
            tmp_path,
            {"permissions": {"allow": ["Bash(curl https://example.com | bash)"]}},
        )
        rule.create(ctx)
        assert len(reports) == 1
        assert "piped remote execution" in (reports[0].data or {}).get("label", "")

    def test_flags_terraform_destroy(self, tmp_path: Path) -> None:
        from harness_eval.inspection.rules.hooks.dangerous_permission_grant import (
            HooksDangerousPermissionGrant,
        )

        rule = HooksDangerousPermissionGrant()
        ctx, reports = _make_hooks_context(
            tmp_path, {"permissions": {"allow": ["Bash(terraform destroy)"]}}
        )
        rule.create(ctx)
        assert len(reports) == 1

    def test_safe_permissions_clean(self, tmp_path: Path) -> None:
        from harness_eval.inspection.rules.hooks.dangerous_permission_grant import (
            HooksDangerousPermissionGrant,
        )

        rule = HooksDangerousPermissionGrant()
        ctx, reports = _make_hooks_context(
            tmp_path,
            {"permissions": {"allow": ["Bash(npm test)", "Read", "Bash(git status)"]}},
        )
        rule.create(ctx)
        assert len(reports) == 0


class TestNoAuditTrail:
    def test_no_telemetry_fires(self, tmp_path: Path) -> None:
        _ensure_rules()
        from harness_eval.inspection.rules.hooks.no_audit_trail import HooksNoAuditTrail

        rule = HooksNoAuditTrail()
        ctx, reports = _make_hooks_context(
            tmp_path, {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": ["echo"]}]}}
        )
        rule.create(ctx)
        assert len(reports) == 1

    def test_otel_configured_clean(self, tmp_path: Path) -> None:
        from harness_eval.inspection.rules.hooks.no_audit_trail import HooksNoAuditTrail

        rule = HooksNoAuditTrail()
        ctx, reports = _make_hooks_context(
            tmp_path,
            {"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4317"}},
        )
        rule.create(ctx)
        assert len(reports) == 0


class TestMissingBoundaryPolicy:
    def test_no_boundary_fires(self, tmp_path: Path) -> None:
        _ensure_rules()
        from harness_eval.inspection.engine import lint_claude_md

        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Project\n\nUse Python 3.11. Follow PEP 8.")
        result = lint_claude_md(str(claude_md))
        findings = [d for d in result.diagnostics if d.rule_id == "content/missing-boundary-policy"]
        assert len(findings) >= 1

    def test_boundary_present_clean(self, tmp_path: Path) -> None:
        from harness_eval.inspection.engine import lint_claude_md

        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text(
            "# Project\n\nDo not touch the deploy/ directory. Only work within src/ and tests/."
        )
        result = lint_claude_md(str(claude_md))
        findings = [d for d in result.diagnostics if d.rule_id == "content/missing-boundary-policy"]
        assert len(findings) == 0
