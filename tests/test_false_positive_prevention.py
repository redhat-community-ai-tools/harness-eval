"""Tests that verify known false-positive scenarios stay quiet.

These tests are derived from real-world deployments where harness-eval
produced findings on legitimate content. Each test documents the source
of the false positive so regressions can be traced.
"""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint
from harness_eval.inspection.parsers import parse_skill


def _make_skill(
    tmp_path: Path,
    name: str,
    body: str,
    frontmatter_extra: str = "",
) -> Path:
    skill_dir = tmp_path / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill\n{frontmatter_extra}---\n\n{body}"
    )
    return skill_dir


def _lint_skill(tmp_path: Path, skill_dir: Path, rule_config: dict | None = None) -> list:
    all_skills = [parse_skill(str(skill_dir))]
    return lint(
        str(skill_dir),
        rule_config,
        scan_state={},
        all_skills=all_skills,
        all_commands=[],
    ).diagnostics


class TestSudoAllowlist:
    """From fullsend PR #5510: install scripts using sudo tar/ln/tee/apparmor_parser
    produced 6 false positives requiring a baseline file."""

    RULE_ID = "security/no-credential-access"
    RULE_CONFIG = {RULE_ID: "error"}

    def test_sudo_tar_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path, "install-skill", body="```bash\nsudo tar xf archive.tar.gz -C /opt\n```"
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0

    def test_sudo_ln_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path,
            "link-skill",
            body="```bash\nsudo ln -sf /opt/bin/tool /usr/local/bin/tool\n```",
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0

    def test_sudo_tee_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path,
            "tee-skill",
            body="```bash\necho 'deb repo' | sudo tee /etc/apt/sources.list.d/repo.list\n```",
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0

    def test_sudo_apparmor_parser_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path,
            "aa-skill",
            body="```bash\nsudo apparmor_parser -r /etc/apparmor.d/profile\n```",
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0

    def test_sudo_cp_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path, "cp-skill", body="```bash\nsudo cp config.conf /etc/myapp/\n```"
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0

    def test_sudo_systemctl_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path, "svc-skill", body="```bash\nsudo systemctl restart myservice\n```"
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0

    def test_sudo_apt_get_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path, "aptget-skill", body="```bash\nsudo apt-get install -y curl\n```"
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0

    def test_sudo_rm_still_flagged(self, tmp_path: Path) -> None:
        """sudo rm is genuinely dangerous and should still flag (outside code blocks)."""
        skill_dir = _make_skill(
            tmp_path, "rm-skill", body="Run sudo rm -rf /var/log/old to clean up."
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) >= 1

    def test_sudo_curl_still_flagged(self, tmp_path: Path) -> None:
        """sudo curl is suspicious and should still flag (outside code blocks)."""
        skill_dir = _make_skill(
            tmp_path,
            "curl-skill",
            body="Run sudo curl http://example.com/install.sh to download.",
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) >= 1


class TestBrokenReferencesTemplates:
    """From fullsend PR #5510: templated path .transcripts/run-<id>/conversation.jsonl
    was treated as a literal broken reference."""

    RULE_ID = "content/broken-references"
    RULE_CONFIG = {RULE_ID: "warning"}

    def test_angle_bracket_template_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path,
            "transcript-skill",
            body="Output is saved to `.transcripts/run-<id>/conversation.jsonl`.",
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0

    def test_env_var_template_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path,
            "env-skill",
            body="Config at `$HOME/.config/app/settings.json`.",
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0

    def test_curly_brace_template_not_flagged(self, tmp_path: Path) -> None:
        skill_dir = _make_skill(
            tmp_path,
            "template-skill",
            body="Read from `${PROJECT_ROOT}/data/output.csv`.",
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, self.RULE_CONFIG)
            if d.rule_id == self.RULE_ID
        ]
        assert len(diags) == 0


class TestSentenceBoundaryPatterns:
    """Ensure greedy patterns don't match across sentence boundaries."""

    def test_memory_write_cross_sentence(self, tmp_path: Path) -> None:
        """'Write to file. Memory is fine.' should not flag memory-write-unscoped."""
        skill_dir = _make_skill(
            tmp_path,
            "safe-skill",
            body="Write the output to a file. Memory usage should stay low.",
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, {"security/memory-write-unscoped": "warning"})
            if d.rule_id == "security/memory-write-unscoped"
        ]
        assert len(diags) == 0

    def test_delegation_cross_sentence(self, tmp_path: Path) -> None:
        """'Create a report. The agent handles formatting.' should not flag."""
        skill_dir = _make_skill(
            tmp_path,
            "report-skill",
            body="Create a detailed report. The agent handles formatting automatically.",
        )
        diags = [
            d
            for d in _lint_skill(tmp_path, skill_dir, {"security/unbounded-delegation": "warning"})
            if d.rule_id == "security/unbounded-delegation"
        ]
        assert len(diags) == 0


class TestCliBinaryNotSkill:
    """CLI binary names should not be flagged as missing skills."""

    def _make_and_lint(self, tmp_path, body):
        from harness_eval.inspection.engine import lint_command
        from harness_eval.inspection.parsers import parse_skill

        skill_dir = tmp_path / "real-skill"
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: real-skill\ndescription: Real\n---\n\nBody."
        )
        cmd_dir = tmp_path / "my-cmd"
        cmd_dir.mkdir(parents=True, exist_ok=True)
        (cmd_dir / "command.md").write_text(body)
        all_skills = [parse_skill(str(skill_dir))]
        result = lint_command(str(cmd_dir), all_skills=all_skills)
        return [
            d for d in result.diagnostics if d.rule_id == "command/references-nonexistent-skill"
        ]

    def test_uvx_harness_eval_not_flagged(self, tmp_path: Path) -> None:
        diags = self._make_and_lint(
            tmp_path,
            "If `uvx` is not available, fall back to `pip install harness-eval` "
            "and use `harness-eval` directly.",
        )
        assert len(diags) == 0

    def test_pip_install_binary_not_flagged(self, tmp_path: Path) -> None:
        diags = self._make_and_lint(
            tmp_path,
            "Install with pip install ruff and use `ruff` to check code.",
        )
        assert len(diags) == 0

    def test_kubectl_helm_not_flagged(self, tmp_path: Path) -> None:
        diags = self._make_and_lint(
            tmp_path,
            "Run `kubectl apply -f x.yaml`. If it fails, use `helm` directly.",
        )
        assert len(diags) == 0

    def test_path_reference_not_flagged(self, tmp_path: Path) -> None:
        diags = self._make_and_lint(
            tmp_path,
            "See /docs/release.md for details.",
        )
        assert len(diags) == 0

    def test_genuine_skill_reference_fires(self, tmp_path: Path) -> None:
        diags = self._make_and_lint(
            tmp_path,
            "This command invokes the skill 'code-review' to analyze changes.",
        )
        assert len(diags) >= 1

    def test_slash_command_reference_fires(self, tmp_path: Path) -> None:
        diags = self._make_and_lint(
            tmp_path,
            "Triggers /security-audit on the workspace.",
        )
        assert len(diags) >= 1


class TestOrdinaryInstructionsNotOverreach:
    """Ordinary instructions should not trigger scope-overreach."""

    def test_review_all_code_changes(self, tmp_path: Path) -> None:
        from harness_eval.inspection.engine import lint

        skill_dir = tmp_path / "review-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: review\ndescription: Code review\n---\n\n"
            "Review all code changes in the PR before approving."
        )
        result = lint(str(skill_dir), {"quality/scope-overreach": "warning"})
        diags = [d for d in result.diagnostics if d.rule_id == "quality/scope-overreach"]
        assert len(diags) == 0

    def test_format_all_files(self, tmp_path: Path) -> None:
        from harness_eval.inspection.engine import lint

        skill_dir = tmp_path / "fmt-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: fmt\ndescription: Formatter\n---\n\n"
            "Format all files with prettier before committing."
        )
        result = lint(str(skill_dir), {"quality/scope-overreach": "warning"})
        diags = [d for d in result.diagnostics if d.rule_id == "quality/scope-overreach"]
        assert len(diags) == 0

    def test_run_after_any_changes(self, tmp_path: Path) -> None:
        from harness_eval.inspection.engine import lint

        skill_dir = tmp_path / "test-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: test\ndescription: Testing\n---\n\nRun pytest after any changes to src/."
        )
        result = lint(str(skill_dir), {"quality/scope-overreach": "warning"})
        diags = [d for d in result.diagnostics if d.rule_id == "quality/scope-overreach"]
        assert len(diags) == 0
