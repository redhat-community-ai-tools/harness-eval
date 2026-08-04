"""Tests for cross-component lint rules."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint
from harness_eval.inspection.parsers import parse_skill


def _make_skill(
    tmp_path: Path,
    name: str,
    body: str = "A useful skill.",
    frontmatter_extra: str = "",
) -> Path:
    """Create a minimal skill directory with SKILL.md and return its path."""
    skill_dir = tmp_path / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill {name}\n{frontmatter_extra}---\n\n{body}"
    )
    return skill_dir


# --- OrphanSkills ---


class TestOrphanSkills:
    def test_orphan_detected(self, tmp_path: Path) -> None:
        """Skills not referenced by any command should be flagged."""
        _make_skill(tmp_path, "alpha")
        _make_skill(tmp_path, "beta")

        all_skills = [
            parse_skill(str(tmp_path / "alpha")),
            parse_skill(str(tmp_path / "beta")),
        ]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "alpha"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        rule_ids = {d.rule_id for d in result.diagnostics}
        assert "content/orphan-skills" in rule_ids

    def test_no_orphan_when_referenced(self, tmp_path: Path) -> None:
        """A skill referenced by a command body should not be flagged."""
        from harness_eval.inspection.parsers import parse_command

        _make_skill(tmp_path, "alpha")
        _make_skill(tmp_path, "beta")

        cmd_dir = tmp_path / "my-cmd"
        cmd_dir.mkdir()
        (cmd_dir / "command.md").write_text(
            "---\ndescription: Test command\n---\n\nThis command invokes alpha and also uses beta."
        )

        all_skills = [
            parse_skill(str(tmp_path / "alpha")),
            parse_skill(str(tmp_path / "beta")),
        ]
        all_commands = [parse_command(str(cmd_dir))]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "alpha"),
            all_skills=all_skills,
            all_commands=all_commands,
            scan_state=scan_state,
        )

        orphan_findings = [d for d in result.diagnostics if d.rule_id == "content/orphan-skills"]
        assert len(orphan_findings) == 0

    def test_single_skill_skipped(self, tmp_path: Path) -> None:
        """Single-skill setups should not trigger orphan detection."""
        _make_skill(tmp_path, "only-skill")

        all_skills = [parse_skill(str(tmp_path / "only-skill"))]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "only-skill"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        orphan_findings = [d for d in result.diagnostics if d.rule_id == "content/orphan-skills"]
        assert len(orphan_findings) == 0


# --- McpSkillAlignment ---


class TestMcpSkillAlignment:
    def test_mcp_config_unused(self, tmp_path: Path) -> None:
        """MCP config with servers but no skill referencing MCP should flag."""
        _make_skill(tmp_path, "plain-skill", body="This skill does plain stuff.")

        mcp_config = tmp_path / ".mcp.json"
        mcp_config.write_text(json.dumps({"mcpServers": {"my-server": {"url": "http://x"}}}))

        all_skills = [parse_skill(str(tmp_path / "plain-skill"))]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "plain-skill"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        rule_ids = {d.rule_id for d in result.diagnostics}
        assert "content/mcp-skill-alignment" in rule_ids
        mcp_findings = [d for d in result.diagnostics if d.rule_id == "content/mcp-skill-alignment"]
        assert any("my-server" in d.message for d in mcp_findings)

    def test_mcp_config_with_matching_skill(self, tmp_path: Path) -> None:
        """MCP config should not flag if a skill references MCP tools."""
        _make_skill(
            tmp_path,
            "mcp-user",
            body="Use mcp__my_server__search to find things.",
        )

        mcp_config = tmp_path / ".mcp.json"
        mcp_config.write_text(json.dumps({"mcpServers": {"my-server": {"url": "http://x"}}}))

        all_skills = [parse_skill(str(tmp_path / "mcp-user"))]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "mcp-user"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        mcp_findings = [d for d in result.diagnostics if d.rule_id == "content/mcp-skill-alignment"]
        assert len(mcp_findings) == 0


# --- TotalContextBudget ---


class TestTotalContextBudget:
    def test_over_budget(self, tmp_path: Path) -> None:
        """Total tokens exceeding threshold should flag."""
        # Create skills with large content to exceed 60,000 tokens (30% of 200k)
        big_content = "word " * 20000  # ~20k tokens each
        _make_skill(tmp_path, "big-a", body=big_content)
        _make_skill(tmp_path, "big-b", body=big_content)
        _make_skill(tmp_path, "big-c", body=big_content)
        _make_skill(tmp_path, "big-d", body=big_content)

        all_skills = [
            parse_skill(str(tmp_path / "big-a")),
            parse_skill(str(tmp_path / "big-b")),
            parse_skill(str(tmp_path / "big-c")),
            parse_skill(str(tmp_path / "big-d")),
        ]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "big-a"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        rule_ids = {d.rule_id for d in result.diagnostics}
        assert "content/total-context-budget" in rule_ids

    def test_under_budget(self, tmp_path: Path) -> None:
        """Small skills should not trigger total context budget warning."""
        _make_skill(tmp_path, "small-a", body="A small skill.")
        _make_skill(tmp_path, "small-b", body="Another small skill.")

        all_skills = [
            parse_skill(str(tmp_path / "small-a")),
            parse_skill(str(tmp_path / "small-b")),
        ]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "small-a"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        budget_findings = [
            d for d in result.diagnostics if d.rule_id == "content/total-context-budget"
        ]
        assert len(budget_findings) == 0


# --- PermissionEscalation ---


class TestPermissionEscalation:
    def test_escalation_detected(self, tmp_path: Path) -> None:
        """Skill without Bash referencing one with Bash should flag (transitive escalation)."""
        _make_skill(
            tmp_path,
            "admin-skill",
            body="This skill calls deploy-skill to deploy.",
        )
        _make_skill(
            tmp_path,
            "deploy-skill",
            body="Deploy logic here.",
            frontmatter_extra="allowed-tools:\n  - Bash\n",
        )

        all_skills = [
            parse_skill(str(tmp_path / "admin-skill")),
            parse_skill(str(tmp_path / "deploy-skill")),
        ]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "admin-skill"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        rule_ids = {d.rule_id for d in result.diagnostics}
        assert "content/permission-escalation" in rule_ids
        escalation_findings = [
            d for d in result.diagnostics if d.rule_id == "content/permission-escalation"
        ]
        assert any("Bash" in d.message for d in escalation_findings)

    def test_no_escalation_when_both_have_tools(self, tmp_path: Path) -> None:
        """No flag when both skills have the same tools."""
        _make_skill(
            tmp_path,
            "skill-a",
            body="This skill calls skill-b.",
            frontmatter_extra="allowed-tools:\n  - Bash\n",
        )
        _make_skill(
            tmp_path,
            "skill-b",
            body="Helper logic.",
            frontmatter_extra="allowed-tools:\n  - Bash\n",
        )

        all_skills = [
            parse_skill(str(tmp_path / "skill-a")),
            parse_skill(str(tmp_path / "skill-b")),
        ]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "skill-a"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        escalation_findings = [
            d for d in result.diagnostics if d.rule_id == "content/permission-escalation"
        ]
        assert len(escalation_findings) == 0

    def test_no_escalation_source_has_more(self, tmp_path: Path) -> None:
        """Source skill having MORE tools than target is not escalation."""
        _make_skill(
            tmp_path,
            "admin-skill",
            body="This skill calls helper-skill.",
            frontmatter_extra="allowed-tools:\n  - Bash\n  - Edit\n",
        )
        _make_skill(tmp_path, "helper-skill", body="Helper logic here.")

        all_skills = [
            parse_skill(str(tmp_path / "admin-skill")),
            parse_skill(str(tmp_path / "helper-skill")),
        ]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "admin-skill"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        escalation_findings = [
            d for d in result.diagnostics if d.rule_id == "content/permission-escalation"
        ]
        assert len(escalation_findings) == 0

    def test_no_escalation_single_skill(self, tmp_path: Path) -> None:
        """Single skill should not trigger escalation check."""
        _make_skill(
            tmp_path,
            "lone-skill",
            body="Solo skill.",
            frontmatter_extra="allowed-tools:\n  - Bash\n",
        )

        all_skills = [parse_skill(str(tmp_path / "lone-skill"))]
        scan_state: dict = {}

        result = lint(
            str(tmp_path / "lone-skill"),
            all_skills=all_skills,
            all_commands=[],
            scan_state=scan_state,
        )

        escalation_findings = [
            d for d in result.diagnostics if d.rule_id == "content/permission-escalation"
        ]
        assert len(escalation_findings) == 0
