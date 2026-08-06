"""Tests for agentic security rules."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint


def _make_skill(tmp_path: Path, name: str, body: str) -> str:
    skill_dir = tmp_path / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill\n---\n\n{body}"
    )
    return str(skill_dir)


def _make_agent(tmp_path: Path, name: str, frontmatter: str, body: str = "") -> str:
    agent_dir = tmp_path / ".claude" / "agents"
    agent_dir.mkdir(parents=True, exist_ok=True)
    path = agent_dir / f"{name}.md"
    path.write_text(f"---\n{frontmatter}\n---\n{body}")
    return str(path)


# -----------------------------------------------------------------------
# agent/excessive-permissions
# -----------------------------------------------------------------------

EXCESSIVE_PERM_CONFIG = {"agent/excessive-permissions": "error"}


class TestExcessivePermissions:
    def test_no_constraints_flagged(self, tmp_path: Path) -> None:
        _make_agent(tmp_path, "open-agent", "description: does everything")
        (tmp_path / "CLAUDE.md").write_text("# Test")
        from harness_eval.core.setup import discover_setup
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("test", str(tmp_path))
        results = inspect_setup(setup, EXCESSIVE_PERM_CONFIG)
        diags = [
            d for r in results for d in r.diagnostics if d.rule_id == "agent/excessive-permissions"
        ]
        assert len(diags) >= 1
        assert any("no allowedTools or disallowedTools" in d.message for d in diags)

    def test_with_disallowed_tools_not_flagged(self, tmp_path: Path) -> None:
        _make_agent(tmp_path, "restricted-agent", "description: restricted\ndisallowedTools: Bash")
        (tmp_path / "CLAUDE.md").write_text("# Test")
        from harness_eval.core.setup import discover_setup
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("test", str(tmp_path))
        results = inspect_setup(setup, EXCESSIVE_PERM_CONFIG)
        diags = [
            d for r in results for d in r.diagnostics if d.rule_id == "agent/excessive-permissions"
        ]
        assert len(diags) == 0

    def test_with_allowed_tools_not_flagged(self, tmp_path: Path) -> None:
        _make_agent(tmp_path, "scoped-agent", "description: scoped\ntools:\n  - Read\n  - Write")
        (tmp_path / "CLAUDE.md").write_text("# Test")
        from harness_eval.core.setup import discover_setup
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("test", str(tmp_path))
        results = inspect_setup(setup, EXCESSIVE_PERM_CONFIG)
        diags = [
            d for r in results for d in r.diagnostics if d.rule_id == "agent/excessive-permissions"
        ]
        assert len(diags) == 0


# -----------------------------------------------------------------------
# memory-write-unscoped (skill + agent variants)
# -----------------------------------------------------------------------

MEMORY_SKILL_CONFIG = {"security/memory-write-unscoped": "error"}
MEMORY_AGENT_CONFIG = {"agent/memory-write-unscoped": "error"}


class TestMemoryWriteUnscopedSkill:
    def test_save_to_memory_flagged(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "mem-skill", "Save the result to memory for later use.")
        result = lint(path, MEMORY_SKILL_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "security/memory-write-unscoped"]
        assert len(diags) >= 1

    def test_clean_skill_not_flagged(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "clean-skill", "Format the output as JSON.")
        result = lint(path, MEMORY_SKILL_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "security/memory-write-unscoped"]
        assert len(diags) == 0

    def test_no_flag_cross_sentence(self, tmp_path: Path) -> None:
        """Words in different sentences should not match across sentence boundary."""
        # "Write" and "memory" are in separate sentences
        path = _make_skill(
            tmp_path,
            "sentence-test",
            "Write the output to a CSV file. Memory usage is 2GB.",
        )
        result = lint(path, MEMORY_SKILL_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "security/memory-write-unscoped"]
        assert len(diags) == 0

    def test_memory_in_code_block_downgraded(self, tmp_path: Path) -> None:
        body = "Example:\n```\nSave this to memory for later.\n```\n"
        path = _make_skill(tmp_path, "code-block-skill", body)
        result = lint(path, MEMORY_SKILL_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "security/memory-write-unscoped"]
        flagged = [d for d in diags if "code block" not in d.message]
        assert len(flagged) == 0


class TestMemoryWriteUnscopedAgent:
    def test_persist_memory_flagged(self, tmp_path: Path) -> None:
        _make_agent(
            tmp_path,
            "mem-agent",
            "description: remembers things",
            "Remember this across sessions for future reference.",
        )
        (tmp_path / "CLAUDE.md").write_text("# Test")
        from harness_eval.core.setup import discover_setup
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("test", str(tmp_path))
        results = inspect_setup(setup, MEMORY_AGENT_CONFIG)
        diags = [
            d for r in results for d in r.diagnostics if d.rule_id == "agent/memory-write-unscoped"
        ]
        assert len(diags) >= 1

    def test_clean_agent_not_flagged(self, tmp_path: Path) -> None:
        _make_agent(
            tmp_path,
            "clean-agent",
            "description: helpful agent",
            "Help the user write code.",
        )
        (tmp_path / "CLAUDE.md").write_text("# Test")
        from harness_eval.core.setup import discover_setup
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("test", str(tmp_path))
        results = inspect_setup(setup, MEMORY_AGENT_CONFIG)
        diags = [
            d for r in results for d in r.diagnostics if d.rule_id == "agent/memory-write-unscoped"
        ]
        assert len(diags) == 0


# -----------------------------------------------------------------------
# unbounded-delegation (skill + agent variants)
# -----------------------------------------------------------------------

DELEGATION_SKILL_CONFIG = {"security/unbounded-delegation": "error"}
DELEGATION_AGENT_CONFIG = {"agent/unbounded-delegation": "error"}


class TestUnboundedDelegationSkill:
    def test_spawn_agent_flagged(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "spawner", "Spawn an agent for each file in the list.")
        result = lint(path, DELEGATION_SKILL_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "security/unbounded-delegation"]
        assert len(diags) >= 1

    def test_agent_tool_flagged(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "delegator", "Use the Agent tool to handle each task.")
        result = lint(path, DELEGATION_SKILL_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "security/unbounded-delegation"]
        assert len(diags) >= 1

    def test_clean_skill_not_flagged(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "safe-skill", "Read the file and return the contents.")
        result = lint(path, DELEGATION_SKILL_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "security/unbounded-delegation"]
        assert len(diags) == 0

    def test_no_flag_cross_sentence(self, tmp_path: Path) -> None:
        """Words in different sentences should not match across boundary."""
        path = _make_skill(
            tmp_path,
            "sentence-test",
            "Launch the test suite. The agent will handle the rest.",
        )
        result = lint(path, DELEGATION_SKILL_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "security/unbounded-delegation"]
        assert len(diags) == 0

    def test_agent_in_code_block_downgraded(self, tmp_path: Path) -> None:
        body = "Example:\n```\nSpawn an agent for this task.\n```\n"
        path = _make_skill(tmp_path, "example-skill", body)
        result = lint(path, DELEGATION_SKILL_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "security/unbounded-delegation"]
        flagged = [d for d in diags if "code block" not in d.message]
        assert len(flagged) == 0


class TestUnboundedDelegationAgent:
    def test_delegate_subagent_flagged(self, tmp_path: Path) -> None:
        _make_agent(
            tmp_path,
            "delegating-agent",
            "description: orchestrator",
            "Delegate to a subagent for each subtask.",
        )
        (tmp_path / "CLAUDE.md").write_text("# Test")
        from harness_eval.core.setup import discover_setup
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("test", str(tmp_path))
        results = inspect_setup(setup, DELEGATION_AGENT_CONFIG)
        diags = [
            d for r in results for d in r.diagnostics if d.rule_id == "agent/unbounded-delegation"
        ]
        assert len(diags) >= 1

    def test_clean_agent_not_flagged(self, tmp_path: Path) -> None:
        _make_agent(
            tmp_path,
            "simple-agent",
            "description: simple",
            "Read files and answer questions.",
        )
        (tmp_path / "CLAUDE.md").write_text("# Test")
        from harness_eval.core.setup import discover_setup
        from harness_eval.inspection.engine import inspect_setup

        setup = discover_setup("test", str(tmp_path))
        results = inspect_setup(setup, DELEGATION_AGENT_CONFIG)
        diags = [
            d for r in results for d in r.diagnostics if d.rule_id == "agent/unbounded-delegation"
        ]
        assert len(diags) == 0
