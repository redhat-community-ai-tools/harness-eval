"""Regression tests for scan isolation and architecture boundaries."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from harness_eval.analysis.component_graph import build_component_graph
from harness_eval.analysis.reachability import compute_reachability
from harness_eval.cli import cli
from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType, ScanLimitExceeded, ScanLimits
from harness_eval.inspection import registry
from harness_eval.inspection.parsers import parse_hooks
from harness_eval.inspection.registry import RuleCatalog, get_default_catalog
from harness_eval.inspection.rules._config_fs import project_root
from harness_eval.inspection.setup import parse_setup
from harness_eval.inspection.types import (
    ParsedCommand,
    ParsedSkill,
    RuleCategory,
    RuleContext,
    RuleMeta,
    ScanArtifacts,
    Severity,
)
from harness_eval.inspection.yaml_rules import load_yaml_rules_from_dir


def _write_setup(root: Path, skill_body: str = "Body.\n") -> Path:
    (root / "CLAUDE.md").write_text("# Root\n")
    skill_dir = root / "skills" / "demo"
    skill_dir.mkdir(parents=True)
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text(f"---\nname: demo\ndescription: Demo skill\n---\n\n{skill_body}")
    return skill_md


def _skill(tmp_path: Path, name: str) -> ParsedSkill:
    return ParsedSkill(
        dir_path=str(tmp_path / name),
        dir_name=name,
        skill_md_path=str(tmp_path / name / "SKILL.md"),
        raw_content="",
        frontmatter={},
        raw_frontmatter="",
        frontmatter_start_line=0,
        body="",
        body_start_line=0,
        files=[],
    )


def _command(tmp_path: Path) -> ParsedCommand:
    return ParsedCommand(
        dir_path=str(tmp_path),
        dir_name="command",
        command_md_path=str(tmp_path / "command.md"),
        raw_content="",
        frontmatter={},
        body="",
        body_start_line=0,
        script_references=[],
        files=[],
    )


# --- rule catalogs -----------------------------------------------------------


def test_target_yaml_rules_are_isolated_to_a_catalog(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "custom.yaml").write_text(
        "id: custom/isolated\n"
        "severity: warning\n"
        "description: Isolated rule\n"
        "target: skill\n"
        "category: content\n"
        "patterns: [{label: marker, regex: marker}]\n"
    )

    isolated = get_default_catalog().copy()
    assert load_yaml_rules_from_dir(rules_dir, catalog=isolated) == 1
    assert isolated.get("custom/isolated") is not None
    assert get_default_catalog().get("custom/isolated") is None


def test_rule_catalog_copy_has_independent_storage() -> None:
    catalog = RuleCatalog()
    copied = catalog.copy()
    assert catalog is not copied
    catalog.clear()
    assert copied.all() == []


class _PluginRule:
    meta = RuleMeta(
        id="plugin/example",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Rule contributed by a plugin",
        category=RuleCategory.CONTENT,
        messages={"hit": "hit"},
    )

    def create(self, context: RuleContext) -> None:
        return None


class _FakeEntryPoint:
    def __init__(self, name: str, provider: Any) -> None:
        self.name = name
        self._provider = provider

    def load(self) -> Any:
        if isinstance(self._provider, Exception):
            raise self._provider
        return self._provider


class _FakeEntryPoints:
    def __init__(self, entries: list[_FakeEntryPoint]) -> None:
        self._entries = entries

    def select(self, group: str) -> list[_FakeEntryPoint]:
        assert group == registry.ENTRY_POINT_GROUP
        return self._entries


def _provider_callable(catalog: RuleCatalog) -> None:
    rule = _PluginRule()
    rule.meta = RuleMeta(
        id="plugin/from-callable",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Rule registered by a callable provider",
        category=RuleCategory.CONTENT,
        messages={"hit": "hit"},
    )
    catalog.register(rule)


def test_entry_point_providers_are_validated_and_isolated(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class_rule = type(
        "_ClassRule",
        (),
        {
            "meta": RuleMeta(
                id="plugin/from-class",
                default_severity=Severity.WARNING,
                fixable=False,
                description="Rule from a class provider",
                category=RuleCategory.CONTENT,
                messages={"hit": "hit"},
            ),
            "create": lambda self, context: None,
        },
    )
    entries = [
        _FakeEntryPoint("instance", _PluginRule()),
        _FakeEntryPoint("klass", class_rule),
        _FakeEntryPoint("callable", _provider_callable),
        _FakeEntryPoint("not-a-rule", object()),
        _FakeEntryPoint("broken", ImportError("boom")),
    ]
    monkeypatch.setattr(registry, "entry_points", lambda: _FakeEntryPoints(entries))

    catalog = RuleCatalog()
    with caplog.at_level(logging.ERROR, logger="harness_eval.inspection.registry"):
        assert catalog.load_entry_points() == 3

    assert {r.meta.id for r in catalog.all()} == {
        "plugin/example",
        "plugin/from-class",
        "plugin/from-callable",
    }
    assert get_default_catalog().get("plugin/example") is None
    failed = [rec.message for rec in caplog.records if "Failed to load" in rec.message]
    assert len(failed) == 2


def test_register_provider_rejects_objects_that_are_not_rules() -> None:
    with pytest.raises(TypeError, match="rule plugin must expose"):
        RuleCatalog().register_provider(object())


# --- typed setup bridge and scan artifacts ------------------------------------


def test_parsed_payload_is_attached_to_canonical_component(tmp_path: Path) -> None:
    _write_setup(tmp_path)

    setup = discover_setup("test", str(tmp_path))
    parsed = parse_setup(setup)
    skill = parsed.core_by_type(ComponentType.SKILL)[0]
    assert skill.parsed is not None
    assert parsed.skills[0] is skill.parsed
    assert parsed.parsed(ComponentType.SKILL)[0] is skill.parsed
    assert parsed.claude_mds[0].file_path.endswith("CLAUDE.md")


def test_scan_artifacts_are_a_view_over_one_state_dict(tmp_path: Path) -> None:
    state: dict[str, Any] = {}
    artifacts = ScanArtifacts(state, project_root=tmp_path)

    assert state["project_root"] == str(tmp_path)
    assert artifacts.project_root == tmp_path

    index = {"skills": {"demo"}}
    artifacts.component_index = index
    assert state["component_index"] is index

    assert artifacts.mark_once("checked")
    assert not artifacts.mark_once("checked")
    assert state["checked"] is True

    artifacts.rule_state["my-rule"] = {"seen": 1}
    assert state["_rule_state"]["my-rule"] == {"seen": 1}


def test_rule_context_binds_scan_state_and_artifacts_to_the_same_dict(tmp_path: Path) -> None:
    skill = _skill(tmp_path, "demo")
    scan_state: dict[str, Any] = {"project_root": str(tmp_path)}

    context = RuleContext(
        report=lambda descriptor: None,
        severity=Severity.WARNING,
        skill=skill,
        scan_state=scan_state,
    )

    assert context.scan_state is scan_state
    assert context.artifacts.state is scan_state
    assert context.artifacts.project_root == tmp_path
    context.artifacts.mark_once("once")
    assert scan_state["once"] is True


# --- scan limits ---------------------------------------------------------------


def test_scan_limits_measure_only_agent_setup_files(tmp_path: Path) -> None:
    skill_md = _write_setup(tmp_path)
    (tmp_path / "dataset.bin").write_bytes(b"x" * 4096)
    limits = ScanLimits(max_file_bytes=1024, max_total_bytes=10_000, max_files=10, max_depth=10)

    # An unrelated large file never trips a limit.
    setup = discover_setup("test", str(tmp_path), limits=limits)
    assert len(setup.components) == 2

    # An oversized skill file does, before discovery reads it.
    skill_md.write_text("x" * 2048)
    with pytest.raises(ScanLimitExceeded, match="max_file_bytes"):
        discover_setup("test", str(tmp_path), limits=limits)


def test_scan_limits_count_files_and_total_bytes(tmp_path: Path) -> None:
    _write_setup(tmp_path)
    with pytest.raises(ScanLimitExceeded, match="max_files"):
        discover_setup("test", str(tmp_path), limits=ScanLimits(max_files=1))
    with pytest.raises(ScanLimitExceeded, match="max_total_bytes"):
        discover_setup("test", str(tmp_path), limits=ScanLimits(max_total_bytes=8))


@pytest.mark.parametrize(
    "command",
    ["harness-lint", "harness-gate", "harness-security", "skill-verify"],
)
def test_every_scanning_command_reports_limits_cleanly(tmp_path: Path, command: str) -> None:
    _write_setup(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, [command, str(tmp_path), "--max-file-bytes", "16"])

    assert result.exit_code != 0
    assert "max_file_bytes=16" in result.output
    assert "--max-file-bytes" in result.output
    assert "Traceback" not in result.output


# --- component graph evidence ----------------------------------------------------


def test_hook_edges_are_token_bounded_and_marked_inferred(tmp_path: Path) -> None:
    skill = _skill(tmp_path, "foo")
    command = _command(tmp_path)
    hook_path = tmp_path / "settings.json"

    hook_path.write_text('{"hooks": {"PreToolUse": [{"command": "run foobar"}]}}')
    graph = build_component_graph([skill], [command], hooks=parse_hooks(str(hook_path)))
    assert not [edge for edge in graph.edges if edge.target == "foo"]

    hook_path.write_text('{"hooks": {"PreToolUse": [{"command": "run foo"}]}}')
    graph = build_component_graph([skill], [command], hooks=parse_hooks(str(hook_path)))
    edge = next(edge for edge in graph.edges if edge.target == "foo")
    assert edge.evidence_kind == "inferred"
    assert edge.confidence == pytest.approx(0.35)


def test_reachability_reports_inferred_evidence(tmp_path: Path) -> None:
    skill = _skill(tmp_path, "foo")
    hook_path = tmp_path / "settings.json"
    hook_path.write_text('{"hooks": {"PreToolUse": [{"command": "run foo"}]}}')
    graph = build_component_graph([skill], [], hooks=parse_hooks(str(hook_path)))

    result = compute_reachability(graph, skill.skill_md_path)
    assert result.reachable
    assert result.evidence_kind == "inferred"
    assert result.trigger_breadth == "unknown"

    assert graph.edges_to("foo", min_confidence=0.5) == []
    assert [e.target for e in graph.edges_to("foo")] == ["foo"]


# --- project root ------------------------------------------------------------------


def test_project_root_is_the_git_repository_in_a_monorepo(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "CLAUDE.md").write_text("# Monorepo\n")
    package = tmp_path / "packages" / "app"
    commands = package / ".claude" / "commands"
    commands.mkdir(parents=True)
    (package / "CLAUDE.md").write_text("# App\n")
    command_md = commands / "build.md"
    command_md.write_text("Run scripts/build.sh\n")

    # Commands run from the repository root, so a nested CLAUDE.md must not
    # shadow the enclosing repository.
    assert project_root(command_md) == tmp_path.resolve()
