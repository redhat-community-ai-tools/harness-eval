"""Regression tests for scan isolation and architecture boundaries."""

from __future__ import annotations

from pathlib import Path

import pytest

from harness_eval.analysis.component_graph import build_component_graph
from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType, ScanLimitExceeded, ScanLimits
from harness_eval.inspection.parsers import parse_hooks
from harness_eval.inspection.registry import RuleCatalog, get_default_catalog
from harness_eval.inspection.setup import parse_setup
from harness_eval.inspection.types import ParsedCommand, ParsedSkill
from harness_eval.inspection.yaml_rules import load_yaml_rules_from_dir


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


def test_parsed_payload_is_attached_to_canonical_component(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# Root\n")
    skill_dir = tmp_path / "skills" / "demo"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo skill\n---\n\nBody.\n"
    )

    setup = discover_setup("test", str(tmp_path))
    parsed = parse_setup(setup)
    skill = parsed.core_by_type(ComponentType.SKILL)[0]
    assert skill.parsed is not None
    assert parsed.parsed(skill.component_type)[0] is skill.parsed


def test_hook_edges_are_token_bounded_and_marked_inferred(tmp_path: Path) -> None:
    skill = ParsedSkill(
        dir_path=str(tmp_path / "foo"),
        dir_name="foo",
        skill_md_path=str(tmp_path / "foo" / "SKILL.md"),
        raw_content="",
        frontmatter={},
        raw_frontmatter="",
        frontmatter_start_line=0,
        body="",
        body_start_line=0,
        files=[],
    )
    command = ParsedCommand(
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
    hook_path = tmp_path / "settings.json"
    hook_path.write_text('{"hooks": {"PreToolUse": [{"command": "run foobar"}]}}')
    graph = build_component_graph([skill], [command], hooks=parse_hooks(str(hook_path)))
    assert not [edge for edge in graph.edges if edge.target == "foo"]

    hook_path.write_text('{"hooks": {"PreToolUse": [{"command": "run foo"}]}}')
    graph = build_component_graph([skill], [command], hooks=parse_hooks(str(hook_path)))
    edge = next(edge for edge in graph.edges if edge.target == "foo")
    assert edge.evidence_kind == "inferred"
    assert edge.confidence == pytest.approx(0.35)


def test_scan_limits_fail_before_discovery_reads_large_files(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# Root\n")
    (tmp_path / "large.txt").write_text("x" * 32)

    with pytest.raises(ScanLimitExceeded, match="max_file_bytes"):
        discover_setup(
            "test",
            str(tmp_path),
            limits=ScanLimits(max_file_bytes=16, max_total_bytes=10_000, max_files=10, max_depth=10),
        )


def test_rule_catalog_copy_has_independent_storage() -> None:
    catalog = RuleCatalog()
    copied = catalog.copy()
    assert catalog is not copied
    catalog.clear()
    assert copied.all() == []
