"""Discovery, parsing, and inventory of pipeline agent harness definitions."""

from __future__ import annotations

import shutil
from pathlib import Path

from harness_eval.core.discoverers.fullsend import FullsendDiscoverer, is_harness_file
from harness_eval.core.inventory import collect_setup_file_paths
from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType
from harness_eval.inspection.harness_formats.fullsend import map_fullsend, normalize_path
from harness_eval.inspection.parsers import parse_harness
from harness_eval.inspection.setup import parse_setup

FIXTURE = Path(__file__).parent / "fixtures" / "sample-fullsend-setup"


def test_fixture_is_detected_as_fullsend() -> None:
    setup = discover_setup("fs", str(FIXTURE))
    assert "fullsend" in setup.detected_tools
    harnesses = setup.by_type(ComponentType.HARNESS)
    assert [h.name for h in harnesses] == ["triage"]
    assert harnesses[0].source_tool == "fullsend"


def test_yaml_without_marker_key_is_not_a_harness() -> None:
    assert not is_harness_file(FIXTURE / "harness" / "README.yaml")
    assert is_harness_file(FIXTURE / "harness" / "triage.yaml")


def test_inventory_covers_harness_candidates() -> None:
    inventory = {str(p.resolve()) for p in collect_setup_file_paths(FIXTURE)}
    for name in ("triage.yaml", "README.yaml"):
        assert str((FIXTURE / "harness" / name).resolve()) in inventory
    setup = discover_setup("fs", str(FIXTURE))
    components = {str(Path(c.path).resolve()) for c in setup.components}
    assert components - inventory == set()


def test_fingerprint_changes_when_a_harness_changes(tmp_path: Path) -> None:
    shutil.copytree(FIXTURE, tmp_path / "scaffold")
    before = discover_setup("fs", str(tmp_path / "scaffold")).fingerprint
    harness = tmp_path / "scaffold" / "harness" / "triage.yaml"
    harness.write_text(harness.read_text().replace("model: opus", "model: sonnet"))
    after = discover_setup("fs", str(tmp_path / "scaffold")).fingerprint
    assert before != after


def test_recursive_discovery_finds_nested_scaffold(tmp_path: Path) -> None:
    shutil.copytree(FIXTURE, tmp_path / "internal" / "scaffold" / "repo")
    (tmp_path / "CLAUDE.md").write_text("# root\n")
    flat = discover_setup("fs", str(tmp_path))
    assert flat.by_type(ComponentType.HARNESS) == []
    nested = discover_setup("fs", str(tmp_path), recursive=True)
    assert [h.name for h in nested.by_type(ComponentType.HARNESS)] == ["triage"]
    disc = FullsendDiscoverer()
    assert disc.detect(tmp_path) is False
    assert disc.detect(tmp_path / "internal" / "scaffold" / "repo") is True


def test_parse_harness_normalizes_fullsend_fields() -> None:
    parsed = parse_harness(str(FIXTURE / "harness" / "triage.yaml"), "fullsend")
    assert parsed.parse_errors == []
    f = parsed.fields
    assert f is not None
    assert f.root_dir == FIXTURE.resolve()
    assert f.instructions == "agents/triage.md"
    assert f.model == "opus"
    assert f.policy == "policies/base.yaml"
    assert f.scripts == {
        "pre": "scripts/pre-triage.sh",
        "post": "scripts/post-triage.sh",
        "validator": "scripts/validate-output-schema.sh",
        "forge.github.pre": "scripts/pre-triage.sh",
        "forge.github.post": "scripts/post-triage.sh",
    }
    assert f.skills == ["skills/issue-labels"]
    assert f.plugins == ["plugins/gopls-lsp"]
    assert [hf.dest for hf in f.host_files] == [
        "/sandbox/workspace/.env.d/vertex.env",
        "/tmp/.gcp-credentials.json",
    ]
    assert f.host_files[0].optional is True
    # The legacy env spelling of the output contract is normalized.
    assert f.output_schema == "${FULLSEND_DIR}/schemas/triage-result.schema.json"
    assert f.output_file == "triage-result.json"
    assert f.env["runner"]["FULLSEND_OUTPUT_FILE"] == "triage-result.json"
    assert "github" in f.platform_overrides


def test_refs_exclude_what_the_runtime_cannot_resolve_statically() -> None:
    parsed = parse_harness(str(FIXTURE / "harness" / "triage.yaml"), "fullsend")
    assert parsed.fields is not None
    refs = {r.field: r for r in parsed.fields.refs}
    # Host variable references are not decidable from the tree.
    assert "host_files[1].src" not in refs
    # ${FULLSEND_DIR} is the scaffold root and is normalized away.
    assert refs["env.runner.FULLSEND_OUTPUT_SCHEMA"].value == "schemas/triage-result.schema.json"
    assert refs["host_files[0].src"].optional is True
    assert refs["skills[0]"].directory is True
    assert refs["plugins[0]"].directory is True


def test_normalize_path_decidability() -> None:
    assert normalize_path("scripts/pre.sh") == "scripts/pre.sh"
    assert normalize_path("${FULLSEND_DIR}/schemas/x.json") == "schemas/x.json"
    assert normalize_path("${FULLSEND_DIR:-/opt}/schemas/x.json") is None
    assert normalize_path("${GITHUB_WORKSPACE}/target-repo") is None
    assert normalize_path("https://example.com/harness/base.yaml") is None
    assert normalize_path("/abs/path.sh") is None
    assert normalize_path("~/x.sh") is None
    assert normalize_path("   ") is None


def test_map_fullsend_with_runner_env_and_base(tmp_path: Path) -> None:
    data = {
        "base": "harness/base.yaml",
        "runner_env": {"FULLSEND_OUTPUT_SCHEMA": "${FULLSEND_DIR}/schemas/r.json", "X": "1"},
        "env": {"runner": {"X": "2"}},
    }
    f = map_fullsend(data, tmp_path / "harness" / "child.yaml")
    assert f.root_dir == tmp_path.resolve()
    assert f.base == "harness/base.yaml"
    assert f.instructions is None
    # env.runner overrides runner_env on collision, matching the runtime merge.
    assert f.env["runner"] == {"FULLSEND_OUTPUT_SCHEMA": "${FULLSEND_DIR}/schemas/r.json", "X": "2"}
    assert [r.field for r in f.refs] == ["base", "env.runner.FULLSEND_OUTPUT_SCHEMA"]


def test_parse_setup_attaches_harness_payload() -> None:
    setup = discover_setup("fs", str(FIXTURE))
    parsed = parse_setup(setup)
    assert len(parsed.harnesses) == 1
    assert parsed.harnesses[0].name == "triage"
    assert parsed.parsed(ComponentType.HARNESS) == parsed.harnesses


def test_invalid_yaml_reports_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "harness" / "bad.yaml"
    bad.parent.mkdir()
    bad.write_text("agent: agents/x.md\n  broken: [\n")
    # A broken file in harness/ stays a harness so the parse error is reported
    # instead of the component silently disappearing from the scan.
    assert is_harness_file(bad)
    elsewhere = tmp_path / "other" / "bad.yaml"
    elsewhere.parent.mkdir()
    elsewhere.write_text("agent: agents/x.md\n  broken: [\n")
    assert not is_harness_file(elsewhere)
    parsed = parse_harness(str(bad), "fullsend")
    assert parsed.fields is None
    assert parsed.parse_errors and parsed.parse_errors[0].startswith("Invalid YAML")


def test_layer_completeness_is_recorded() -> None:
    parsed = parse_harness(str(FIXTURE / "harness" / "triage.yaml"), "fullsend")
    assert parsed.fields is not None and parsed.fields.layer_complete is True
