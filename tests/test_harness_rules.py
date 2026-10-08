"""Rules on pipeline agent harness definitions."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup, lint_harness

FIXTURE = Path(__file__).parent / "fixtures" / "sample-fullsend-setup"
RULE = "harness/referenced-file-exists"


def _findings(result, rule=RULE):
    return [d for d in result.diagnostics if d.rule_id == rule]


def _scaffold(tmp_path: Path) -> Path:
    dst = tmp_path / "scaffold"
    shutil.copytree(FIXTURE, dst)
    return dst


def _harness(root: Path) -> Path:
    return root / "harness" / "triage.yaml"


def test_clean_fixture_has_no_findings() -> None:
    result = lint_harness(str(_harness(FIXTURE)), source_tool="fullsend")
    assert _findings(result) == []
    assert any(r.rule_id == RULE and r.passed for r in result.rules_run)


def test_missing_agent_prompt_is_reported(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    (root / "agents" / "triage.md").unlink()
    result = lint_harness(str(_harness(root)), source_tool="fullsend")
    found = _findings(result)
    assert len(found) == 1
    assert found[0].data == {
        "field": "agent",
        "ref": "agents/triage.md",
        "kind": "the file",
        "root": str(root.resolve()),
    }
    assert found[0].location.start_line == 3


def test_every_reference_kind_is_checked(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    shutil.rmtree(root / "skills" / "issue-labels")
    shutil.rmtree(root / "plugins" / "gopls-lsp")
    (root / "policies" / "base.yaml").unlink()
    (root / "scripts" / "validate-output-schema.sh").unlink()
    (root / "schemas" / "triage-result.schema.json").unlink()
    result = lint_harness(str(_harness(root)), source_tool="fullsend")
    fields = sorted(d.data["field"] for d in _findings(result))
    assert fields == [
        "env.runner.FULLSEND_OUTPUT_SCHEMA",
        "plugins[0]",
        "policy",
        "skills[0]",
        "validation_loop.script",
    ]


def test_forge_override_script_is_checked(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    h = _harness(root)
    h.write_text(
        h.read_text().replace(
            "    post_script: scripts/post-triage.sh", "    post_script: scripts/post-github.sh"
        )
    )
    result = lint_harness(str(h), source_tool="fullsend")
    assert [d.data["field"] for d in _findings(result)] == ["forge.github.post_script"]


def test_skill_must_be_a_directory_not_a_file(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    shutil.rmtree(root / "skills" / "issue-labels")
    (root / "skills" / "issue-labels").write_text("not a directory\n")
    result = lint_harness(str(_harness(root)), source_tool="fullsend")
    assert [d.data["field"] for d in _findings(result)] == ["skills[0]"]
    assert "the directory" in _findings(result)[0].message


def test_optional_and_host_variable_sources_are_never_reported(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    # env/vertex.env never existed in the fixture: it is optional. The second
    # host file is a ${VAR} path. Neither is decidable, neither is reported.
    assert not (root / "env").exists()
    result = lint_harness(str(_harness(root)), source_tool="fullsend")
    assert _findings(result) == []


def test_url_base_disables_the_rule(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    (root / "agents" / "triage.md").unlink()
    h = _harness(root)
    h.write_text("base: https://example.com/harness/base.yaml\n" + h.read_text().lstrip("-\n"))
    result = lint_harness(str(h), source_tool="fullsend")
    assert _findings(result) == []


def test_local_base_is_a_reference(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    h = _harness(root)
    h.write_text("base: harness/base.yaml\n" + h.read_text().lstrip("-\n"))
    result = lint_harness(str(h), source_tool="fullsend")
    assert [d.data["field"] for d in _findings(result)] == ["base"]
    (root / "harness" / "base.yaml").write_text("role: triage\n")
    assert _findings(lint_harness(str(h), source_tool="fullsend")) == []


def test_path_escaping_root_is_reported(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    h = _harness(root)
    h.write_text(h.read_text().replace("policy: policies/base.yaml", "policy: ../../etc/passwd"))
    result = lint_harness(str(h), source_tool="fullsend")
    found = _findings(result)
    assert len(found) == 1 and "outside the harness root" in found[0].message


def test_inspect_setup_runs_the_rule_on_discovered_harnesses(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    (root / "scripts" / "pre-triage.sh").unlink()
    setup = discover_setup("fs", str(root))
    results = inspect_setup(setup)
    harness_results = [r for r in results if r.target_type == "harness"]
    assert len(harness_results) == 1
    fields = sorted(d.data["field"] for d in _findings(harness_results[0]))
    assert fields == ["forge.github.pre_script", "pre_script"]


def test_unknown_format_yields_no_fields_and_no_findings(tmp_path: Path) -> None:
    h = tmp_path / "harness" / "x.yaml"
    h.parent.mkdir()
    h.write_text("agent: agents/missing.md\n")
    result = lint_harness(str(h), source_tool=None)
    assert _findings(result) == []


def test_json_output_groups_harness_results(tmp_path: Path) -> None:
    from harness_eval.analysis.system import analyze_system
    from harness_eval.output.report import format_json

    root = _scaffold(tmp_path)
    setup = discover_setup("fs", str(root))
    results = inspect_setup(setup)
    data = json.loads(format_json(analyze_system(setup), results))
    assert "harness" in data["inspection"]
    assert data["inspection"]["harness"][0]["name"] == "triage"


def test_overlay_layer_is_not_checked(tmp_path: Path) -> None:
    """A per-repo overlay references files that upstream layers provide."""
    overlay = tmp_path / ".fullsend" / "customized"
    (overlay / "harness").mkdir(parents=True)
    (overlay / "agents").mkdir()
    (overlay / "agents" / "my-agent.md").write_text("---\nname: my-agent\n---\nBody\n")
    (overlay / "harness" / "my-agent.yaml").write_text(
        "agent: customized/agents/my-agent.md\n"
        "policy: policies/base.yaml\n"  # provided by the upstream layer
        "pre_script: scripts/pre-code.sh\n"
    )
    result = lint_harness(str(overlay / "harness" / "my-agent.yaml"), source_tool="fullsend")
    assert _findings(result) == []
    from harness_eval.inspection.harness_formats.fullsend import scaffold_root

    root, overlay_flag = scaffold_root(overlay / "harness" / "my-agent.yaml")
    assert root == (tmp_path / ".fullsend").resolve() and overlay_flag is True


def test_org_config_layer_is_not_checked(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    (root / "config.yaml").write_text("repos: []\n")
    (root / "agents" / "triage.md").unlink()
    assert _findings(lint_harness(str(_harness(root)), source_tool="fullsend")) == []


def test_partial_layer_without_scripts_dir_is_not_checked(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    shutil.rmtree(root / "scripts")
    assert _findings(lint_harness(str(_harness(root)), source_tool="fullsend")) == []
