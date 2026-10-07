"""Second batch of harness rules: output contract, schema validity, host-file collisions."""

from __future__ import annotations

import shutil
from pathlib import Path

from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup, lint_harness
from harness_eval.inspection.parsers import parse_harness

FIXTURE = Path(__file__).parent / "fixtures" / "sample-fullsend-setup"
CONTRACT = "harness/output-contract-instructed"
SCHEMA = "harness/output-schema-valid"
COLLISION = "harness/host-file-dest-collision"


def _findings(result, rule):
    return [d for d in result.diagnostics if d.rule_id == rule]


def _scaffold(tmp_path: Path) -> Path:
    dst = tmp_path / "scaffold"
    shutil.copytree(FIXTURE, dst)
    return dst


def _harness(root: Path) -> Path:
    return root / "harness" / "triage.yaml"


def _lint(root: Path):
    return lint_harness(str(_harness(root)), source_tool="fullsend")


def _strip_mentions(root: Path) -> None:
    """Remove every output-contract mention from the fixture's instructions."""
    prompt = root / "agents" / "triage.md"
    prompt.write_text(
        "---\nname: triage\ndescription: Triage specialist.\n---\n\nRead the issue and decide.\n"
    )


# --- output-contract-instructed -------------------------------------------------


def test_contract_tokens_are_derived_from_the_declaration() -> None:
    parsed = parse_harness(str(_harness(FIXTURE)), "fullsend")
    assert parsed.fields is not None
    assert parsed.fields.output_contract_tokens == [
        "FULLSEND_OUTPUT_DIR",
        "FULLSEND_OUTPUT_FILE",
        "FULLSEND_OUTPUT_SCHEMA",
        "fullsend-check-output",
        "triage-result.json",
        "triage-result.schema.json",
    ]


def test_clean_fixture_mentions_the_contract() -> None:
    assert _findings(_lint(FIXTURE), CONTRACT) == []


def test_contract_without_any_mention_is_reported(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    _strip_mentions(root)
    found = _findings(_lint(root), CONTRACT)
    assert len(found) == 1
    assert found[0].data["contract"] == "${FULLSEND_DIR}/schemas/triage-result.schema.json"
    assert found[0].data["count"] == 2  # prompt + skill
    assert "triage-result.json" in found[0].data["tokens"]
    assert found[0].location.start_line is not None


def test_mention_in_a_listed_skill_is_enough(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    _strip_mentions(root)
    skill = root / "skills" / "issue-labels" / "SKILL.md"
    skill.write_text(
        skill.read_text() + "\nWrite the result to `$FULLSEND_OUTPUT_DIR/triage-result.json`.\n"
    )
    assert _findings(_lint(root), CONTRACT) == []


def test_mention_in_a_skill_sub_file_is_enough(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    _strip_mentions(root)
    (root / "skills" / "issue-labels" / "output.md").write_text("Run fullsend-check-output.\n")
    assert _findings(_lint(root), CONTRACT) == []


def test_mention_in_shared_instruction_file_is_enough(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    _strip_mentions(root)
    (root / "AGENTS.md").write_text(
        "Every agent writes agent-result.json to FULLSEND_OUTPUT_DIR.\n"
    )
    assert _findings(_lint(root), CONTRACT) == []


def test_default_output_file_name_counts_when_none_is_declared(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    _strip_mentions(root)
    h = _harness(root)
    h.write_text(h.read_text().replace("    FULLSEND_OUTPUT_FILE: triage-result.json\n", ""))
    assert "agent-result.json" in parse_harness(str(h), "fullsend").fields.output_contract_tokens
    (root / "agents" / "triage.md").write_text("---\nname: t\n---\nWrite agent-result.json.\n")
    assert _findings(_lint(root), CONTRACT) == []


def test_no_contract_means_no_finding(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    _strip_mentions(root)
    h = _harness(root)
    text = h.read_text()
    text = text.replace(
        "    FULLSEND_OUTPUT_SCHEMA: ${FULLSEND_DIR}/schemas/triage-result.schema.json\n", ""
    )
    text = text.replace("    FULLSEND_OUTPUT_FILE: triage-result.json\n", "")
    h.write_text(text)
    assert parse_harness(str(h), "fullsend").fields.output_contract_tokens == []
    assert _findings(_lint(root), CONTRACT) == []


def test_silent_when_instructions_may_come_from_elsewhere(tmp_path: Path) -> None:
    for extra in (
        "base: harness/base.yaml\n",
        "agent_input: inputs\n",
        "allow_runtime_fetch: true\n",
    ):
        root = _scaffold(tmp_path / extra.split(":")[0])
        _strip_mentions(root)
        h = _harness(root)
        h.write_text(extra + h.read_text().lstrip("-\n"))
        (root / "harness" / "base.yaml").write_text("role: triage\n")
        (root / "inputs").mkdir(exist_ok=True)
        assert _findings(_lint(root), CONTRACT) == [], extra


def test_silent_when_a_listed_instruction_file_is_missing(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    _strip_mentions(root)
    shutil.rmtree(root / "skills" / "issue-labels")
    assert _findings(_lint(root), CONTRACT) == []


def test_silent_on_incomplete_layer(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    _strip_mentions(root)
    (root / "config.yaml").write_text("repos: []\n")
    assert _findings(_lint(root), CONTRACT) == []


# --- output-schema-valid ---------------------------------------------------------


def test_valid_schema_passes() -> None:
    assert _findings(_lint(FIXTURE), SCHEMA) == []


def test_invalid_json_schema_is_reported(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    (root / "schemas" / "triage-result.schema.json").write_text('{"type": "object",\n')
    found = _findings(_lint(root), SCHEMA)
    assert len(found) == 1
    assert found[0].data["ref"] == "schemas/triage-result.schema.json"
    assert "line 2" in found[0].message


def test_non_object_schema_is_reported(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    (root / "schemas" / "triage-result.schema.json").write_text("[1, 2]\n")
    found = _findings(_lint(root), SCHEMA)
    assert len(found) == 1 and found[0].data["kind"] == "list"


def test_missing_schema_is_not_this_rules_finding(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    (root / "schemas" / "triage-result.schema.json").unlink()
    assert _findings(_lint(root), SCHEMA) == []


def test_validation_loop_schema_key_is_checked(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    (root / "schemas" / "loop.json").write_text("not json")
    h = _harness(root)
    h.write_text(
        h.read_text().replace(
            "  max_iterations: 2\n", "  max_iterations: 2\n  schema: schemas/loop.json\n"
        )
    )
    found = _findings(_lint(root), SCHEMA)
    assert [d.data["ref"] for d in found] == ["schemas/loop.json"]


# --- host-file-dest-collision ----------------------------------------------------


def test_distinct_destinations_pass() -> None:
    assert _findings(_lint(FIXTURE), COLLISION) == []


def test_duplicate_destination_is_reported(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    h = _harness(root)
    h.write_text(
        h.read_text().replace(
            "skills:\n",
            "  - src: ${EXTRA_CREDENTIALS}\n    dest: /tmp/.gcp-credentials.json\n\nskills:\n",
        )
    )
    found = _findings(_lint(root), COLLISION)
    assert len(found) == 1
    assert found[0].data == {
        "first": "${GOOGLE_APPLICATION_CREDENTIALS}",
        "second": "${EXTRA_CREDENTIALS}",
        "dest": "/tmp/.gcp-credentials.json",
    }
    assert found[0].location.start_line is not None


def test_optional_entries_never_collide(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    h = _harness(root)
    h.write_text(
        h.read_text().replace(
            "skills:\n",
            "  - src: ${EXTRA_CREDENTIALS}\n    dest: /tmp/.gcp-credentials.json\n"
            "    optional: true\n\nskills:\n",
        )
    )
    assert _findings(_lint(root), COLLISION) == []


def test_rules_run_through_inspect_setup(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    results = [
        r for r in inspect_setup(discover_setup("fs", str(root))) if r.target_type == "harness"
    ]
    ran = {rr.rule_id for rr in results[0].rules_run}
    assert {CONTRACT, SCHEMA, COLLISION} <= ran
