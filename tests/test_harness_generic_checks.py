"""Generic checks on the files a harness delivers: schema self-consistency
and .env syntax."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from harness_eval.inspection.engine import lint_harness
from harness_eval.inspection.rules.harness.host_file_env_syntax import malformed_env_lines
from harness_eval.inspection.rules.harness.output_schema_valid import unsatisfiable_required

FIXTURE = Path(__file__).parent / "fixtures" / "sample-fullsend-setup"
SCHEMA = "harness/output-schema-valid"
ENV = "harness/host-file-env-syntax"


def _scaffold(tmp_path: Path) -> Path:
    dst = tmp_path / "scaffold"
    shutil.copytree(FIXTURE, dst)
    return dst


def _diags(result, rule):
    return [d for d in result.diagnostics if d.rule_id == rule]


def test_unsatisfiable_required_only_when_nothing_can_admit_the_key() -> None:
    closed = {
        "type": "object",
        "additionalProperties": False,
        "required": ["a", "b"],
        "properties": {"a": {"type": "string"}},
    }
    assert unsatisfiable_required(closed) == [("root", "b")]
    open_schema = {**closed, "additionalProperties": True}
    assert unsatisfiable_required(open_schema) == []
    patterned = {**closed, "patternProperties": {"^b": {}}}
    assert unsatisfiable_required(patterned) == []
    nested = {"type": "object", "properties": {"inner": closed}, "items": [closed]}
    assert unsatisfiable_required(nested) == [("root.inner", "b"), ("root.items[0]", "b")]


def test_schema_rule_reports_unsatisfiable_required(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    schema = root / "schemas" / "triage-result.schema.json"
    schema.write_text(
        json.dumps(
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["category", "confidence"],
                "properties": {"category": {"type": "string"}},
            }
        )
    )
    result = lint_harness(
        str(root / "harness" / "triage.yaml"), {SCHEMA: "error"}, source_tool="fullsend"
    )
    found = _diags(result, SCHEMA)
    assert [(d.data["path"], d.data["key"]) for d in found] == [("root", "confidence")]


def test_schema_rule_is_silent_on_the_fixture(tmp_path: Path) -> None:
    result = lint_harness(
        str(FIXTURE / "harness" / "triage.yaml"), {SCHEMA: "error"}, source_tool="fullsend"
    )
    assert _diags(result, SCHEMA) == []


def test_malformed_env_lines_tolerates_comments_exports_and_quoted_values() -> None:
    text = "# comment\nA=1\nexport B=two words\nC=\"multi\nline\"\n\nD='x'\nset -x\nE\nF=${G}\n"
    assert malformed_env_lines(text) == [(8, "set -x"), (9, "E")]


def test_env_rule_reports_bad_lines_in_delivered_env_file(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    (root / "env").mkdir()
    (root / "env" / "vertex.env").write_text(
        "CLOUDSDK_CORE_PROJECT=${GCP_PROJECT}\nsource other.env\n"
    )
    result = lint_harness(
        str(root / "harness" / "triage.yaml"), {ENV: "error"}, source_tool="fullsend"
    )
    found = _diags(result, ENV)
    assert len(found) == 1
    assert found[0].data == {"src": "env/vertex.env", "line": 2, "text": "source other.env"}
    assert found[0].location.start_line == 2


def test_env_rule_is_silent_on_clean_or_missing_env_file(tmp_path: Path) -> None:
    root = _scaffold(tmp_path)
    harness = root / "harness" / "triage.yaml"
    assert _diags(lint_harness(str(harness), {ENV: "error"}, source_tool="fullsend"), ENV) == []
    (root / "env").mkdir()
    (root / "env" / "vertex.env").write_text("# vertex\nA=1\nexport B=2\n")
    assert _diags(lint_harness(str(harness), {ENV: "error"}, source_tool="fullsend"), ENV) == []
