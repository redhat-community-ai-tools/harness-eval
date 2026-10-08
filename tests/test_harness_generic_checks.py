"""Generic checks on the files a harness delivers: schema self-consistency."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from harness_eval.inspection.engine import lint_harness
from harness_eval.inspection.rules.harness.output_schema_valid import unsatisfiable_required

FIXTURE = Path(__file__).parent / "fixtures" / "sample-fullsend-setup"
SCHEMA = "harness/output-schema-valid"


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
