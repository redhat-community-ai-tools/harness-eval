"""End-to-end fixture tests: discover + inspect on every sample fixture.

Catches parser errors and zero-rule scans that unit tests miss.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness_eval.config.presets import RECOMMENDED
from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup

FIXTURES = Path(__file__).parent / "fixtures"

SAMPLE_FIXTURES = sorted(p.name for p in FIXTURES.iterdir() if p.name.startswith("sample-"))

FULL_RULE_TOOLS = {"sample-setup-a", "sample-setup-b", "sample-cursor-setup"}


@pytest.mark.parametrize("fixture_name", SAMPLE_FIXTURES)
def test_no_parser_errors(fixture_name: str) -> None:
    fixture_path = FIXTURES / fixture_name
    setup = discover_setup(name=fixture_name, path=str(fixture_path))
    results = inspect_setup(setup, RECOMMENDED)
    parser_errors = [
        d
        for r in results
        for d in r.diagnostics
        if d.rule_id == "parser" and d.severity.value == "error"
    ]
    assert parser_errors == [], f"{fixture_name}: unexpected parser errors: " + "; ".join(
        d.message for d in parser_errors
    )


@pytest.mark.parametrize("fixture_name", sorted(FULL_RULE_TOOLS))
def test_rules_actually_run(fixture_name: str) -> None:
    fixture_path = FIXTURES / fixture_name
    setup = discover_setup(name=fixture_name, path=str(fixture_path))
    results = inspect_setup(setup, RECOMMENDED)
    total_rules = sum(len(r.rules_run) for r in results)
    assert total_rules > 0, f"{fixture_name}: no rules ran on any component"
