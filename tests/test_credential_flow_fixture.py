"""End-to-end test: genuine credential-to-network invocation edge is still detected."""

from __future__ import annotations

from pathlib import Path

from harness_eval.config.presets import PRESETS
from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup

FIXTURE = Path(__file__).parent / "fixtures" / "corpus" / "credential-flow"


def test_genuine_credential_flow_detected() -> None:
    setup = discover_setup(FIXTURE.name, str(FIXTURE))
    results = inspect_setup(setup, config_rules=PRESETS["security"])
    rule_ids = {d.rule_id for r in results for d in r.diagnostics}
    assert "security/cross-component-flow" in rule_ids, (
        f"Expected cross-component-flow finding, got: {sorted(rule_ids)}"
    )
