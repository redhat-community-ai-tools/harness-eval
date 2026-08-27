"""Every registered rule must carry a valid tier and scope, and the gating set
is pinned to the rules validated on the corpus (see docs/rule-taxonomy.md)."""

from __future__ import annotations

import harness_eval.inspection  # noqa: F401 — triggers register_all_rules
from harness_eval.inspection.registry import get_all_rules

VALID_TIERS = {"gating", "provisional", "advisory"}
VALID_SCOPES = {"FILE", "FILE_FS", "PAIRWISE", "SETUP"}

GATING_RULES = {
    "mcp/unpinned-package",
    "cross/overpermissive-grants",
    "content/hardcoded-machine-path",
    "cross/multi-assistant-drift",
    "agent/description-required",
    "frontmatter/format-valid",
}


def test_every_rule_has_valid_tier_and_scope() -> None:
    for rule in get_all_rules():
        meta = rule.meta
        assert meta.tier in VALID_TIERS, f"{meta.id} has invalid tier {meta.tier!r}"
        assert meta.scope in VALID_SCOPES, f"{meta.id} has invalid scope {meta.scope!r}"


def test_gating_set_matches_registry() -> None:
    gating = {r.meta.id for r in get_all_rules() if r.meta.tier == "gating"}
    assert gating == GATING_RULES
