"""Every registered rule must carry a valid tier and scope, and the gating set
is pinned to the rules validated on the corpus (see docs/rule-taxonomy.md)."""

from __future__ import annotations

import harness_eval.inspection  # noqa: F401 — triggers register_all_rules
from harness_eval.inspection.registry import get_all_rules

VALID_TIERS = {"gating", "provisional", "advisory"}
VALID_SCOPES = {"FILE", "FILE_FS", "PAIRWISE", "SETUP"}

GATING_RULES = {
    "agent/description-required",
    "claude-md/include-exists",
    "command/description-required",
    "command/script-exists",
    "content/hardcoded-machine-path",
    "cross/multi-assistant-drift",
    "cross/overpermissive-grants",
    "frontmatter/description-required",
    "frontmatter/format-valid",
    "hooks/command-script-exists",
    "hooks/json-duplicate-keys",
    "hooks/local-settings-committed",
    "hooks/permission-contradiction",
    "hooks/permission-prompt-disabled",
    "hooks/valid-structure",
    "mcp/endpoint-integrity",
    "mcp/json-duplicate-keys",
    "mcp/unpinned-package",
    "mcp/valid-config",
    "security/credential-file-present",
    "structural/skill-md-exists",
    "structural/symlink-escape",
}


def test_every_rule_has_valid_tier_and_scope() -> None:
    for rule in get_all_rules():
        meta = rule.meta
        assert meta.tier in VALID_TIERS, f"{meta.id} has invalid tier {meta.tier!r}"
        assert meta.scope in VALID_SCOPES, f"{meta.id} has invalid scope {meta.scope!r}"


def test_gating_set_matches_registry() -> None:
    gating = {r.meta.id for r in get_all_rules() if r.meta.tier == "gating"}
    assert gating == GATING_RULES
