from __future__ import annotations

from collections.abc import Iterable
from typing import Any

# Severities come from RuleMeta.default_severity so a new rule is on by default.
# The hand-maintained parts are the two override maps below. Which rules a
# command runs is not configured here at all: it is derived from
# RuleMeta.effect and RuleMeta.tier (see docs/rule-taxonomy.md), so the
# selection can never drift from what each rule declares about itself.

# Off, or severity different from default_severity.
RECOMMENDED_OVERRIDES: dict[str, str] = {
    "security/yara-signatures": "off",
    "security/cve-lookup": "off",
    "security/ast-behavioral": "warning",
    "security/bash-taint-flow": "warning",
    "security/cross-component-flow": "warning",
    "security/mcp-tool-poisoning": "warning",
    "security/taint-flow": "warning",
}

# Promotions relative to recommended. Keys absent here inherit recommended.
STRICT_OVERRIDES: dict[str, str] = {
    "agent/constraint-body-match": "error",
    "agent/disallowed-tools-parseable": "error",
    "agent/excessive-permissions": "error",
    "command/allowed-tools-coverage": "error",
    "command/references-nonexistent-skill": "error",
    "content/allowed-tools-auto-approve": "error",
    "content/circular-references": "error",
    "content/description-length": "error",
    "content/hardcoded-machine-path": "error",
    "content/token-budget": "error",
    "content/total-description-budget": "error",
    "cross/config-instruction-conflict": "error",
    "cross/overpermissive-grants": "error",
    "frontmatter/description-quality": "error",
    "frontmatter/format-valid": "error",
    "hooks/env-credential-override": "error",
    "hooks/local-settings-committed": "error",
    "hooks/matcher-matches-no-tool": "error",
    "hooks/permission-contradiction": "error",
    "hooks/pre-trust-permissions": "error",
    "hooks/silent-failure-masking": "error",
    "mcp/auto-approve-risk": "error",
    "mcp/cross-assistant-divergence": "error",
    "mcp/unpinned-package": "error",
    "mcp/valid-config": "error",
    "quality/imprecise-instruction": "error",
    "quality/redundant-guidance": "error",
    "quality/scope-grab-description": "error",
    "quality/stale-references": "error",
    "quality/unfinished-content": "error",
    "security/ast-behavioral": "error",
    "security/bash-taint-flow": "error",
    "security/cross-component-flow": "warning",
    "security/mcp-tool-poisoning": "error",
    "security/memory-write-unscoped": "error",
    "security/taint-flow": "error",
    "security/unbounded-delegation": "error",
}

# Severities the security command applies on top of recommended: YARA on (no
# network cost; the OSV lookup stays behind the command's --cve flag) and the
# code-analysis rules at error, since this command exists to surface them.
SECURITY_OVERRIDES: dict[str, str] = {
    "security/yara-signatures": "error",
    "security/ast-behavioral": "error",
    "security/bash-taint-flow": "error",
    "security/mcp-tool-poisoning": "error",
    "security/taint-flow": "error",
}


def _all_rules() -> list[Any]:
    import harness_eval.inspection  # noqa: F401 — registers all rules
    from harness_eval.inspection.registry import get_all_rules

    return get_all_rules()


def _registered_default_severities() -> dict[str, str]:
    return {r.meta.id: r.meta.default_severity.value for r in _all_rules()}


def recommended_rules() -> dict[str, str]:
    """Every registered rule at default_severity, plus RECOMMENDED_OVERRIDES."""
    rules = _registered_default_severities()
    rules.update(RECOMMENDED_OVERRIDES)
    return rules


def strict_rules() -> dict[str, str]:
    """Recommended, with STRICT_OVERRIDES applied on top."""
    rules = recommended_rules()
    rules.update(STRICT_OVERRIDES)
    return rules


RECOMMENDED: dict[str, str] = recommended_rules()
STRICT: dict[str, str] = strict_rules()

PRESETS: dict[str, dict[str, str]] = {
    "recommended": RECOMMENDED,
    "strict": STRICT,
}

PRESET_NAMES: tuple[str, ...] = tuple(PRESETS)


def select_rules(
    *,
    effects: Iterable[str],
    tiers: Iterable[str] | None = None,
    categories: Iterable[str] | None = None,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Severity map for the rules matching every given filter.

    ``effects`` is required; ``tiers`` and ``categories`` narrow further when
    given. Severities come from ``base`` (default: recommended).
    """
    severities = base if base is not None else RECOMMENDED
    effect_set = set(effects)
    tier_set = set(tiers) if tiers is not None else None
    category_set = set(categories) if categories is not None else None
    selected: dict[str, str] = {}
    for r in _all_rules():
        if r.meta.effect not in effect_set:
            continue
        if tier_set is not None and r.meta.tier not in tier_set:
            continue
        if category_set is not None and r.meta.category.value not in category_set:
            continue
        selected[r.meta.id] = severities.get(r.meta.id, r.meta.default_severity.value)
    return selected


def gate_rules(include_provisional: bool = False) -> dict[str, str]:
    """Rules for ``harness-gate``: effect=block, tier=gating (plus provisional
    on request). A changed rule declaration changes the gate; nothing else does."""
    tiers = ("gating", "provisional") if include_provisional else ("gating",)
    return select_rules(effects=("block",), tiers=tiers)


def autonomy_rules() -> dict[str, str]:
    """Rules for ``harness-autonomy``: every decidable rule (effect block or
    policy) that has passed the corpus (tier gating or provisional). Heuristic
    (signal) and advice rules never take part."""
    return select_rules(effects=("block", "policy"), tiers=("gating", "provisional"))


def security_rules() -> dict[str, str]:
    """Rules for ``harness-security``: every policy and signal rule, plus the
    block rules whose category is security (secrets, credential files,
    endpoint integrity, symlink escape). Advice rules never take part."""
    rules = select_rules(effects=("policy", "signal"))
    rules.update(select_rules(effects=("block",), categories=("security",)))
    for rid, sev in SECURITY_OVERRIDES.items():
        if rid in rules:
            rules[rid] = sev
    return rules


def lint_rules(preset: str = "recommended", *, everything: bool = False) -> dict[str, str]:
    """Rules for ``harness-lint``: advice rules by default, or every rule with
    ``everything``. Severities follow the named preset."""
    base = PRESETS.get(preset, RECOMMENDED)
    if everything:
        return dict(base)
    return select_rules(effects=("advice",), base=base)


__all__ = [
    "PRESETS",
    "PRESET_NAMES",
    "RECOMMENDED",
    "STRICT",
    "RECOMMENDED_OVERRIDES",
    "STRICT_OVERRIDES",
    "SECURITY_OVERRIDES",
    "autonomy_rules",
    "gate_rules",
    "lint_rules",
    "recommended_rules",
    "security_rules",
    "select_rules",
    "strict_rules",
]
