from __future__ import annotations

import logging
from difflib import get_close_matches

from harness_eval.inspection.types import Rule, RuleCategory

logger = logging.getLogger(__name__)

_registry: dict[str, Rule] = {}

# Rule IDs that have been removed. A config or suppression that still references
# one gets a deprecation warning (pointing at the replacement) instead of the
# generic "unknown rule" warning, and never an error.
DEPRECATED_RULES: dict[str, str] = {
    "mcp/duplicate-server": "mcp/json-duplicate-keys",
}


def register_rule(rule: Rule) -> None:
    if rule.meta.id in _registry:
        raise ValueError(f'Rule "{rule.meta.id}" already registered')
    _registry[rule.meta.id] = rule


def get_all_rules() -> list[Rule]:
    return list(_registry.values())


def get_rules_by_category(category: RuleCategory) -> list[Rule]:
    return [r for r in _registry.values() if r.meta.category == category]


def get_rule(rule_id: str) -> Rule | None:
    return _registry.get(rule_id)


def suggest_rule_id(rule_id: str) -> list[str]:
    """Return similar rule IDs for a non-matching ID."""
    return get_close_matches(rule_id, _registry.keys(), n=3, cutoff=0.6)


def clear_rules() -> None:
    _registry.clear()
