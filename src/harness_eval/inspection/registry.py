from __future__ import annotations

import logging
from difflib import get_close_matches
from dataclasses import dataclass, field
from importlib.metadata import entry_points

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import Rule, RuleCategory

logger = logging.getLogger(__name__)

@dataclass
class RuleCatalog:
    """An isolated collection of rules for one application or scan.

    The old module-level functions remain as compatibility helpers, but new
    code should pass a catalog explicitly.  Keeping scan-local catalogs avoids
    target-provided YAML rules leaking across concurrent or repeated scans.
    """

    _rules: dict[str, Rule] = field(default_factory=dict)
    _target_index: dict[ComponentType, tuple[Rule, ...]] = field(
        default_factory=dict, init=False, repr=False
    )

    def register(self, rule: Rule) -> None:
        if rule.meta.id in self._rules:
            raise ValueError(f'Rule "{rule.meta.id}" already registered')
        self._rules[rule.meta.id] = rule
        self._target_index.clear()

    def unregister(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)
        self._target_index.clear()

    def all(self) -> list[Rule]:
        return list(self._rules.values())

    def by_category(self, category: RuleCategory) -> list[Rule]:
        return [r for r in self._rules.values() if r.meta.category == category]

    def for_target(self, component_type: ComponentType) -> tuple[Rule, ...]:
        """Return the rules applicable to a component type using a cached index."""
        if component_type not in self._target_index:
            self._target_index[component_type] = tuple(
                rule for rule in self._rules.values() if rule.meta.target_type == component_type
            )
        return self._target_index[component_type]

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def suggest(self, rule_id: str) -> list[str]:
        return get_close_matches(rule_id, self._rules.keys(), n=3, cutoff=0.6)

    def copy(self) -> "RuleCatalog":
        """Return a catalog with the same rule instances and independent storage."""
        return RuleCatalog(dict(self._rules))

    def clear(self) -> None:
        self._rules.clear()
        self._target_index.clear()

    def load_entry_points(self, group: str = "harness_eval.rules") -> int:
        """Load installed third-party rule providers into this catalog.

        Providers may expose a Rule instance/class or a callable accepting the
        catalog. Installed Python packages are trusted application extensions;
        target repositories still only contribute declarative YAML rules.
        """
        loaded = 0
        for entry_point in entry_points().select(group=group):
            try:
                provider = entry_point.load()
                if callable(provider) and not hasattr(provider, "meta"):
                    result = provider(self)
                    if isinstance(result, RuleCatalog):
                        loaded += len(result.all())
                    elif result is not None:
                        loaded += 1
                else:
                    rule = provider() if isinstance(provider, type) else provider
                    if hasattr(rule, "meta"):
                        self.register(rule)
                        loaded += 1
            except Exception:  # pragma: no cover - provider failures are isolated
                logger.exception("Failed to load harness-eval rule plugin %s", entry_point.name)
        return loaded


_registry = RuleCatalog()


def get_default_catalog() -> RuleCatalog:
    """Return the process default catalog used by legacy convenience APIs."""
    return _registry

# Rule IDs that have been removed. A config or suppression that still references
# one gets a deprecation warning (pointing at the replacement) instead of the
# generic "unknown rule" warning, and never an error.
DEPRECATED_RULES: dict[str, str] = {
    "mcp/duplicate-server": "mcp/json-duplicate-keys",
}


def register_rule(rule: Rule) -> None:
    _registry.register(rule)


def unregister_rule(rule_id: str) -> None:
    _registry.unregister(rule_id)


def get_all_rules() -> list[Rule]:
    return _registry.all()


def get_rules_by_category(category: RuleCategory) -> list[Rule]:
    return _registry.by_category(category)


def get_rule(rule_id: str) -> Rule | None:
    return _registry.get(rule_id)


def suggest_rule_id(rule_id: str) -> list[str]:
    """Return similar rule IDs for a non-matching ID."""
    return _registry.suggest(rule_id)


def clear_rules() -> None:
    _registry.clear()
