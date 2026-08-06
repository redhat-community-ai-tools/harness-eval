"""Versioned data files for knowledge that decays over time."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_DATA_DIR = Path(__file__).parent

_capabilities_cache: CapabilityTaxonomy | None = None


@dataclass(frozen=True)
class CapabilityTaxonomy:
    """Structured access to the capabilities taxonomy."""

    _raw: dict[str, object] = field(repr=False)

    def python_sources(self, category: str) -> set[str]:
        sources = self._raw.get("sources", {})
        cat = sources.get(category, {})
        return set(cat.get("python", []))

    def all_python_sources(self) -> set[str]:
        result: set[str] = set()
        for cat in self._raw.get("sources", {}).values():
            result.update(cat.get("python", []))
        return result

    def python_sinks(self, category: str) -> set[str]:
        sinks = self._raw.get("sinks", {})
        cat = sinks.get(category, {})
        return set(cat.get("python", []))

    def all_python_sinks(self) -> set[str]:
        result: set[str] = set()
        for cat in self._raw.get("sinks", {}).values():
            result.update(cat.get("python", []))
        return result

    def bash_taint_sources(self) -> list[tuple[re.Pattern[str], str]]:
        items = self._raw.get("bash_taint", {}).get("sources", [])
        return [(re.compile(item["pattern"]), item["label"]) for item in items]

    def bash_taint_sinks(self) -> list[tuple[re.Pattern[str], str]]:
        items = self._raw.get("bash_taint", {}).get("sinks", [])
        return [(re.compile(item["pattern"]), item["label"]) for item in items]

    def bash_self_contained(self) -> list[tuple[re.Pattern[str], str]]:
        items = self._raw.get("bash_taint", {}).get("self_contained", [])
        return [(re.compile(item["pattern"]), item["label"]) for item in items]

    def capability_patterns(self) -> dict[str, list[re.Pattern[str]]]:
        raw = self._raw.get("capability_patterns", {})
        result: dict[str, list[re.Pattern[str]]] = {}
        for cap, patterns in raw.items():
            result[cap] = [re.compile(p["pattern"], re.I) for p in patterns]
        return result

    def tool_to_capability(self) -> dict[str, set[str]]:
        raw = self._raw.get("tool_to_capability", {})
        return {tool: set(caps) for tool, caps in raw.items()}


def load_capabilities() -> CapabilityTaxonomy:
    global _capabilities_cache
    if _capabilities_cache is not None:
        return _capabilities_cache
    data = yaml.safe_load((_DATA_DIR / "capabilities.yaml").read_text())
    _capabilities_cache = CapabilityTaxonomy(_raw=data)
    return _capabilities_cache


def load_builtins() -> set[str]:
    data = json.loads((_DATA_DIR / "builtins.json").read_text())
    return set(data["claude_code_commands"])


def load_secret_prefixes() -> list[str]:
    data = json.loads((_DATA_DIR / "secret_prefixes.json").read_text())
    return list(data)


def load_tool_names() -> list[str]:
    data = json.loads((_DATA_DIR / "tool_names.json").read_text())
    return list(data)


def load_tautological_patterns(
    *,
    generic_advice_only: bool = False,
) -> list[tuple[str, re.Pattern[str]]]:
    data = json.loads((_DATA_DIR / "tautological_patterns.json").read_text())
    patterns = data["patterns"]
    if generic_advice_only:
        patterns = [p for p in patterns if p.get("generic_advice")]
    return [(p["label"], re.compile(p["regex"], re.I)) for p in patterns]
