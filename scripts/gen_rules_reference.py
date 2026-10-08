#!/usr/bin/env python3
"""Generate the effect/tier/scope tables in docs/rules-reference.md and README.md
from the rule registry, so they can never drift from RuleMeta.

Run after changing any rule's effect, tier or scope:

    uv run scripts/gen_rules_reference.py

The generated blocks are delimited by
``<!-- BEGIN GENERATED: <name> -->`` / ``<!-- END GENERATED: <name> -->`` markers.
tests/test_doc_counts.py imports the render functions below and asserts the
committed files still match the registry.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import harness_eval.inspection  # noqa: F401 — registers all rules
from harness_eval.inspection.registry import get_all_rules

ROOT = Path(__file__).resolve().parent.parent

TIER_ORDER = ["gating", "provisional", "advisory"]
SCOPE_ORDER = ["FILE", "FILE_FS", "PAIRWISE", "SETUP"]
EFFECT_ORDER = ["block", "policy", "signal", "advice"]


def render_rule_table() -> str:
    rows = [
        "| Rule | Effect | Tier | Scope | Target |",
        "|------|--------|------|-------|--------|",
    ]
    for r in sorted(get_all_rules(), key=lambda x: x.meta.id):
        rows.append(
            f"| `{r.meta.id}` | {r.meta.effect} | {r.meta.tier} | {r.meta.scope} "
            f"| {r.meta.target_label} |"
        )
    return "\n".join(rows)


def render_effect_counts() -> str:
    counts = Counter(r.meta.effect for r in get_all_rules())
    rows = ["| Effect | Rules | Run by |", "|--------|-------|--------|"]
    run_by = {
        "block": "`harness-gate`, `harness-autonomy`, `harness-security` (security category)",
        "policy": "`harness-autonomy` (REVIEW_REQUIRED), `harness-security`",
        "signal": "`harness-security`",
        "advice": "`harness-lint`",
    }
    rows += [f"| {e} | {counts.get(e, 0)} | {run_by[e]} |" for e in EFFECT_ORDER]
    return "\n".join(rows)


def render_autonomy_rules() -> str:
    """The exact rule list harness-autonomy runs, grouped by effect."""
    rules = [
        r
        for r in get_all_rules()
        if r.meta.effect in ("block", "policy") and r.meta.tier in ("gating", "provisional")
    ]
    rows = [
        "| Rule | Effect | Tier | Target | What it decides |",
        "|------|--------|------|--------|-----------------|",
    ]
    for r in sorted(rules, key=lambda x: (x.meta.effect, x.meta.id)):
        rows.append(
            f"| `{r.meta.id}` | {r.meta.effect} | {r.meta.tier} | {r.meta.target_label} "
            f"| {r.meta.description} |"
        )
    return "\n".join(rows)


def render_tier_counts() -> str:
    counts = Counter(r.meta.tier for r in get_all_rules())
    rows = ["| Tier | Rules |", "|------|-------|"]
    rows += [f"| {t} | {counts.get(t, 0)} |" for t in TIER_ORDER]
    return "\n".join(rows)


def render_scope_counts() -> str:
    counts = Counter(r.meta.scope for r in get_all_rules())
    rows = ["| Scope | Rules |", "|-------|-------|"]
    rows += [f"| {s} | {counts.get(s, 0)} |" for s in SCOPE_ORDER]
    return "\n".join(rows)


def replace_block(text: str, marker: str, body: str) -> str:
    begin = f"<!-- BEGIN GENERATED: {marker} -->"
    end = f"<!-- END GENERATED: {marker} -->"
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
    if not pattern.search(text):
        raise SystemExit(f"Marker {marker!r} not found in target file")
    return pattern.sub(f"{begin}\n{body}\n{end}", text)


def apply() -> None:
    ref = ROOT / "docs" / "rules-reference.md"
    ref.write_text(replace_block(ref.read_text(), "rule-tiers", render_rule_table()))

    ref.write_text(replace_block(ref.read_text(), "autonomy-rules", render_autonomy_rules()))

    readme = ROOT / "README.md"
    text = readme.read_text()
    text = replace_block(text, "effect-counts", render_effect_counts())
    text = replace_block(text, "tier-counts", render_tier_counts())
    text = replace_block(text, "scope-counts", render_scope_counts())
    readme.write_text(text)


if __name__ == "__main__":
    apply()
    print("Regenerated tier/scope tables in docs/rules-reference.md and README.md")
