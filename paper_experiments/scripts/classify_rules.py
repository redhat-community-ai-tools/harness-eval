#!/usr/bin/env python3
"""Classify every harness-eval rule by the analysis scope its detection requires.

Scope is decided from what a rule's implementation consumes:
  FILE      the bytes of one component only
  FILE_FS   one component plus the surrounding filesystem
  PAIRWISE  a comparison between two components
  SETUP     the whole component graph or an aggregate over all components

An automated pass reads each rule's source for the signals below. A manual
override table (OVERRIDES) records rules whose signals are misleading, with the
reason. Both the automated and the final classification are written to
data/rule_scope.json so the correction can be audited.
"""
from __future__ import annotations

import importlib
import inspect
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "rule_scope.json"

import harness_eval.inspection  # noqa: E402,F401
from harness_eval.inspection.registry import get_all_rules  # noqa: E402

# A rule is SETUP when it builds or traverses a structure over all components;
# PAIRWISE when it compares the target against one other component at a time;
# FILE_FS when it touches the filesystem beyond the target's own text.
SETUP_SIGNALS = [r"component_graph", r"build_graph", r"_find_cycles", r"graph\[", r"graph:\s*dict",
                 r"sum\(.*for .* in context\.all_skills", r"total_tokens", r"reachab"]
PAIR_SIGNALS = [r"tfidf_similarity", r"_split_sections", r"for other in", r"other_skill", r"other_cmd",
                r"for .* in context\.all_(skills|commands)"]
FS_SIGNALS = [r"\.is_file\(\)", r"\.exists\(\)", r"\.is_dir\(\)", r"os\.walk", r"\.glob\(", r"read_text\(",
              r"Path\(", r"os\.path\.(exists|isfile)", r"open\("]

# Hand corrections. A rule that reads a settings file looks global because
# settings govern the whole project, but it consumes one component: FILE.
# A rule that iterates all components while applying an independent per-file
# check looks compositional but judges each locally: FILE.
OVERRIDES: dict[str, tuple[str, str]] = {
    "cross/overpermissive-grants": ("FILE", "reads one settings file; each entry is judged on its own text"),
    "hooks/permission-contradiction": ("FILE", "compares two lists inside one settings file"),
    "hooks/permission-prompt-disabled": ("FILE", "key presence in one settings file"),
    "hooks/local-settings-committed": ("FILE_FS", "presence of a sibling file"),
    "security/dangerous-permission-grant": ("FILE", "pattern match on one settings file"),
    "hooks/pre-trust-permissions": ("FILE", "key presence in one settings file"),
    "cross/config-instruction-conflict": ("PAIRWISE", "settings deny list against one instruction file"),
    "cross/multi-assistant-drift": ("PAIRWISE", "similarity between two context files"),
    "mcp/cross-assistant-divergence": ("PAIRWISE", "same server in two assistants' MCP configs"),
    "content/mcp-skill-alignment": ("SETUP", "configured servers against every skill that references a tool"),
    "content/circular-references": ("SETUP", "cycle in the reference graph over all skills and commands"),
    "content/orphan-skills": ("SETUP", "reachability from any component"),
    "content/permission-escalation": ("SETUP", "capabilities along delegation edges"),
    "content/total-context-budget": ("SETUP", "aggregate over all always-loaded components"),
    "content/total-description-budget": ("SETUP", "aggregate over all skill descriptions"),
    "security/cross-component-flow": ("SETUP", "reachability over the component graph"),
    "content/duplicate-detection": ("PAIRWISE", "similarity between two skills"),
    "command/duplicate-detection": ("PAIRWISE", "similarity between two commands"),
    "command/references-nonexistent-skill": ("PAIRWISE", "one command against the skill inventory"),
    "agent/referenced-skills-exist": ("PAIRWISE", "one agent against the skill inventory"),
    "content/broken-references": ("FILE_FS", "path resolution against the filesystem"),
    "content/hardcoded-machine-path": ("FILE", "pattern on one file's text"),
    "frontmatter/format-valid": ("FILE", "YAML parse of one file"),
    "frontmatter/description-required": ("FILE", "field presence in one file"),
    "agent/description-required": ("FILE", "field presence in one file"),
    "mcp/unpinned-package": ("FILE", "package spec text in one config"),
    "claude-md/skill-duplication": ("PAIRWISE", "context file against each skill"),
    "hooks/matcher-matches-no-tool": ("FILE", "matcher string against a fixed tool list"),
    "structural/skill-md-exists": ("FILE_FS", "file presence in the skill directory"),
    "command/skill-overlap": ("PAIRWISE", "one command's triggers against each skill"),
    "mcp/duplicate-server": ("FILE", "duplicate names inside one config file"),
    "submission/file-completeness": ("FILE_FS", "expected files in the skill directory"),
}
# Every rule under these prefixes is a pattern match on one component's text
# unless listed above. Their source mentions "other" and "overlap" inside
# regex patterns, which fooled the automated pass.
TEXT_PATTERN_PREFIXES = ("security/", "quality/", "agent/", "command/", "hooks/", "instruction/")


def _auto(src: str) -> str:
    if any(re.search(p, src) for p in SETUP_SIGNALS):
        return "SETUP"
    if any(re.search(p, src) for p in PAIR_SIGNALS):
        return "PAIRWISE"
    if any(re.search(p, src) for p in FS_SIGNALS):
        return "FILE_FS"
    return "FILE"


def main() -> None:
    out = {}
    for rule in get_all_rules():
        cls = type(rule)
        try:
            src = inspect.getsource(sys.modules[cls.__module__])
        except (OSError, TypeError):
            src = ""
        auto = _auto(src)
        if rule.meta.id in OVERRIDES:
            final, reason = OVERRIDES[rule.meta.id]
        elif rule.meta.id.startswith(TEXT_PATTERN_PREFIXES) and auto in ("PAIRWISE", "SETUP"):
            final, reason = "FILE", "pattern match on one component; signal words appear inside regexes"
        else:
            final, reason = auto, ""
        out[rule.meta.id] = {"auto": auto, "scope": final, "corrected": final != auto,
                             "reason": reason, "category": str(rule.meta.category.value),
                             "security": rule.meta.id.startswith("security/") or rule.meta.category.value == "security",
                             "default_severity": str(rule.meta.default_severity.value)}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1, sort_keys=True))
    counts = {}
    for v in out.values():
        counts[v["scope"]] = counts.get(v["scope"], 0) + 1
    corrected = sum(1 for v in out.values() if v["corrected"])
    print(f"{len(out)} rules: {counts}; {corrected} hand-corrected", file=sys.stderr)


if __name__ == "__main__":
    main()
