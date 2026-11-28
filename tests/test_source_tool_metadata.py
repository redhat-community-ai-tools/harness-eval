"""Every rule that guards on source_tool in its body must declare tools in its
metadata so the engine can skip the rule without calling it, and so the tool
matrix in docs/rules-reference.md accurately reflects tool applicability.

A rule may keep its runtime guard alongside the metadata declaration (belt and
suspenders).  But a guard without a declaration is a gap: the matrix says the
rule applies to all tools, yet the rule body silently returns for non-Claude
invocations.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import harness_eval.inspection  # noqa: F401 — triggers register_all_rules
from harness_eval.inspection.registry import get_all_rules

RULES_DIR = Path(__file__).resolve().parent.parent / "src" / "harness_eval" / "inspection" / "rules"

# Pattern that matches runtime source_tool guards like:
#   if context.source_tool is not None and context.source_tool != "claude":
#       return
_SOURCE_TOOL_GUARD = re.compile(r"""source_tool\s.*!=\s*["']claude["']""")


def _classes_with_source_tool_guard(path: Path) -> dict[str, str | None]:
    """Return a mapping of class_name -> rule_id for classes whose ``create``
    method contains a ``source_tool != "claude"`` guard.

    Uses the AST so we correctly associate each guard with its owning class,
    even when multiple rule classes share a file.
    """
    source = path.read_text()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    source_lines = source.splitlines()
    results: dict[str, str | None] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        # Extract the rule id from the class-level ``meta = RuleMeta(id=...)``
        rule_id: str | None = None
        for item in node.body:
            if isinstance(item, (ast.Assign, ast.AnnAssign)):
                # Find RuleMeta(...) call
                value = item.value if isinstance(item, ast.AnnAssign) else item.value
                if isinstance(value, ast.Call):
                    func = value.func
                    name = None
                    if isinstance(func, ast.Name):
                        name = func.id
                    elif isinstance(func, ast.Attribute):
                        name = func.attr
                    if name == "RuleMeta":
                        for kw in value.keywords:
                            if kw.arg == "id" and isinstance(kw.value, ast.Constant):
                                rule_id = kw.value.value

        # Check if the create() method contains the source_tool guard
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == "create":
                # Get source lines for this method
                start = item.lineno - 1
                end = item.end_lineno if item.end_lineno else start + 1
                method_source = "\n".join(source_lines[start:end])
                if _SOURCE_TOOL_GUARD.search(method_source):
                    results[node.name] = rule_id

    return results


def test_source_tool_guard_has_tools_metadata() -> None:
    """A rule that guards on source_tool must declare tools in RuleMeta."""
    # Build a map of rule_id -> RuleMeta from the registry.
    rules_by_id = {r.meta.id: r.meta for r in get_all_rules()}

    # Scan rule source files for source_tool guards per class.
    missing: list[str] = []
    for py_file in sorted(RULES_DIR.rglob("*.py")):
        if py_file.name.startswith("_"):
            continue
        classes = _classes_with_source_tool_guard(py_file)
        for _cls_name, rule_id in classes.items():
            if rule_id is None:
                continue
            meta = rules_by_id.get(rule_id)
            if meta is None:
                continue
            if meta.tools is None:
                missing.append(rule_id)

    assert missing == [], (
        f"{len(missing)} rule(s) guard on source_tool in their body but do not "
        f"declare tools in RuleMeta: {', '.join(sorted(missing))}. "
        f'Add tools=("claude",) to each rule\'s RuleMeta.'
    )
