from __future__ import annotations

import ast
from pathlib import Path

from harness_eval.data import load_capabilities
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_caps = load_capabilities()
_DANGEROUS_BUILTINS = _caps.python_sinks("dangerous_builtins")
_SUBPROCESS_CALLS = _caps.python_sinks("subprocess")
_OS_EXEC_CALLS = _caps.python_sinks("os_exec")


def _get_call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        return f"{node.func.value.id}.{node.func.attr}"
    return None


def _is_dynamic_source(node: ast.expr) -> bool:
    if isinstance(node, ast.Call):
        name = _get_call_name(node)
        if name and any(
            name.lower().endswith(kw) or kw == name.lower()
            for kw in ["decode", "b64decode", "urlopen", "read", "recv", "get"]
        ):
            return True
    return isinstance(node, ast.Subscript)


def _all_args_constant(node: ast.Call) -> bool:
    for arg in node.args:
        if isinstance(arg, ast.Constant):
            continue
        if isinstance(arg, ast.List) and all(isinstance(e, ast.Constant) for e in arg.elts):
            continue
        return False
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return False
        if not isinstance(kw.value, ast.Constant) and kw.arg not in (
            "stdout",
            "stderr",
            "stdin",
            "encoding",
            "cwd",
            "env",
            "check",
        ):
            return False
    return True


def _analyze_file(py_path: Path, context: RuleContext, skill_md_path: str) -> None:
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_path))
    except SyntaxError:
        return

    rel_path = py_path.name

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _get_call_name(node)
        if call_name is None:
            continue

        line = getattr(node, "lineno", 0)

        if call_name in _DANGEROUS_BUILTINS:
            has_dynamic = any(_is_dynamic_source(arg) for arg in node.args)
            if has_dynamic:
                context.report(
                    ReportDescriptor(
                        message_id="ast_exec_chain",
                        data={
                            "call": call_name,
                            "file": rel_path,
                            "line": str(line),
                        },
                        location=Location(file=skill_md_path, start_line=line),
                    )
                )
            else:
                context.report(
                    ReportDescriptor(
                        message_id="ast_dangerous_call",
                        data={
                            "call": call_name,
                            "file": rel_path,
                            "line": str(line),
                        },
                        location=Location(file=skill_md_path, start_line=line),
                    )
                )
        elif call_name in _SUBPROCESS_CALLS or call_name in _OS_EXEC_CALLS:
            if _all_args_constant(node):
                context.report(
                    ReportDescriptor(
                        message_id="ast_subprocess_hardcoded",
                        data={
                            "call": call_name,
                            "file": rel_path,
                            "line": str(line),
                        },
                        location=Location(file=skill_md_path, start_line=line),
                        severity_override=Severity.WARNING,
                    )
                )
            else:
                context.report(
                    ReportDescriptor(
                        message_id="ast_subprocess_dynamic",
                        data={
                            "call": call_name,
                            "file": rel_path,
                            "line": str(line),
                        },
                        location=Location(file=skill_md_path, start_line=line),
                        severity_override=Severity.WARNING,
                    )
                )
        elif call_name == "getattr" and len(node.args) >= 2:
            if not isinstance(node.args[1], ast.Constant):
                context.report(
                    ReportDescriptor(
                        message_id="ast_dynamic_import",
                        data={
                            "call": "getattr (non-literal)",
                            "file": rel_path,
                            "line": str(line),
                        },
                        location=Location(file=skill_md_path, start_line=line),
                        severity_override=Severity.WARNING,
                    )
                )


class AstBehavioral:
    meta: RuleMeta = RuleMeta(
        id="security/ast-behavioral",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect dangerous function calls in Python scripts via AST analysis",
        category=RuleCategory.SECURITY,
        messages={
            "ast_dangerous_call": "{{file}}:{{line}} calls {{call}}, which can execute arbitrary code.",
            "ast_subprocess_hardcoded": "{{file}}:{{line}} calls {{call}} with hardcoded arguments. Review if this is intentional.",
            "ast_subprocess_dynamic": "{{file}}:{{line}} calls {{call}} with dynamic arguments. Verify inputs are not user-controlled.",
            "ast_dynamic_import": "{{file}}:{{line}} uses {{call}}, which can load arbitrary modules.",
            "ast_exec_chain": "{{file}}:{{line}} calls {{call}} with a dynamic source (decoded/fetched data), a high-risk execution chain.",
        },
        frameworks={"owasp_agentic": "AG04", "mitre_atlas": "AML.T0054"},
        default_suggestion="Remove or sandbox the flagged code pattern.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        if not skill.dir_path:
            return
        skill_dir = Path(skill.dir_path)
        if not skill_dir.is_dir():
            return

        for py_file in sorted(skill_dir.rglob("*.py")):
            if ".git" in py_file.parts or "__pycache__" in py_file.parts:
                continue
            _analyze_file(py_file, context, skill.skill_md_path)
