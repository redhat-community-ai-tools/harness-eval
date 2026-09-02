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


def _load_sets() -> tuple[set[str], set[str], set[str], set[str], set[str], set[str], set[str]]:
    caps = load_capabilities()
    credential = caps.python_sources("credential")
    file_read = caps.python_sources("file_read")
    network_input = caps.python_sources("network_input")
    network_sinks = caps.python_sinks("network_output")
    exec_sinks = caps.python_sinks("code_execution")
    all_sources = credential | file_read | network_input
    all_sinks = network_sinks | exec_sinks
    return credential, file_read, network_input, network_sinks, exec_sinks, all_sources, all_sinks


(
    _CREDENTIAL_SOURCES,
    _FILE_READ_SOURCES,
    _NETWORK_INPUT_SOURCES,
    _NETWORK_SINKS,
    _EXEC_SINKS,
    ALL_SOURCES,
    ALL_SINKS,
) = _load_sets()


def _resolve_dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_dotted_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
    return None


def _get_call_name(node: ast.Call) -> str | None:
    return _resolve_dotted_name(node.func)


def _classify_source(name: str) -> str | None:
    if name in _CREDENTIAL_SOURCES:
        return "credential"
    if name in _FILE_READ_SOURCES:
        return "file_read"
    if name in _NETWORK_INPUT_SOURCES:
        return "network_input"
    return None


def _classify_sink(name: str) -> str | None:
    if name in _NETWORK_SINKS:
        return "network_output"
    if name in _EXEC_SINKS:
        return "code_execution"
    return None


def _analyze_file(py_path: Path, context: RuleContext, skill_md_path: str) -> None:
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_path))
    except SyntaxError:
        return

    rel_path = py_path.name
    tainted: dict[str, tuple[str, int]] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                call_name = _get_call_name(node.value)
                if call_name:
                    source_type = _classify_source(call_name)
                    if source_type:
                        tainted[target.id] = (source_type, getattr(node, "lineno", 0))

            if (
                isinstance(target, ast.Name)
                and isinstance(node.value, ast.Subscript)
                and isinstance(node.value.value, ast.Attribute)
            ):
                attr_name = ""
                if isinstance(node.value.value.value, ast.Name):
                    attr_name = f"{node.value.value.value.id}.{node.value.value.attr}"
                if attr_name in _CREDENTIAL_SOURCES:
                    tainted[target.id] = ("credential", getattr(node, "lineno", 0))

            if isinstance(target, ast.Name) and isinstance(node.value, ast.JoinedStr):
                for val in node.value.values:
                    if (
                        isinstance(val, ast.FormattedValue)
                        and isinstance(val.value, ast.Name)
                        and val.value.id in tainted
                    ):
                        tainted[target.id] = tainted[val.value.id]
                        break

        if isinstance(node, ast.Call):
            call_name = _get_call_name(node)
            if not call_name:
                continue
            sink_type = _classify_sink(call_name)
            if not sink_type:
                continue
            line = getattr(node, "lineno", 0)

            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in tainted:
                    source_type, source_line = tainted[arg.id]
                    _report_flow(
                        context,
                        source_type,
                        sink_type,
                        rel_path,
                        source_line,
                        line,
                        skill_md_path,
                    )
                    break

            for kw in node.keywords:
                if isinstance(kw.value, ast.Name) and kw.value.id in tainted:
                    source_type, source_line = tainted[kw.value.id]
                    _report_flow(
                        context,
                        source_type,
                        sink_type,
                        rel_path,
                        source_line,
                        line,
                        skill_md_path,
                    )
                    break


def _report_flow(
    context: RuleContext,
    source_type: str,
    sink_type: str,
    file: str,
    source_line: int,
    sink_line: int,
    skill_md_path: str,
) -> None:
    if source_type == "credential" and sink_type == "network_output":
        msg_id = "taint_credential_leak"
        suggestion = (
            "Remove the network call or use a secret manager instead of environment variables."
        )
    elif source_type == "file_read" and sink_type == "network_output":
        msg_id = "taint_data_exfil"
        suggestion = None
    elif sink_type == "code_execution":
        msg_id = "taint_input_exec"
        suggestion = None
    else:
        msg_id = "taint_data_exfil"
        suggestion = None

    context.report(
        ReportDescriptor(
            message_id=msg_id,
            data={
                "source": source_type,
                "sink": sink_type,
                "file": file,
                "source_line": str(source_line),
                "sink_line": str(sink_line),
            },
            location=Location(file=skill_md_path, start_line=sink_line),
            suggestion=suggestion,
        )
    )


class TaintTracking:
    meta: RuleMeta = RuleMeta(
        id="security/taint-flow",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect data flows from sensitive sources to dangerous sinks in Python scripts",
        category=RuleCategory.SECURITY,
        messages={
            "taint_credential_leak": "{{file}}: credential read (line {{source_line}}) flows to network output (line {{sink_line}}). Possible secret exfiltration.",
            "taint_data_exfil": "{{file}}: {{source}} data (line {{source_line}}) flows to {{sink}} (line {{sink_line}}). Verify this is intentional.",
            "taint_input_exec": "{{file}}: external input (line {{source_line}}) flows to code execution (line {{sink_line}}). Possible injection vector.",
        },
        frameworks={"owasp_llm": "LLM06", "owasp_agentic": "AG04"},
        default_suggestion="Add input validation before using untrusted data in sensitive operations.",
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
