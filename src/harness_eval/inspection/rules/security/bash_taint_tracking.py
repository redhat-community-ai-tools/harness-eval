from __future__ import annotations

import re
from pathlib import Path

try:
    import bashlex

    _HAS_BASHLEX = True
except ImportError:
    _HAS_BASHLEX = False

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

_SOURCE_PATTERNS = [pat for pat, _ in _caps.bash_taint_sources()]

_SINK_PATTERNS = _caps.bash_taint_sinks()

_SELF_CONTAINED_PATTERNS = _caps.bash_self_contained()

_ASSIGNMENT_RE = re.compile(r"^(\w+)=(.+)$")
_READ_CMD_RE = re.compile(r"\bread\s+(?:-\w+\s+)*(\w+)")

# Patterns for AST-enhanced detection
_BASE64_PIPE_RE = re.compile(r"\bbase64\s+-d\b.*\|\s*(?:bash|sh)\b")
_EVAL_CMDSUB_RE = re.compile(r"\beval\b.*\$\(")
_EXPORT_TAINTED_RE = re.compile(r"\bexport\s+(\w+)=\$(\w+|\{[^}]+\})")


def _has_source(line: str) -> bool:
    """Check if a line contains an untrusted source pattern."""
    return any(p.search(line) for p in _SOURCE_PATTERNS)


def _find_sink(line: str) -> str | None:
    """Return the sink label if a line contains a dangerous sink, else None."""
    for pattern, label in _SINK_PATTERNS:
        if pattern.search(line):
            return label
    return None


# ---------------------------------------------------------------------------
# AST-based analysis (bashlex)
# ---------------------------------------------------------------------------


def _analyze_bash_file_ast(
    source: str,
    rel_path: str,
    context: RuleContext,
    skill_md_path: str,
) -> bool:
    """Analyze a bash script using bashlex AST.

    Returns True if analysis succeeded, False if bashlex failed and we should
    fall back to regex.
    """
    if not _HAS_BASHLEX:
        return False

    try:
        parts = bashlex.parse(source)
    except Exception:
        # bashlex can't parse everything; fall back to regex
        return False

    lines = source.split("\n")
    tainted_vars: dict[str, int] = {}
    reported_lines: set[int] = set()

    def _line_number_for_pos(pos: int) -> int:
        """Convert a character offset to a 1-based line number."""
        return source[:pos].count("\n") + 1

    def _report_taint(line_no: int, sink_label: str) -> None:
        if line_no in reported_lines:
            return
        reported_lines.add(line_no)
        context.report(
            ReportDescriptor(
                message_id="bash_taint_flow",
                data={
                    "file": rel_path,
                    "sink": sink_label,
                    "line": str(line_no),
                },
                location=Location(file=skill_md_path, start_line=line_no),
            )
        )

    def _report_indirect(line_no: int, var_name: str, source_line: int, sink_label: str) -> None:
        if line_no in reported_lines:
            return
        reported_lines.add(line_no)
        context.report(
            ReportDescriptor(
                message_id="bash_taint_indirect",
                data={
                    "file": rel_path,
                    "var": var_name,
                    "source_line": str(source_line),
                    "sink": sink_label,
                    "sink_line": str(line_no),
                },
                location=Location(file=skill_md_path, start_line=line_no),
            )
        )

    def _walk_node(node: object) -> None:  # noqa: C901
        """Recursively walk a bashlex AST node looking for taint flows."""
        if not hasattr(node, "kind"):
            return

        kind = node.kind  # type: ignore[union-attr]
        line_no = _line_number_for_pos(node.pos[0])  # type: ignore[union-attr]

        # Detect pipe commands: check for dangerous pipes
        if kind == "pipeline":
            pipe_parts = node.parts  # type: ignore[union-attr]
            if len(pipe_parts) >= 2:
                # Get the text of the full pipeline
                start, end = node.pos  # type: ignore[union-attr]
                pipe_text = source[start:end]

                # base64 -d | bash pattern
                if _BASE64_PIPE_RE.search(pipe_text):
                    _report_taint(line_no, "base64 decode | bash")

                # Check for X | bash/sh/eval at the right side
                last_part = pipe_parts[-1]
                if hasattr(last_part, "parts") and last_part.parts:
                    last_word = last_part.parts[0]
                    if hasattr(last_word, "word") and last_word.word in ("bash", "sh"):
                        # Get first part text to check if it's a network source
                        first_start, first_end = pipe_parts[0].pos
                        first_text = source[first_start:first_end]
                        if any(kw in first_text for kw in ("curl", "wget", "nc", "ncat")):
                            _report_taint(line_no, "curl | bash")
                elif hasattr(last_part, "word") and last_part.word in ("bash", "sh"):
                    first_start, first_end = pipe_parts[0].pos
                    first_text = source[first_start:first_end]
                    if any(kw in first_text for kw in ("curl", "wget", "nc", "ncat")):
                        _report_taint(line_no, "curl | bash")

        # Detect command nodes
        if kind == "command":
            parts = node.parts  # type: ignore[union-attr]
            if parts:
                first = parts[0]
                cmd_name = getattr(first, "word", "") if hasattr(first, "word") else ""

                # eval with command substitution: eval "$(..."
                if cmd_name == "eval":
                    start, end = node.pos  # type: ignore[union-attr]
                    cmd_text = source[start:end]
                    if _EVAL_CMDSUB_RE.search(cmd_text):
                        _report_taint(line_no, "eval")
                    # Check if any argument references a tainted var
                    for part in parts[1:]:
                        word = getattr(part, "word", "")
                        for var_name, src_line in tainted_vars.items():
                            if f"${var_name}" in word or f"${{{var_name}}}" in word:
                                _report_indirect(line_no, var_name, src_line, "eval")

                # read VAR: user input taints the variable
                if cmd_name == "read":
                    for part in parts[1:]:
                        word = getattr(part, "word", "")
                        if word and not word.startswith("-"):
                            tainted_vars[word] = line_no

                # export VAR=$tainted
                if cmd_name == "export":
                    start, end = node.pos  # type: ignore[union-attr]
                    cmd_text = source[start:end]
                    export_m = _EXPORT_TAINTED_RE.search(cmd_text)
                    if export_m:
                        new_var = export_m.group(1)
                        ref_var = export_m.group(2).strip("{}")
                        if ref_var in tainted_vars:
                            tainted_vars[new_var] = line_no

        # Track assignments: VAR=$(cmd) or VAR=value
        if kind == "compound" or kind == "command":
            start, end = node.pos  # type: ignore[union-attr]
            node_text = source[start:end].strip()
            assign_match = _ASSIGNMENT_RE.match(node_text)
            if assign_match:
                var_name, value = assign_match.group(1), assign_match.group(2)
                if _has_source(value):
                    tainted_vars[var_name] = line_no

        # Detect command substitution as taint source
        if kind == "commandsubstitution":
            # The result of $(...) is tainted
            pass

        # Recurse into child nodes
        if hasattr(node, "parts") and node.parts:
            for part in node.parts:
                _walk_node(part)
        if hasattr(node, "list") and node.list:
            for item in node.list:
                _walk_node(item)

    # Walk all top-level AST nodes
    for part in parts:
        _walk_node(part)

    # Also do a line-by-line pass for patterns the AST walk might miss
    # (heredocs, complex variable tracking, self-contained patterns)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if i in reported_lines:
            continue

        # Track assignments from tainted sources (supplement AST tracking)
        assign_match = _ASSIGNMENT_RE.match(stripped)
        if assign_match:
            var_name, value = assign_match.group(1), assign_match.group(2)
            if _has_source(value):
                tainted_vars[var_name] = i

        # Track read command
        read_match = _READ_CMD_RE.search(stripped)
        if read_match:
            tainted_vars[read_match.group(1)] = i

        # Track export VAR=$tainted_var
        export_match = _EXPORT_TAINTED_RE.search(stripped)
        if export_match:
            new_var = export_match.group(1)
            ref_var = export_match.group(2).strip("{}")
            if ref_var in tainted_vars:
                tainted_vars[new_var] = i

        # Self-contained taint flows
        for pattern, label in _SELF_CONTAINED_PATTERNS:
            if pattern.search(stripped):
                _report_taint(i, label)
                continue

        # Check for eval "$(..." pattern on a per-line basis too
        if _EVAL_CMDSUB_RE.search(stripped):
            _report_taint(i, "eval")
            continue

        # Check for base64 -d | bash on a per-line basis
        if _BASE64_PIPE_RE.search(stripped):
            _report_taint(i, "base64 decode | bash")
            continue

        # Check if this line has a sink
        sink = _find_sink(stripped)
        if sink is None:
            continue

        # Direct: line has both source and sink
        if _has_source(stripped):
            _report_taint(i, sink)
            continue

        # Indirect: line uses a tainted variable in a sink
        for var_name, source_line in tainted_vars.items():
            if f"${var_name}" in stripped or f"${{{var_name}}}" in stripped:
                _report_indirect(i, var_name, source_line, sink)
                break

    return True


# ---------------------------------------------------------------------------
# Regex-based analysis (fallback)
# ---------------------------------------------------------------------------


def _analyze_bash_file_regex(
    source: str,
    rel_path: str,
    context: RuleContext,
    skill_md_path: str,
) -> None:
    """Regex fallback: bashlex fails on many real-world scripts, so this ensures coverage."""
    lines = source.split("\n")

    # Track variables assigned from tainted sources
    tainted_vars: dict[str, int] = {}  # var_name -> line_number

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Track assignments from tainted sources
        assign_match = _ASSIGNMENT_RE.match(stripped)
        if assign_match:
            var_name, value = assign_match.group(1), assign_match.group(2)
            if _has_source(value):
                tainted_vars[var_name] = i

        # Track read command: `read VAR` taints VAR
        read_match = _READ_CMD_RE.search(stripped)
        if read_match:
            tainted_vars[read_match.group(1)] = i

        # Track export VAR=$tainted_var
        export_match = _EXPORT_TAINTED_RE.search(stripped)
        if export_match:
            new_var = export_match.group(1)
            ref_var = export_match.group(2).strip("{}")
            if ref_var in tainted_vars:
                tainted_vars[new_var] = i

        # Self-contained taint flows (e.g., curl | bash)
        for pattern, label in _SELF_CONTAINED_PATTERNS:
            if pattern.search(stripped):
                context.report(
                    ReportDescriptor(
                        message_id="bash_taint_flow",
                        data={
                            "file": rel_path,
                            "sink": label,
                            "line": str(i),
                        },
                        location=Location(file=skill_md_path, start_line=i),
                    )
                )
                continue

        # Check if this line has a sink
        sink = _find_sink(stripped)
        if sink is None:
            continue

        # Direct: line has both source and sink
        if _has_source(stripped):
            context.report(
                ReportDescriptor(
                    message_id="bash_taint_flow",
                    data={
                        "file": rel_path,
                        "sink": sink,
                        "line": str(i),
                    },
                    location=Location(file=skill_md_path, start_line=i),
                )
            )
            continue

        # Indirect: line uses a tainted variable in a sink
        for var_name, source_line in tainted_vars.items():
            if f"${var_name}" in stripped or f"${{{var_name}}}" in stripped:
                context.report(
                    ReportDescriptor(
                        message_id="bash_taint_indirect",
                        data={
                            "file": rel_path,
                            "var": var_name,
                            "source_line": str(source_line),
                            "sink": sink,
                            "sink_line": str(i),
                        },
                        location=Location(file=skill_md_path, start_line=i),
                    )
                )
                break


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def _analyze_bash_file(bash_path: Path, context: RuleContext, skill_md_path: str) -> None:
    try:
        source = bash_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    rel_path = bash_path.name

    # AST first; regex fallback catches scripts bashlex can't parse
    if not _analyze_bash_file_ast(source, rel_path, context, skill_md_path):
        _analyze_bash_file_regex(source, rel_path, context, skill_md_path)


class BashTaintTracking:
    meta: RuleMeta = RuleMeta(
        id="security/bash-taint-flow",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Detect data flows from untrusted sources to dangerous sinks in bash scripts",
        category=RuleCategory.SECURITY,
        messages={
            "bash_taint_flow": "{{file}}: untrusted input flows to {{sink}} (line {{line}}). Possible injection vector.",
            "bash_taint_indirect": "{{file}}: tainted variable '${{var}}' (from line {{source_line}}) flows to {{sink}} (line {{sink_line}}). Possible injection vector.",
        },
        frameworks={"owasp_llm": "LLM06", "owasp_agentic": "AG04"},
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if not skill.dir_path:
            return
        skill_dir = Path(skill.dir_path)
        if not skill_dir.is_dir():
            return

        for bash_file in sorted(skill_dir.rglob("*.sh")):
            if ".git" in bash_file.parts or "__pycache__" in bash_file.parts:
                continue
            _analyze_bash_file(bash_file, context, skill.skill_md_path)

        for bash_file in sorted(skill_dir.rglob("*.bash")):
            if ".git" in bash_file.parts or "__pycache__" in bash_file.parts:
                continue
            _analyze_bash_file(bash_file, context, skill.skill_md_path)
