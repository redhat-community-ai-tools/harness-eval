"""Flag a stdio MCP server whose ``args`` name a repository-relative script
that does not exist (``node ./servers/x.js``, ``python ./tools/mcp.py``).
Same decidability as ``mcp/endpoint-integrity`` for the command path: only
``./`` and ``../`` arguments with a script extension are checked, because a
data path (``./src`` for a filesystem server, ``./memory.db``) may be created
at runtime. Build outputs and anything with a variable are left alone."""

from __future__ import annotations

import re
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules._config_fs import project_root
from harness_eval.inspection.rules.mcp._shared import extract_servers, parse_config
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_GENERATED_DIR_RE = re.compile(
    r"(^|/)(node_modules|dist|build|target|out|bin|venv|\.venv|\.[A-Za-z][\w.-]*)/"
)
# Files an interpreter loads at startup; a missing one fails the server on launch.
_SCRIPT_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".py", ".rb", ".sh", ".php", ".pl")


class McpArgsReferenceMissingFile:
    meta = RuleMeta(
        id="mcp/args-reference-missing-file",
        tier="provisional",
        effect="block",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description=(
            "Flag an MCP server argument that is a repository-relative script path "
            "that does not exist"
        ),
        category=RuleCategory.STRUCTURAL,
        messages={
            "missing_path": (
                "MCP server '{{server}}': argument '{{path}}' does not exist in the repository."
            ),
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Fix the path, or commit the file the server is started with.",
    )

    def create(self, context: RuleContext) -> None:
        raw, path = context.source_text()
        if not raw or not raw.strip():
            return
        data, _ = parse_config(raw)
        if not isinstance(data, dict):
            return
        servers = extract_servers(data)
        if not isinstance(servers, dict):
            return
        root = project_root(Path(path), ceiling=context.artifacts.project_root)
        loc = Location(file=path)
        for name, sd in servers.items():
            if not isinstance(sd, dict) or not sd.get("command"):
                continue
            args = sd.get("args")
            if not isinstance(args, list):
                continue
            for arg in args:
                if not isinstance(arg, str) or not arg.startswith(("./", "../")):
                    continue
                if not arg.lower().endswith(_SCRIPT_SUFFIXES):
                    continue
                if "$" in arg or "*" in arg or _GENERATED_DIR_RE.search(arg):
                    continue
                if (root / arg).exists() or (Path(path).parent / arg).exists():
                    continue
                context.report(
                    ReportDescriptor(
                        message_id="missing_path",
                        data={"server": name, "path": arg},
                        location=loc,
                    )
                )
