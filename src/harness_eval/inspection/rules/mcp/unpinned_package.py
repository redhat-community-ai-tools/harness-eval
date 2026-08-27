from __future__ import annotations

import json

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_NPX_COMMANDS = {"npx", "bunx"}
_UVX_COMMANDS = {"uvx"}
_PIPX_COMMAND = "pipx"


def _is_local_spec(spec: str) -> bool:
    return spec.startswith((".", "./", "/", "file:"))


def _is_npx_pinned(spec: str) -> bool:
    if _is_local_spec(spec):
        return True
    # Has @version but not @latest. A scoped package (@scope/name) starts with
    # "@", which is not a version separator, so look for "@" after position 0.
    at_idx = spec.rfind("@")
    if at_idx <= 0:
        return False
    version = spec[at_idx + 1 :]
    return version.lower() != "latest" and len(version) > 0


def _is_uvx_pinned(spec: str) -> bool:
    if _is_local_spec(spec):
        return True
    return "==" in spec or "@" in spec


def _is_docker_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    if ":" in image:
        tag = image.rsplit(":", 1)[1]
        return tag.lower() != "latest"
    return False


class McpUnpinnedPackage:
    meta = RuleMeta(
        id="mcp/unpinned-package",
        tier="gating",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Flag MCP servers that run unpinned third-party packages",
        category=RuleCategory.SECURITY,
        messages={
            "unpinned": (
                "MCP server '{{server}}': runs unpinned package '{{spec}}'"
                " -- version is re-resolved every session. Pin an exact version."
            ),
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Pin the package to an exact version.",
    )

    def create(self, context: RuleContext) -> None:
        raw = context.skill.raw_content
        if not raw or not raw.strip():
            return

        loc = Location(file=context.skill.skill_md_path)

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return

        if not isinstance(data, dict):
            return

        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            return

        for server_name, server_def in servers.items():
            if not isinstance(server_def, dict):
                continue

            command = server_def.get("command", "")
            args = server_def.get("args", [])
            if not isinstance(args, list):
                args = []

            all_parts = [command] + [str(a) for a in args]
            cmd_base = command.rsplit("/", 1)[-1] if command else ""

            # npx / bunx
            if cmd_base in _NPX_COMMANDS:
                self._check_npx(context, loc, server_name, all_parts[1:], cmd_base)
                continue

            # uvx
            if cmd_base in _UVX_COMMANDS:
                self._check_uvx(context, loc, server_name, all_parts[1:])
                continue

            # pipx run
            if cmd_base == _PIPX_COMMAND and "run" in all_parts:
                run_idx = all_parts.index("run")
                self._check_uvx(context, loc, server_name, all_parts[run_idx + 1 :])
                continue

            # docker
            if cmd_base == "docker" and "run" in all_parts:
                run_idx = all_parts.index("run")
                self._check_docker(context, loc, server_name, all_parts[run_idx + 1 :])
                continue

    def _check_npx(
        self, context: RuleContext, loc: Location, server: str, args: list[str], cmd: str
    ) -> None:
        # Check if --package with pinned spec exists
        for i, arg in enumerate(args):
            if arg == "--package" and i + 1 < len(args):
                spec = args[i + 1]
                if _is_npx_pinned(spec):
                    return

        # Find the package spec (first arg that isn't a flag)
        for arg in args:
            if arg.startswith("-"):
                continue
            spec = arg
            if not _is_npx_pinned(spec):
                context.report(
                    ReportDescriptor(
                        message_id="unpinned",
                        data={"server": server, "spec": spec},
                        location=loc,
                    )
                )
            return

    def _check_uvx(self, context: RuleContext, loc: Location, server: str, args: list[str]) -> None:
        for arg in args:
            if arg.startswith("-"):
                continue
            spec = arg
            if not _is_uvx_pinned(spec):
                context.report(
                    ReportDescriptor(
                        message_id="unpinned",
                        data={"server": server, "spec": spec},
                        location=loc,
                    )
                )
            return

    def _check_docker(
        self, context: RuleContext, loc: Location, server: str, args: list[str]
    ) -> None:
        skip_next = False
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg.startswith("--") and "=" in arg:
                continue  # --name=foo style
            if arg.startswith("-") and not arg.startswith("--"):
                # Short flags: some take values (-p, -e, -v, -u, -w, -l)
                skip_next = len(arg) == 2 and arg[1] in "pevuwl"
                continue
            if arg.startswith("--"):
                skip_next = arg in (
                    "--name",
                    "--network",
                    "--env",
                    "--volume",
                    "--publish",
                    "--workdir",
                    "--entrypoint",
                    "--user",
                    "--platform",
                    "--label",
                )
                continue
            image = arg
            if not _is_docker_pinned(image):
                context.report(
                    ReportDescriptor(
                        message_id="unpinned",
                        data={"server": server, "spec": image},
                        location=loc,
                    )
                )
            return
