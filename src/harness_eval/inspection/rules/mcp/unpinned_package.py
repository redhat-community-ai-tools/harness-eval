from __future__ import annotations

import json
import re
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.rules.mcp._shared import extract_servers, parse_config
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_NPX_COMMANDS = {"npx", "bunx"}
_LOCAL_RUNNERS = {"tsx", "ts-node", "node", "bun"}
# uvx / pipx flags that consume the next token; the package spec is the first
# token that is neither a flag nor a flag value.
_UVX_VALUE_FLAGS = {
    "--python",
    "-p",
    "--from",
    "--with",
    "--index",
    "--index-url",
    "--extra-index-url",
    "--constraint",
    "-c",
    "--python-preference",
    "--cache-dir",
    "--config-file",
    "--spec",
    "--pip-args",
    "--index-strategy",
    "--refresh-package",
    "--reinstall-package",
}
_UVX_COMMANDS = {"uvx"}
_PIPX_COMMAND = "pipx"
_NPX_VALUE_FLAGS = {"--registry", "--cache", "--userconfig", "--prefix", "--loglevel"}

_NPM_VERSION_RE = re.compile(
    r"[v=]?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_PYTHON_VERSION_RE = re.compile(
    r"v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"
    r"(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?"
    r"(?:(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*)|(?:-[0-9]+))?"
    r"(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?",
    re.I,
)


def _is_local_spec(spec: str) -> bool:
    return spec.startswith((".", "./", "/", "file:"))


def _is_npx_pinned(spec: str) -> bool:
    if _is_local_spec(spec):
        return True
    # Require an exact version, not a dist-tag or range. A scoped package starts with
    # "@", which is not a version separator, so look for "@" after position 0.
    at_idx = spec.rfind("@")
    if at_idx <= 0:
        return False
    version = spec[at_idx + 1 :]
    return _NPM_VERSION_RE.fullmatch(version) is not None


def _declared_dependencies(context: RuleContext) -> set[str]:
    """Package names in the nearest package.json (dependencies and
    devDependencies) at or above the configuration file, within the root."""
    _, path = context.source_text()
    root = context.scan_state.get("project_root")
    start = Path(path).resolve().parent if path else None
    if start is None:
        return set()
    stop = Path(root).resolve() if root else start
    names: set[str] = set()
    for d in [start, *start.parents]:
        pj = d / "package.json"
        if pj.is_file():
            try:
                data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                data = {}
            if isinstance(data, dict):
                for key in ("dependencies", "devDependencies"):
                    deps = data.get(key)
                    if isinstance(deps, dict):
                        names |= set(deps)
            break
        if d == stop:
            break
    return names


def _is_uvx_pinned(spec: str) -> bool:
    if _is_local_spec(spec):
        return True
    if spec.startswith("git+"):
        return re.search(r"@(?:[0-9a-f]{40}|[0-9a-f]{64})(?:#.*)?$", spec, re.I) is not None
    if "==" in spec:
        version = spec.split("==", 1)[1].strip()
    elif "@" in spec:
        version = spec.rsplit("@", 1)[1].strip()
    else:
        return False
    return _PYTHON_VERSION_RE.fullmatch(version) is not None


# ``docker run`` flags that consume the next token; the image is the first
# token that is neither a flag nor a flag value.
_DOCKER_VALUE_FLAGS = frozenset(
    {
        "--name",
        "--network",
        "--net",
        "--env",
        "--volume",
        "--publish",
        "--workdir",
        "--entrypoint",
        "--user",
        "--platform",
        "--label",
        "--pull",
        "--restart",
        "--memory",
        "--cpus",
        "--add-host",
        "--cap-add",
        "--cap-drop",
        "--security-opt",
        "--mount",
        "--device",
        "--env-file",
        "--hostname",
        "--ipc",
        "--pid",
        "--log-driver",
        "--log-opt",
        "--health-cmd",
        "--shm-size",
        "--stop-signal",
        "--tmpfs",
        "--ulimit",
        "--gpus",
        "--runtime",
        "--sysctl",
        "--dns",
        "--expose",
        "--link",
        "--cgroup-parent",
        "--storage-opt",
        "--isolation",
        "--domainname",
        "--mac-address",
        "--group-add",
        "--volumes-from",
        "--network-alias",
        "--ip",
        "--annotation",
        "--cidfile",
        "--stop-timeout",
        "--userns",
        "--uts",
        "--cpuset-cpus",
        "--memory-swap",
        "--pids-limit",
        "--attach",
        "--detach-keys",
    }
)


def _is_docker_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    # A registry port is not an image tag. This rule accepts an explicit
    # non-latest tag; that is not a claim that tags are immutable digests.
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[1]
        return bool(tag) and tag.lower() != "latest"
    return False


class McpUnpinnedPackage:
    meta = RuleMeta(
        id="mcp/unpinned-package",
        tier="gating",
        effect="policy",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Flag MCP servers that run unpinned third-party packages",
        category=RuleCategory.SECURITY,
        messages={
            "unpinned": (
                "MCP server '{{server}}': runs unpinned package '{{spec}}'"
                " -- declare an exact package version or a non-latest image tag;"
                " prefer an image digest for immutability."
            ),
        },
        target_type=ComponentType.MCP_CONFIG,
        default_suggestion="Pin an exact package version; for containers, prefer a content digest.",
    )

    def create(self, context: RuleContext) -> None:
        raw, path = context.source_text()
        if not raw or not raw.strip():
            return

        loc = Location(file=path)

        data, _ = parse_config(raw)

        if not isinstance(data, dict):
            return

        servers = extract_servers(data)
        if not isinstance(servers, dict):
            return

        for server_name, server_def in servers.items():
            if not isinstance(server_def, dict):
                continue
            if server_def.get("disabled") is True:
                continue  # never started, so nothing is resolved

            command_value = server_def.get("command", "")
            args = server_def.get("args", [])
            if not isinstance(args, list):
                args = []

            # OpenCode V2 stores a local command as one argv array.
            if isinstance(command_value, list):
                command = str(command_value[0]) if command_value else ""
                args = [*command_value[1:], *args]
            else:
                command = command_value if isinstance(command_value, str) else ""

            all_parts = [command] + [str(a) for a in args]
            cmd_base = command.replace("\\", "/").rsplit("/", 1)[-1]
            if cmd_base.endswith((".cmd", ".exe")):
                cmd_base = cmd_base.rsplit(".", 1)[0]

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
        local_deps = _declared_dependencies(context)
        # Every explicit package matters; one pinned package cannot hide a
        # second floating package. Stop at the positional command, whose
        # arguments are not npx options.
        packages: list[str] = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in {"--no-install", "--offline"}:
                return
            if arg == "--":
                i += 1
                break
            if arg in _NPX_VALUE_FLAGS:
                i += 2
                continue
            if arg in {"--package", "-p"} and i + 1 < len(args):
                packages.append(args[i + 1])
                i += 2
                continue
            if arg.startswith("--package="):
                packages.append(arg.split("=", 1)[1])
            elif arg.startswith("-p") and not arg.startswith("--") and len(arg) > 2:
                packages.append(arg[2:])
            elif arg in {"--call", "-c"} or not arg.startswith("-"):
                break
            i += 1
        if packages:
            for spec in packages:
                if not _is_npx_pinned(spec):
                    context.report(
                        ReportDescriptor(
                            message_id="unpinned",
                            data={"server": server, "spec": spec},
                            location=loc,
                        )
                    )
            return
        # Find the package spec (first arg that isn't a flag)
        for arg in args[i:]:
            if arg.startswith("-"):
                continue
            spec = arg
            # A runner (tsx, ts-node, node, bun) given a file in the repository
            # executes local code; the runner is a dev tool, not the server.
            if spec in _LOCAL_RUNNERS and any(
                (a.endswith((".ts", ".js", ".mjs", ".cjs", ".py")) or "/" in a)
                and not a.startswith("-")
                for a in args[args.index(arg) + 1 :]
            ):
                return
            # Treat a bare project dependency as locally managed. An explicit
            # selector can request a different version and must still be checked.
            # This is not verification of installation or lockfile contents.
            bare = (
                "@" + spec[1:].split("@", 1)[0] if spec.startswith("@") else spec.split("@", 1)[0]
            )
            if bare == spec and bare in local_deps:
                return
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
        # --from / pipx --spec identify the package, not the command name.
        # Both split and equals forms must inspect the selector itself.
        i = 0
        while i < len(args):
            arg = args[i]
            spec = None
            if arg in {"--from", "--spec"} and i + 1 < len(args):
                spec = args[i + 1]
            elif arg.startswith(("--from=", "--spec=")):
                spec = arg.split("=", 1)[1]
            elif arg == "--" and i + 1 < len(args):
                spec = args[i + 1]
            elif not arg.startswith("-"):
                spec = arg
            if spec is not None:
                if not _is_uvx_pinned(spec):
                    context.report(
                        ReportDescriptor(
                            message_id="unpinned",
                            data={"server": server, "spec": spec},
                            location=loc,
                        )
                    )
                return
            i += 2 if arg in _UVX_VALUE_FLAGS else 1

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
                skip_next = len(arg) == 2 and arg[1] in "pevuwlhmca"
                continue
            if arg.startswith("--"):
                skip_next = arg in _DOCKER_VALUE_FLAGS
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
