"""Mapper for fullsend ``harness/*.yaml`` files.

Field semantics follow the fullsend runtime (``internal/harness/harness.go``):

- Relative paths resolve against the scaffold root, the parent of the
  ``harness/`` directory, not the YAML file itself.
- ``${FULLSEND_DIR}`` is the scaffold root; the runtime injects it.
- Any other ``${VAR}`` is expanded from the host environment at run time and
  is therefore not resolvable from the tree. Such references are kept out of
  ``refs`` on purpose.
- ``host_files[].optional`` means the runtime tolerates a missing source.
- ``forge.<platform>`` overrides scripts and env per platform; the overriding
  paths are references in their own right.
- ``validation_loop`` is the output contract: a validator script and,
  optionally, a schema. ``FULLSEND_OUTPUT_SCHEMA`` / ``FULLSEND_OUTPUT_FILE``
  in the runner environment are the legacy spelling of the same contract.
- Configuration is layered (upstream defaults, then an org config repo,
  then per-repo ``.fullsend/customized/`` overlays) and composed into one
  directory at dispatch time. A harness in an upper layer may reference a
  file that only a lower layer provides, so a reference that is missing from
  *this* tree is a defect only when the tree is a complete scaffold. The
  mapper records that as ``layer_complete``: the tree carries its own
  ``agents/`` and ``scripts/`` directories, is not an org config repo (no
  ``config.yaml`` at the root), and the file is not under ``customized/``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from harness_eval.inspection.harness_formats import (
    HarnessFields,
    HarnessHostFile,
    HarnessRef,
    register_mapper,
)

ROOT_VAR = "FULLSEND_DIR"
_VAR_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-=][^}]*)?\}")
_ROOT_PREFIX_RE = re.compile(r"^\$\{" + ROOT_VAR + r"\}/?")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)

SCHEMA_ENV = "FULLSEND_OUTPUT_SCHEMA"
OUTPUT_FILE_ENV = "FULLSEND_OUTPUT_FILE"
OUTPUT_DIR_ENV = "FULLSEND_OUTPUT_DIR"
# The validator's default when FULLSEND_OUTPUT_FILE is unset
# (scripts/validate-output-schema.sh), and the in-sandbox self-check tool
# the scaffold prompts call.
DEFAULT_OUTPUT_FILE = "agent-result.json"
OUTPUT_CHECK_TOOL = "fullsend-check-output"
# Scaffold-level instruction files the runtime exposes to every agent.
SHARED_INSTRUCTION_FILES = ("AGENTS.md", "CLAUDE.md")


def normalize_path(value: str) -> str | None:
    """Return a tree-relative path for *value*, or None when it is not decidable.

    ``${FULLSEND_DIR}/schemas/x.json`` becomes ``schemas/x.json``. A value
    with any other variable, a URL, or an absolute path cannot be checked in
    a clone and yields None.
    """
    value = _ROOT_PREFIX_RE.sub("", value.strip())
    if not value or _VAR_RE.search(value) or _SCHEME_RE.match(value):
        return None
    if value.startswith("/") or value.startswith("~"):
        return None
    return value


def _str(data: dict[str, Any], key: str) -> str | None:
    v = data.get(key)
    return v if isinstance(v, str) and v.strip() else None


def _str_list(data: dict[str, Any], key: str) -> list[str]:
    v = data.get(key)
    if not isinstance(v, list):
        return []
    return [x for x in v if isinstance(x, str) and x.strip()]


def _skill_list(data: dict[str, Any], key: str) -> list[str]:
    """Skill entries: a plain path, or a mapping with ``source`` (fullsend
    SkillEntry with per-file overrides)."""
    v = data.get(key)
    if not isinstance(v, list):
        return []
    out: list[str] = []
    for x in v:
        if isinstance(x, str) and x.strip():
            out.append(x)
        elif isinstance(x, dict):
            src = x.get("source") or x.get("path")
            if isinstance(src, str) and src.strip():
                out.append(src)
    return out


def _is_provider_path(value: str) -> bool:
    """fullsend accepts a provider as a built-in name (``github-ro``) or as a
    path to a provider definition; only the path form is checkable."""
    return "/" in value or value.endswith((".yaml", ".yml"))


def _resource_refs(fields: HarnessFields, data: dict[str, Any], prefix: str) -> None:
    """Path-typed resources that appear both at the top level and under a
    ``forge.<platform>`` override: skills, plugins, host files, providers,
    policy, openshell profiles, validation loop script and schema."""
    for i, s in enumerate(_skill_list(data, "skills")):
        _add_ref(fields, f"{prefix}skills[{i}]", s, directory=True)
    for i, p in enumerate(_str_list(data, "plugins")):
        _add_ref(fields, f"{prefix}plugins[{i}]", p, directory=True)
    for i, p in enumerate(_str_list(data, "providers")):
        if _is_provider_path(p):
            _add_ref(fields, f"{prefix}providers[{i}]", p)
    if prefix:
        _add_ref(fields, f"{prefix}policy", _str(data, "policy"))
    openshell = data.get("openshell")
    if isinstance(openshell, dict):
        for i, p in enumerate(_str_list(openshell, "profiles")):
            _add_ref(fields, f"{prefix}openshell.profiles[{i}]", p)
    for i, hf in enumerate(data.get("host_files") or []):
        if not isinstance(hf, dict):
            continue
        src, dest = _str(hf, "src"), _str(hf, "dest")
        if src is None or dest is None:
            continue
        optional = bool(hf.get("optional"))
        # Platform host files are alternatives (github or gitlab, never both in
        # one run), so they take part in the existence check but not in the
        # destination-collision check, which reasons about one run.
        if not prefix:
            fields.host_files.append(
                HarnessHostFile(
                    src=src, dest=dest, optional=optional, expand=bool(hf.get("expand"))
                )
            )
        _add_ref(fields, f"{prefix}host_files[{i}].src", src, optional=optional)
    if prefix:
        loop = data.get("validation_loop")
        if isinstance(loop, dict):
            _add_ref(fields, f"{prefix}validation_loop.script", _str(loop, "script"))
            _add_ref(fields, f"{prefix}validation_loop.schema", _str(loop, "schema"))


def _env_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items() if v is not None}


def _add_ref(fields: HarnessFields, name: str, value: str | None, **kw: bool) -> None:
    if value is None:
        return
    norm = normalize_path(value)
    if norm is None:
        return
    fields.refs.append(HarnessRef(field=name, value=norm, **kw))


def _script_fields(fields: HarnessFields, data: dict[str, Any], prefix: str) -> None:
    for key, slot in (("pre_script", "pre"), ("post_script", "post")):
        v = _str(data, key)
        if v is not None:
            fields.scripts[f"{prefix}{slot}"] = v
            _add_ref(fields, f"{prefix}{key}", v)


ORG_CONFIG_FILE = "config.yaml"
OVERLAY_DIR = "customized"
_COMPLETE_LAYER_DIRS = ("agents", "scripts")


def scaffold_root(path: Path) -> tuple[Path, bool]:
    """Return (root the harness resolves paths against, whether it is an overlay)."""
    root = path.resolve().parent
    if root.name == "harness":
        root = root.parent
    overlay = False
    if root.name == OVERLAY_DIR:
        # ``.fullsend/customized/harness/x.yaml`` resolves against ``.fullsend/``.
        root = root.parent
        overlay = True
    return root, overlay


def is_layer_complete(root: Path, *, overlay: bool) -> bool:
    if overlay or (root / ORG_CONFIG_FILE).is_file():
        return False
    return all((root / d).is_dir() for d in _COMPLETE_LAYER_DIRS)


def map_fullsend(data: dict[str, Any], path: Path) -> HarnessFields:
    root, overlay = scaffold_root(path)
    fields = HarnessFields(root_dir=root, layer_complete=is_layer_complete(root, overlay=overlay))

    fields.base = _str(data, "base")
    fields.instructions = _str(data, "agent")
    fields.model = _str(data, "model")
    fields.image = _str(data, "image")
    fields.policy = _str(data, "policy")
    fields.agent_input = _str(data, "agent_input")
    fields.runtime_fetch = bool(data.get("allow_runtime_fetch"))

    # A local base is a file reference too; a URL base is skipped by normalize_path.
    _add_ref(fields, "base", fields.base)
    _add_ref(fields, "agent", fields.instructions)
    _add_ref(fields, "policy", fields.policy)
    _add_ref(fields, "agent_input", fields.agent_input, directory=True)
    _add_ref(fields, "doc", _str(data, "doc"))

    _script_fields(fields, data, "")

    fields.skills = _skill_list(data, "skills")
    fields.plugins = _str_list(data, "plugins")
    _resource_refs(fields, data, "")

    for i, srv in enumerate(data.get("api_servers") or []):
        if isinstance(srv, dict):
            _add_ref(fields, f"api_servers[{i}].script", _str(srv, "script"))

    loop = data.get("validation_loop")
    if isinstance(loop, dict):
        script = _str(loop, "script")
        if script is not None:
            fields.scripts["validator"] = script
            _add_ref(fields, "validation_loop.script", script)
        fields.output_schema = _str(loop, "schema")
        _add_ref(fields, "validation_loop.schema", fields.output_schema)

    env = data.get("env")
    if isinstance(env, dict):
        for target in ("runner", "sandbox"):
            m = _env_map(env.get(target))
            if m:
                fields.env[target] = m
    runner_env = _env_map(data.get("runner_env"))
    if runner_env:
        fields.env["runner"] = {**runner_env, **fields.env.get("runner", {})}

    runner = fields.env.get("runner", {})
    if fields.output_schema is None and SCHEMA_ENV in runner:
        fields.output_schema = runner[SCHEMA_ENV]
        _add_ref(fields, f"env.runner.{SCHEMA_ENV}", fields.output_schema)
    fields.output_file = runner.get(OUTPUT_FILE_ENV)

    forge = data.get("forge")
    if isinstance(forge, dict):
        for platform, override in forge.items():
            if not isinstance(override, dict):
                continue
            fields.platform_overrides[str(platform)] = override
            _script_fields(fields, override, f"forge.{platform}.")
            _resource_refs(fields, override, f"forge.{platform}.")
            # Platform skills are instructions the agent runs with on that
            # platform; the instruction closure and the managed set include them.
            for s in _skill_list(override, "skills"):
                if s not in fields.skills:
                    fields.skills.append(s)

    if fields.output_schema is not None or fields.output_file is not None:
        tokens = [OUTPUT_DIR_ENV, OUTPUT_FILE_ENV, SCHEMA_ENV, OUTPUT_CHECK_TOOL]
        tokens.append(Path(fields.output_file).name if fields.output_file else DEFAULT_OUTPUT_FILE)
        if fields.output_schema is not None:
            tokens.append(Path(fields.output_schema).name)
        fields.output_contract_tokens = tokens
    fields.shared_instruction_files = list(SHARED_INSTRUCTION_FILES)

    return fields


register_mapper("fullsend", map_fullsend)
