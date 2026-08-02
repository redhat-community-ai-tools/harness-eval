from __future__ import annotations

import contextlib
import re
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_STANDARD_VARS = {
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "PWD",
    "TMPDIR",
    "LANG",
    "TERM",
    "CI",
    "EDITOR",
    "DISPLAY",
    "HOSTNAME",
    "LOGNAME",
    "OLDPWD",
    "SHLVL",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
}

_GITHUB_PREFIX = "GITHUB_"

_PROVIDER_KEYS = {"ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"}

# Shell: $VAR and ${VAR} (but not ${VAR:-default})
_SHELL_VAR_RE = re.compile(r"\$\{?([A-Z_][A-Z0-9_]*)\}?")
_SHELL_DEFAULT_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*):-")

# Python: os.environ["VAR"], os.environ.get("VAR"), os.getenv("VAR")
_PY_ENVIRON_RE = re.compile(r'os\.environ(?:\.get)?\s*[\[\(]\s*["\']([A-Z_][A-Z0-9_]*)["\']')
_PY_GETENV_RE = re.compile(r'os\.getenv\s*\(\s*["\']([A-Z_][A-Z0-9_]*)["\']')
# Python with default: os.getenv("VAR", default)
_PY_GETENV_DEFAULT_RE = re.compile(r'os\.getenv\s*\(\s*["\']([A-Z_][A-Z0-9_]*)["\'],')

# JS: process.env.VAR
_JS_ENV_RE = re.compile(r"process\.env\.([A-Z_][A-Z0-9_]*)")


def _extract_env_vars(content: str) -> set[str]:
    """Extract environment variable names referenced in content."""
    vars_found: set[str] = set()
    vars_with_defaults: set[str] = set()

    # Shell vars
    for m in _SHELL_VAR_RE.finditer(content):
        vars_found.add(m.group(1))
    for m in _SHELL_DEFAULT_RE.finditer(content):
        vars_with_defaults.add(m.group(1))

    # Python
    for m in _PY_ENVIRON_RE.finditer(content):
        vars_found.add(m.group(1))
    for m in _PY_GETENV_RE.finditer(content):
        vars_found.add(m.group(1))
    for m in _PY_GETENV_DEFAULT_RE.finditer(content):
        vars_with_defaults.add(m.group(1))

    # JS
    for m in _JS_ENV_RE.finditer(content):
        vars_found.add(m.group(1))

    return vars_found - vars_with_defaults


def _is_standard_var(var: str) -> bool:
    return var in _STANDARD_VARS or var.startswith(_GITHUB_PREFIX) or var in _PROVIDER_KEYS


_SCRIPT_EXTENSIONS = {".sh", ".bash", ".py", ".js", ".ts", ".mjs", ".cjs"}
_MAX_SCRIPT_SIZE = 256 * 1024  # 256 KB


def _read_script_files(skill_dir: str) -> str:
    """Read script files from a skill directory."""
    parts: list[str] = []
    dir_path = Path(skill_dir)
    if not dir_path.is_dir():
        return ""
    for p in sorted(dir_path.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _SCRIPT_EXTENSIONS:
            continue
        if ".git" in p.parts or "__pycache__" in p.parts:
            continue
        try:
            if p.stat().st_size > _MAX_SCRIPT_SIZE:
                continue
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n".join(parts)


def _is_documented(var: str, documentation: str) -> bool:
    """Check if a variable is mentioned in documentation."""
    return var in documentation


class UndeclaredEnvVar:
    meta = RuleMeta(
        id="content/undeclared-env-var",
        default_severity=Severity.WARNING,
        fixable=False,
        description="Flag environment variables used but not documented",
        category=RuleCategory.CONTENT,
        messages={
            "undeclared": (
                "'{{component}}' reads ${{var}} but it is not documented anywhere"
                " and has no default -- the setup breaks silently where it is unset."
            ),
        },
        target_type=ComponentType.SKILL,
    )

    def create(self, context: RuleContext) -> None:
        if context.scan_state.get("undeclared_env_var_checked"):
            return
        context.scan_state["undeclared_env_var_checked"] = True

        # Use all_skills if available, otherwise fall back to the current skill
        skills_to_check = context.all_skills if context.all_skills else [context.skill]

        # Gather documentation text (CLAUDE.md, README, skill docs)
        doc_text = self._gather_documentation(skills_to_check)

        # Check skills
        for skill in skills_to_check:
            content = skill.body or ""
            for file_content in skill.sub_file_contents.values():
                content += "\n" + file_content
            # Also read script files (.sh, .py, .js, etc.) from the skill directory
            content += "\n" + _read_script_files(skill.dir_path)
            # Check the skill's frontmatter description as additional documentation
            skill_desc = skill.frontmatter.get("description", "") or ""

            env_vars = _extract_env_vars(content)
            for var in sorted(env_vars):
                if _is_standard_var(var):
                    continue
                if _is_documented(var, doc_text) or _is_documented(var, skill_desc):
                    continue
                context.report(
                    ReportDescriptor(
                        message_id="undeclared",
                        data={"component": skill.dir_name, "var": var},
                        location=Location(file=skill.skill_md_path),
                    )
                )

        # Check commands
        for cmd in context.all_commands:
            content = cmd.body or ""
            cmd_desc = cmd.frontmatter.get("description", "") or ""

            env_vars = _extract_env_vars(content)
            for var in sorted(env_vars):
                if _is_standard_var(var):
                    continue
                if _is_documented(var, doc_text) or _is_documented(var, cmd_desc):
                    continue
                context.report(
                    ReportDescriptor(
                        message_id="undeclared",
                        data={"component": cmd.dir_name, "var": var},
                        location=Location(file=cmd.command_md_path),
                    )
                )

    def _gather_documentation(self, skills: list) -> str:
        """Gather text from CLAUDE.md, README, etc."""
        docs: list[str] = []

        if not skills:
            return ""

        # Find project root
        root = Path(skills[0].dir_path).resolve()
        while root != root.parent:
            if (root / ".git").is_dir():
                break
            root = root.parent

        for name in ("CLAUDE.md", "README.md", "AGENTS.md", "GEMINI.md"):
            doc_path = root / name
            if doc_path.is_file():
                with contextlib.suppress(OSError):
                    docs.append(doc_path.read_text(encoding="utf-8", errors="replace"))

        return "\n".join(docs)
