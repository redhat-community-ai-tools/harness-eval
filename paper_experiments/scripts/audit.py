#!/usr/bin/env python3
"""Re-derive findings mechanically from re-cloned repositories at pinned commits.

For every candidate rule, a seeded sample of flagged repositories is
re-cloned at the commit recorded in results.jsonl and each finding is
re-derived by an independent check that reconstructs the rule's stated
condition from the repository tree. The checks below do not import
harness-eval; they are written against each rule's documented condition so
that they test the rule as specified rather than re-running it.

Circular reference chains get a second, stricter question: does the cycle
survive when only invocation constructs (a slash command after an invocation
verb, in backticks, or at line start) count as edges? A cycle built from
directory paths that collide with skill names is recorded as refuted.

The reference-resolution rule is sub-classified by consequence: dead
(no such basename anywhere in the tree), misrouted (basename exists at another
path), or runtime-output (the surrounding text tells the agent to create it).

usage: audit.py [--per-rule N] [--seed S] [--exhaustive rule1,rule2,...|all] [--workers K]
  --exhaustive audits every finding of the named rules (no sampling), so that
  prevalence for those rules counts only re-derived findings. "all" audits
  every candidate rule exhaustively except the ones in SAMPLED.
Every record in data/audit_findings.jsonl carries a verdict, a sub-class, and
a short evidence string (the entry, matcher, or path the check re-derived) so
that a consequence reading can be done from the audit file alone.
Writes data/audit_summary.json and data/audit_findings.jsonl (no repository content).
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = DATA / "results.jsonl"

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# Every rule whose condition is decidable from a file, the filesystem, or a
# comparison of two files, and whose consequence is a security exposure or a
# configuration that cannot work as written. Heuristic rules (judgments about
# prose) are not candidates and never carry a figure.
CANDIDATES = [
    # security: execution and credential surface
    "mcp/unpinned-package", "cross/overpermissive-grants", "security/dangerous-permission-grant",
    "hooks/permission-prompt-disabled", "hooks/local-settings-committed", "hooks/pre-trust-permissions",
    "hooks/api-key-helper", "hooks/base-url-override", "hooks/env-credential-override",
    "hooks/dangerous-command", "content/allowed-tools-auto-approve", "mcp/auto-approve-risk",
    "mcp/no-plaintext-secrets", "mcp/endpoint-integrity", "security/credential-file-present",
    "structural/symlink-escape",
    # configuration that cannot work as written
    "frontmatter/format-valid", "frontmatter/description-required", "agent/description-required",
    "structural/skill-md-exists", "hooks/command-script-exists", "hooks/valid-structure",
    "hooks/matcher-matches-no-tool", "hooks/permission-contradiction", "mcp/valid-config",
    "mcp/json-duplicate-keys", "hooks/json-duplicate-keys", "claude-md/include-exists",
    "command/script-exists", "command/references-nonexistent-skill", "agent/referenced-skills-exist",
    # cross-assistant
    "cross/multi-assistant-drift", "mcp/cross-assistant-divergence",
    # reference resolution: audited on a sample for its consequence split, never a blocker
    "content/broken-references",
]
SAMPLED = {"content/broken-references"}

# Claude Code built-in tool names as documented for hook matchers (PreToolUse,
# PostToolUse, PermissionRequest). Written independently of the tool's list and
# deliberately wider: a matcher on a tool that existed in some client version
# is not a dead matcher.
TOOL_NAMES = {"Bash", "Edit", "MultiEdit", "Write", "Read", "Glob", "Grep", "LS", "Task", "Agent", "WebFetch",
              "WebSearch", "NotebookEdit", "NotebookRead", "TodoWrite", "TodoRead", "BashOutput", "KillBash",
              "KillShell", "ExitPlanMode", "EnterPlanMode", "AskUserQuestion", "SlashCommand", "Skill",
              "ListMcpResourcesTool", "ReadMcpResourceTool", "Monitor", "mcp__example__tool"}
# Events whose matcher selects a tool name. Other events match on their own
# vocabulary (SessionStart: startup|resume|clear|compact; PreCompact: manual|auto;
# SessionEnd, Notification) or ignore the matcher.
TOOL_MATCHER_EVENTS = {"pretooluse", "posttooluse", "posttoolusefailure", "permissionrequest"}
LIFECYCLE_EVENTS = {"sessionstart", "sessionend", "precompact", "notification", "stop", "subagentstop"}
BUILTIN_SLASH = {"help", "clear", "compact", "init", "review", "model", "config", "cost", "doctor", "login",
                 "logout", "memory", "permissions", "pr_comments", "pr-comments", "status", "terminal-setup",
                 "vim", "bug", "release-notes", "mcp", "agents", "hooks", "plan", "resume", "add-dir", "ide",
                 "export", "exit", "quit", "rewind", "context", "todos", "usage", "output-style", "statusline",
                 "plugin", "plugins", "skills", "effort", "fast", "loop", "security-review", "simplify",
                 "continue", "commit", "fix", "test", "dev", "build", "run", "start", "deploy"}
SECRET_PREFIXES = ("sk-ant-", "sk-proj-", "ghp_", "gho_", "ghu_", "ghs_", "github_pat_", "glpat-", "AKIA", "ASIA",
                   "xoxb-", "xoxp-", "xoxa-", "AIza", "ya29.", "-----BEGIN")
DANGEROUS_HOOK = {
    "rm -rf": re.compile(r"\brm\s+-rf\b"), "chmod 777": re.compile(r"\bchmod\s+777\b"),
    "dd if=": re.compile(r"\bdd\s+if="), "mkfs": re.compile(r"\bmkfs\b"),
    "fork bomb": re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    "git push --force": re.compile(r"\bgit\s+push\s+--force\b"), "git reset --hard": re.compile(r"\bgit\s+reset\s+--hard\b"),
    "curl pipe to shell": re.compile(r"\bcurl\b.*\|\s*(?:bash|sh)\b"), "wget pipe to shell": re.compile(r"\bwget\b.*\|\s*(?:bash|sh)\b"),
}
DANGEROUS_GRANT = [
    (re.compile(r"sudo\b", re.I), "privilege_escalation"), (re.compile(r"\bsu\b", re.I), "privilege_escalation"),
    (re.compile(r"chmod\s+777\b"), "world_writable"), (re.compile(r"rm\s+-rf\s+/", re.I), "destructive_fs"),
    (re.compile(r"\bshred\b", re.I), "destructive_fs"), (re.compile(r"\bmkfs\b", re.I), "destructive_fs"),
    (re.compile(r"\bdd\b.*\bof=", re.I), "destructive_fs"), (re.compile(r"crontab\b", re.I), "persistence"),
    (re.compile(r"launchctl\b", re.I), "persistence"), (re.compile(r"systemctl\s+enable\b", re.I), "persistence"),
    (re.compile(r"curl.*\|\s*(?:ba)?sh\b", re.I), "remote_exec"), (re.compile(r"wget.*\|\s*(?:ba)?sh\b", re.I), "remote_exec"),
    (re.compile(r"terraform\s+destroy\b", re.I), "infra_destroy"), (re.compile(r"kubectl\s+delete\b", re.I), "infra_destroy"),
]

EXEC_CMDS = {"sh", "bash", "zsh", "dash", "fish", "env", "eval", "exec", "xargs", "nohup", "timeout", "watch",
             "sudo", "doas", "python", "python3", "perl", "ruby", "node", "bun", "deno", "php", "lua", "awk",
             "gawk", "mawk", "nawk", "sed", "find", "vim", "vi", "nvim", "less", "man", "npx", "bunx", "uvx",
             "pipx", "docker", "podman", "make", "ssh", "curl", "wget"}
# Commands whose wildcard grant is an unrestricted shell (the security class);
# curl, wget, make, docker, ssh and editors are scoped grants reported apart.
SHELL_EXEC_CMDS = {"sh", "bash", "zsh", "dash", "fish", "env", "eval", "exec", "xargs", "nohup", "timeout", "watch",
                   "sudo", "doas", "python", "python3", "perl", "ruby", "node", "bun", "deno", "php", "lua", "awk",
                   "gawk", "mawk", "nawk", "sed", "find", "vim", "vi", "nvim", "less", "man", "npx", "bunx", "uvx", "pipx"}
MACHINE_PATH_RE = re.compile(r"(/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\)")
FM_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)


def clone_pinned(full_name: str, sha: str) -> Path | None:
    tmp = Path(tempfile.mkdtemp(prefix="he-audit-"))
    dest = tmp / "repo"
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        subprocess.run(["git", "init", "-q", str(dest)], check=True, capture_output=True, env=env)
        subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", f"https://github.com/{full_name}.git"],
                       check=True, capture_output=True, env=env)
        r = subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin", sha],
                           capture_output=True, env=env, timeout=120)
        if r.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            return None
        subprocess.run(["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"], check=True, capture_output=True, env=env)
        return dest
    except Exception:  # noqa: BLE001
        shutil.rmtree(tmp, ignore_errors=True)
        return None


def _skills(root: Path) -> dict[str, Path]:
    """Every directory carrying a SKILL.md, keyed by directory name (first wins).
    Use _skills_all() when a finding must be matched against every candidate."""
    out: dict[str, Path] = {}
    for p in sorted(root.rglob("SKILL.md")):
        if ".git" in p.parts or "node_modules" in p.parts:
            continue
        out.setdefault(p.parent.name, p)
    return out


def _skills_all(root: Path) -> dict[str, list[Path]]:
    out: dict[str, list[Path]] = {}
    for p in sorted(root.rglob("SKILL.md")):
        if ".git" in p.parts or "node_modules" in p.parts:
            continue
        out.setdefault(p.parent.name, []).append(p)
    return out


def _walk_symlinks(root: Path, name: str):
    """Symlinks named *name* anywhere in the tree (rglob skips broken ones)."""
    for d, dirs, files in os.walk(root):
        for x in dirs + files:
            if x == name and os.path.islink(os.path.join(d, x)):
                yield Path(d) / x


def _commands(root: Path) -> dict[str, Path]:
    """Every markdown file under a commands/, command/, or prompts/ directory, keyed by stem."""
    out: dict[str, Path] = {}
    for f in sorted(root.rglob("*.md")):
        if ".git" in f.parts or "node_modules" in f.parts:
            continue
        if any(part in ("commands", "command", "prompts", "agents") for part in f.parts[:-1]):
            out.setdefault(f.stem, f)
    return out


def _commands_all(root: Path) -> dict[str, list[Path]]:
    out: dict[str, list[Path]] = {}
    for f in sorted(root.rglob("*.md")):
        if ".git" in f.parts or "node_modules" in f.parts:
            continue
        if any(part in ("commands", "command", "prompts", "agents") for part in f.parts[:-1]):
            out.setdefault(f.stem, []).append(f)
    return out


def _body(p: Path) -> str:
    try:
        t = p.read_text(errors="replace")
    except OSError:
        return ""
    m = FM_RE.match(t)
    return t[m.end():] if m else t


def _load_json(p: Path) -> tuple[object, bool]:
    """Parse JSON; on failure retry after stripping // and /* */ comments and
    trailing commas (JSONC, which VS Code and OpenCode accept). Returns
    (data, was_jsonc); (None, False) when neither parses."""
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return None, False
    try:
        return json.loads(text), False
    except json.JSONDecodeError:
        pass
    stripped = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    stripped = re.sub(r"(?m)^\s*//[^\n]*$", "", stripped)
    stripped = re.sub(r'(?<![:"\\])//(?![^"\n]*"[^"\n]*$)[^\n]*', "", stripped)
    stripped = re.sub(r",\s*([}\]])", r"\1", stripped)
    try:
        return json.loads(stripped), True
    except json.JSONDecodeError:
        return None, False


def _settings_files(root: Path) -> list[Path]:
    """Every project-scoped settings file the hooks rules read, root first."""
    out: list[Path] = []
    for rel in (".claude/settings.json", ".claude/settings.local.json", ".claude/hooks.json", ".cursor/hooks.json"):
        p = root / rel
        if p.is_file():
            out.append(p)
    for name in ("settings.json", "settings.local.json", "hooks.json"):
        for p in sorted(root.rglob(name)):
            if p.parent.name in (".claude", ".cursor") and p not in out and ".git" not in p.parts and "node_modules" not in p.parts:
                out.append(p)
    return out


def _hook_entries(data: object) -> list[dict]:
    """Flatten settings hooks into (event, matcher, command|prompt, type) records."""
    out: list[dict] = []
    hooks = data.get("hooks", {}) if isinstance(data, dict) else {}
    if not isinstance(hooks, dict):
        return out
    for event, lst in hooks.items():
        if not isinstance(lst, list):
            continue
        for entry in lst:
            if not isinstance(entry, dict):
                out.append({"event": event, "matcher": None, "command": str(entry), "type": "command"})
                continue
            nested = entry.get("hooks")
            if isinstance(nested, list) and nested:
                for sub in nested:
                    if isinstance(sub, str):
                        out.append({"event": event, "matcher": entry.get("matcher"), "command": sub, "type": "command"})
                    elif isinstance(sub, dict):
                        out.append({"event": event, "matcher": entry.get("matcher"), "command": sub.get("command"),
                                    "type": sub.get("type", "command" if "command" in sub else None),
                                    "prompt": sub.get("prompt")})
            else:
                out.append({"event": event, "matcher": entry.get("matcher"), "command": entry.get("command"),
                            "type": entry.get("type", "command" if "command" in entry else None), "prompt": entry.get("prompt")})
    return out


def _mcp_configs(root: Path) -> list[Path]:
    names = (".mcp.json", "mcp.json", "mcp_config.json", "settings.json", "opencode.json", "opencode.jsonc")
    return [p for p in sorted(root.rglob("*")) if p.name in names and p.is_file()
            and ".git" not in p.parts and "node_modules" not in p.parts]


def _servers(p: Path) -> dict:
    data, _ = _load_json(p)
    if not isinstance(data, dict):
        return {}
    for key in ("mcpServers", "servers", "mcp"):
        if isinstance(data.get(key), dict):
            return data[key]
    return {}


def _agents(root: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for base in (".claude/agents", ".github/agents", ".opencode/agents", ".opencode/agent", "agents", ".cursor/agents"):
        d = root / base
        if d.is_dir():
            for p in sorted(d.rglob("*.md")):
                out.setdefault(p.stem, p)
    return out


def _frontmatter(p: Path):
    """(frontmatter dict | None, body). None when there is no block or it does not parse."""
    text = p.read_text(errors="replace")
    m = FM_RE.match(text)
    if not m or yaml is None:
        return None, text
    try:
        fm = yaml.safe_load(m.group(1))
    except Exception:  # noqa: BLE001
        return None, text[m.end():]
    return (fm if isinstance(fm, dict) else None), text[m.end():]


# Three tiers of evidence for an edge, from strongest to weakest. The audit
# reports which tier a cycle survives on, so the paper can say what a
# "cycle" finding actually rests on.
_VERB_RE = re.compile(
    r"(?:\b(?:run|invoke|call|use|trigger|execute|start|then|delegate to|chain)s?\s+(?:the\s+)?[`\"']?/([\w][\w-]+)"
    r"|(?:^|\n)[ \t]*(?:[-*]|\d+\.)?[ \t]*/([\w][\w-]+)\b(?!/)"
    r"|\b(?:invoke|call|trigger|run)s?\s+(?:the\s+)?[`\"']([\w][\w-]+)[`\"']"
    r"|\b(?:skill|command):\s*[`\"']?([\w][\w-]+)"
    r"|\b(?:invoke|call|trigger|run|follow)s?\s+(?:the\s+)?([a-z0-9]+(?:-[a-z0-9]+)+)\b)", re.I)
_TICK_RE = re.compile(r"`/([\w][\w-]+)(?:\s[^`]*)?`")
_MENTION_RE = re.compile(r"(?<![\w./-])/([\w][\w-]+)(?![\w/])")
_HUMAN_RE = re.compile(r"(?:tell|ask)\s+the\s+user|the\s+users?\s+(?:should|must|can|sees?|runs?|types?)"
                       r"|\b(?:they|you)\s+run\b|\bmanually\b", re.I)


def _edges(body: str, own: str, tier: str) -> set[str]:
    if tier == "verb":
        names = set()
        for m in _VERB_RE.finditer(body):
            name = next(g for g in m.groups() if g)
            clause = body[max(0, m.start() - 120): m.end() + 100]
            clause = clause.split(".")[-1] if "." in clause[: m.start() - max(0, m.start() - 120)] else clause
            if _HUMAN_RE.search(body[max(0, m.start() - 120): m.end() + 100]):
                continue
            names.add(name)
    elif tier == "tick":
        names = set(_TICK_RE.findall(body))
    else:
        names = set(_MENTION_RE.findall(body))
    return {n for n in names if n != own}


def _has_cycle(graph: dict[str, set[str]], nodes: list[str]) -> bool:
    nodes_set = set(nodes)
    for start in nodes:
        stack = [(start, [start])]
        seen = set()
        while stack:
            cur, path = stack.pop()
            for nxt in graph.get(cur, ()):
                if nxt not in nodes_set:
                    continue
                if nxt == start and len(path) > 1:
                    return True
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append((nxt, path + [nxt]))
    return False


def check(rule: str, rec: dict, f: dict, root: Path) -> tuple[str, str]:
    """Return (verdict, subclass). verdict in confirmed / refuted / unverifiable."""
    msg = f.get("message", "")
    if rule == "cross/overpermissive-grants":
        m = re.search(r"entry '([^']+)' in (settings(?:\.local)?\.json)", msg)
        if not m:
            return "unverifiable", ""
        entry, fname = m.group(1), m.group(2)
        allow = []
        for p in _settings_files(root):
            if p.name != fname:
                continue
            data, _ = _load_json(p)
            if isinstance(data, dict) and isinstance(data.get("permissions"), dict):
                allow += data["permissions"].get("allow", []) or []
        if entry not in allow:
            return "refuted", "entry_absent"
        if entry == "Bash(*)":
            return "confirmed", "bash_star"
        if entry in ("Bash", "Edit", "Write", "WebFetch"):
            return "confirmed", "bare_tool"
        mm = re.match(r"^Bash\(\s*(?:[\w./-]*/)?([\w.+-]+)", entry)
        if mm and mm.group(1).lower() in EXEC_CMDS and entry.rstrip(")").endswith("*"):
            return "confirmed", "arbitrary_exec"
        return "refuted", "not_exec"
    if rule == "hooks/permission-contradiction":
        m = re.search(r"entry '([^']+)' is covered by permissions.deny entry '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        a, d = m.group(1), m.group(2)
        perms = None
        for p in _settings_files(root):
            data, _ = _load_json(p)
            if isinstance(data, dict) and isinstance(data.get("permissions"), dict):
                pp = data["permissions"]
                if a in (pp.get("allow") or []) and d in (pp.get("deny") or []):
                    perms = pp
                    break
        if perms is None:
            return "refuted", "entry_absent"
        ta, td = a.split("(")[0], d.split("(")[0]
        if ta != td:
            return "refuted", "tool_differs"
        if "(" not in d:
            return "confirmed", "bare_deny"
        sa = a[a.index("(") + 1:-1] if "(" in a else ""
        sd = d[d.index("(") + 1:-1]
        if sd == sa or sd == "*" or (sd.endswith("*") and sa.startswith(sd.rstrip("*").rstrip(":"))):
            return "confirmed", "covered"
        return "refuted", "not_covered"
    if rule == "hooks/permission-prompt-disabled" and "dotfiles" in rec.get("full_name", "").lower():
        return "confirmed", "dotfiles_repo"      # user-scoped settings kept in git, not a project setting
    if rule == "hooks/permission-prompt-disabled":
        for p in _settings_files(root):
            if p.name != "settings.json":
                continue
            data, _ = _load_json(p)
            if not isinstance(data, dict):
                continue
            mode = data.get("permissions", {}).get("defaultMode") if isinstance(data.get("permissions"), dict) else None
            if "defaultMode" in msg and mode in ("bypassPermissions", "dontAsk", "acceptEdits"):
                return "confirmed", mode
            if "enableAllProjectMcpServers" in msg and data.get("enableAllProjectMcpServers") is True:
                return "confirmed", "all_mcp"
            if "skipDangerous" in msg and data.get("skipDangerousModePermissionPrompt") is True:
                return "confirmed", "skip_dangerous"
        return ("unverifiable", "") if not any(k in msg for k in ("defaultMode", "enableAllProjectMcpServers", "skipDangerous")) else ("refuted", "")
    if rule == "hooks/local-settings-committed":
        hits = [p for p in root.rglob("settings.local.json") if p.parent.name == ".claude" and ".git" not in p.parts]
        direct = root / ".claude" / "settings.local.json"
        if direct.is_file() and direct not in hits:
            hits.insert(0, direct)
        if not hits:
            return "refuted", "not_a_claude_dir"
        data, _ = _load_json(hits[0])
        allow = (data.get("permissions", {}) or {}).get("allow", []) if isinstance(data, dict) and isinstance(data.get("permissions"), dict) else []
        return "confirmed", ("with_grants" if allow else "no_grants")
    if rule == "hooks/pre-trust-permissions":
        for p in _settings_files(root):
            if p.name != "settings.json":
                continue
            data, _ = _load_json(p)
            if not isinstance(data, dict):
                continue
            if "permissions.allow" in msg:
                allow = data.get("permissions", {}).get("allow") if isinstance(data.get("permissions"), dict) else None
                if isinstance(allow, list) and allow:
                    exec_like = any(re.match(r"^Bash\(\s*(?:[\w./-]*/)?([\w.+-]+)", e) and re.match(r"^Bash\(\s*(?:[\w./-]*/)?([\w.+-]+)", e).group(1).lower() in EXEC_CMDS
                                    or e in ("Bash", "Bash(*)") for e in allow if isinstance(e, str))
                    return "confirmed", ("allow_with_exec_grant" if exec_like else "allow_scoped_only")
                continue
            mm = re.search(r"define '([^']+)' hooks", msg)
            if mm:
                ev = mm.group(1)
                cmds = [h for h in _hook_entries(data) if str(h["event"]).lower() == ev.lower() and (h.get("command") or h.get("prompt"))]
                if ev.lower() in LIFECYCLE_EVENTS and cmds:
                    return "confirmed", f"lifecycle_{ev.lower()}"
        return "refuted", ""
    if rule == "hooks/api-key-helper":
        for p in _settings_files(root):
            data, _ = _load_json(p)
            if isinstance(data, dict) and "apiKeyHelper" in data:
                return "confirmed", ""
        return "refuted", ""
    if rule == "hooks/base-url-override":
        m = re.search(r"override '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        var = m.group(1)
        for p in _settings_files(root):
            data, _ = _load_json(p)
            if isinstance(data, dict) and isinstance(data.get("env"), dict) and any(k.upper() == var.upper() for k in data["env"]):
                val = next(v for k, v in data["env"].items() if k.upper() == var.upper())
                return "confirmed", ("env_key_literal" if isinstance(val, str) and not val.startswith("$") else "env_key_reference")
            if any(isinstance(h.get("command"), str) and var.upper() in h["command"].upper() for h in _hook_entries(data)):
                return "confirmed", "in_hook_command"
            if var.upper() in p.read_text(errors="replace").upper():
                return "refuted", "mention_only"
        return "refuted", ""
    if rule == "hooks/env-credential-override":
        m = re.search(r"env var '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        var = m.group(1)
        for p in _settings_files(root):
            data, _ = _load_json(p)
            if isinstance(data, dict) and isinstance(data.get("env"), dict) and var in data["env"]:
                val = data["env"][var]
                if not isinstance(val, str) or not val.strip() or val.startswith("$") or "${" in val:
                    return "confirmed", "passthrough_or_empty"
                low = val.lower()
                if any(x in low for x in ("your_", "changeme", "xxx", "todo", "example", "placeholder", "<", "dummy")):
                    return "confirmed", "placeholder"
                return "confirmed", "literal_value"
        return "refuted", ""
    if rule == "security/dangerous-permission-grant":
        m = re.search(r"grants '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        entry = m.group(1)
        for p in _settings_files(root):
            data, _ = _load_json(p)
            allow = data.get("permissions", {}).get("allow", []) if isinstance(data, dict) and isinstance(data.get("permissions"), dict) else []
            if entry in (allow or []):
                for pat, label in DANGEROUS_GRANT:
                    if pat.search(entry):
                        return "confirmed", label
                return "refuted", "no_pattern"
        return "refuted", "entry_absent"
    if rule == "hooks/dangerous-command":
        m = re.search(r"event '([^']+)' contains dangerous command: '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        ev, label = m.groups()
        pat = DANGEROUS_HOOK.get(label)
        if pat is None:
            return "unverifiable", "unknown_label"
        for p in _settings_files(root):
            data, _ = _load_json(p)
            for h in _hook_entries(data):
                if str(h["event"]).lower() == ev.lower() and isinstance(h.get("command"), str) and pat.search(h["command"]):
                    sub = label.replace(" ", "_").replace("-", "")
                    if label == "rm -rf":
                        tgt = re.search(r"rm\s+-rf\s+(\S+)", h["command"])
                        t = tgt.group(1) if tgt else ""
                        sub = "rm_rf_root" if t in ("/", "~", "$HOME", "/*") else ("rm_rf_variable" if t.startswith("$") else "rm_rf_path")
                    return "confirmed", sub
        return "refuted", ""
    if rule == "hooks/valid-structure":
        m = re.search(r"event '([^']+)' has no command", msg)
        if not m:
            return "unverifiable", ""
        ev = m.group(1)
        for p in _settings_files(root):
            data, _ = _load_json(p)
            for h in _hook_entries(data):
                if str(h["event"]).lower() != ev.lower():
                    continue
                if h.get("command"):
                    continue
                if h.get("type") in ("prompt", "agent") or h.get("prompt"):
                    return "refuted", "prompt_hook"
                return "confirmed", ("empty_command" if h.get("command") == "" else "no_command_key")
        return "refuted", "all_have_commands"
    if rule == "hooks/matcher-matches-no-tool":
        m = re.search(r"Matcher '([^']*)'", msg)
        if not m:
            return "unverifiable", ""
        matcher = m.group(1)
        for p in _settings_files(root):
            data, _ = _load_json(p)
            for h in _hook_entries(data):
                if h.get("matcher") != matcher:
                    continue
                ev = str(h["event"]).lower()
                if ev not in TOOL_MATCHER_EVENTS:
                    return "refuted", "event_specific_matcher"
                try:
                    pat = re.compile(matcher)
                except re.error:
                    return "confirmed", "invalid_regex"
                if any(pat.search(n) for n in TOOL_NAMES):
                    return "refuted", "known_tool_outside_list"
                if any(n.lower() == matcher.lower() for n in TOOL_NAMES):
                    return "confirmed", "case_mismatch"
                if re.match(r"^mcp__", matcher, re.I):
                    return "refuted", "mcp_tool_pattern"
                return "confirmed", "unknown_tool"
        return "refuted", "matcher_absent"
    if rule == "mcp/valid-config":
        comp = f.get("component", "")
        cands = [p for p in _mcp_configs(root) if p.name == comp] or [p for p in _mcp_configs(root) if comp.endswith(p.name)]
        if not cands:
            return "unverifiable", "config_not_found"
        if "not valid JSON" in msg:
            parsed = [_load_json(p) for p in cands]
            if any(d is None for d, _ in parsed):
                return "confirmed", "invalid_json"
            return ("refuted", "jsonc_parses") if any(j for _, j in parsed) else ("refuted", "parses")
        for p in cands:
            data, jsonc = _load_json(p)
            if not isinstance(data, dict):
                continue
            if "has no 'mcpServers'" in msg:
                if not any(k in data for k in ("mcpServers", "mcp_servers", "servers", "mcp")):
                    if p.name == "settings.json":
                        return "refuted", "settings_without_mcp_section"
                    entries = {k: v for k, v in data.items() if not k.startswith("$")}
                    if entries and all(isinstance(v, dict) and any(k in v for k in ("command", "url", "httpUrl", "type", "args")) for v in entries.values()):
                        return "confirmed", "flat_server_map"   # plugin-style map, a valid layout
                    return "confirmed", "missing_servers_key"
                continue   # another file of the same name may be the one flagged
            mm = re.search(r"Server '([^']+)' has no 'command'", msg)
            if mm:
                sd = _servers(p).get(mm.group(1))
                if not isinstance(sd, dict):
                    continue
                if sd.get("command") or sd.get("url"):
                    continue
                if any(sd.get(k) for k in ("httpUrl", "serverUrl", "uri", "endpoint", "transport", "cmd")):
                    return "refuted", "alternate_transport_key"
                if "url" in sd and not sd.get("url"):
                    return "confirmed", "empty_url_placeholder"
                return "confirmed", "no_transport"
            mm = re.search(r"Server '([^']+)': '(args|env)' must be", msg)
            if mm:
                sd = _servers(p).get(mm.group(1))
                if not isinstance(sd, dict):
                    continue
                v = sd.get(mm.group(2))
                bad = (mm.group(2) == "args" and v is not None and not isinstance(v, list)) or \
                      (mm.group(2) == "env" and v is not None and not isinstance(v, dict))
                return ("confirmed", f"{mm.group(2)}_wrong_type") if bad else ("refuted", "")
        if "has no 'mcpServers'" in msg:
            return "refuted", "has_servers_key"
        if re.search(r"Server '([^']+)' has no 'command'", msg):
            return "refuted", "has_transport"
        return "unverifiable", ""
    if rule == "mcp/auto-approve-risk":
        m = re.search(r"Server '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        name = m.group(1)
        tool = re.search(r"auto-approves '([^']+)'", msg)
        for p in _mcp_configs(root):
            sd = _servers(p).get(name)
            if not isinstance(sd, dict) or "autoApprove" not in sd:
                continue
            aa = sd["autoApprove"]
            if tool:
                return ("confirmed", "write_or_exec_tool") if isinstance(aa, list) and tool.group(1) in aa else ("refuted", "tool_absent")
            return ("confirmed", "empty_list") if aa == [] else ("refuted", "")
        return "refuted", "server_absent"
    if rule == "mcp/no-plaintext-secrets":
        m = re.search(r"server '([^']+)': '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        name, key = m.groups()
        for p in _mcp_configs(root):
            sd = _servers(p).get(name)
            if not isinstance(sd, dict):
                continue
            for section in ("env", "headers"):
                d = sd.get(section)
                if isinstance(d, dict) and key in d and isinstance(d[key], str):
                    v = d[key]
                    if v.startswith("$") or "${" in v:
                        return "refuted", "env_reference"
                    low = v.lower()
                    if any(x in low for x in ("your_", "changeme", "xxx", "todo", "example", "placeholder", "dummy")) or (low.startswith("<") and low.endswith(">")):
                        return "refuted", "placeholder"
                    if v.startswith(SECRET_PREFIXES):
                        return "confirmed", "known_prefix"
                    if v.startswith("sk-") and len(v) >= 32:
                        return "confirmed", "sk_prefix"
                    if len(v) >= 20:
                        return "confirmed", "high_entropy_value"
                    return "refuted", "short_value"
        return "refuted", "key_absent"
    if rule == "content/allowed-tools-auto-approve":
        m = re.search(r"allowed-tools includes '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        tool = m.group(1)
        comp = f.get("component", "")
        cands = _skills_all(root).get(comp, [])
        if not cands:
            return "unverifiable", "skill_not_found"
        allowed = []
        for cand in cands:
            fm, _ = _frontmatter(cand)
            a = (fm or {}).get("allowed-tools")
            if isinstance(a, str):
                a = [x.strip() for x in a.split(",")]
            if isinstance(a, list):
                allowed += a
        if tool not in allowed:
            return "refuted", "entry_absent"
        t = tool.strip()
        if t.lower() in ("bash", "bash(*)", "bash(:*)"):
            return "confirmed", "bash_unrestricted"
        mm = re.match(r"^Bash\(\s*(?:[\w./-]*/)?([\w.+-]+)(?:\s+(-c|-e|-r|--eval|-exec|run))?(?::\s*\*|\s+\*|\*)\s*\)$", t, re.I)
        if mm and mm.group(1).lower() in SHELL_EXEC_CMDS:
            return "confirmed", "bash_exec_cmd"
        if t.lower().startswith("bash("):
            return "confirmed", "bash_scoped"
        return "confirmed", "write_tool"
    if rule == "frontmatter/description-required":
        comp = f.get("component", "")
        cands = _skills_all(root).get(comp, [])
        if not cands:
            return "unverifiable", "skill_not_found"
        verdicts = []
        for cand in cands:
            fm, _ = _frontmatter(cand)
            if fm is None:
                # The description is indeed absent, but so is the whole block; the
                # loading defect is frontmatter/format-valid's and is counted there.
                verdicts.append(("confirmed", "no_frontmatter_duplicate"))
            elif fm.get("description") is None:
                verdicts.append(("confirmed", "missing"))
            elif isinstance(fm.get("description"), str) and not fm["description"].strip():
                verdicts.append(("confirmed", "empty"))
        return next((v for v in verdicts if v[1] != "no_frontmatter_duplicate"), verdicts[0]) if verdicts else ("refuted", "present")
    if rule == "structural/skill-md-exists":
        m = re.search(r"SKILL\.md not found in (\S+)", msg)
        name = m.group(1) if m else f.get("component", "")
        for d in root.rglob(name):
            if not d.is_dir() or ".git" in d.parts or "node_modules" in d.parts or d.parent.name not in ("skills", "skill"):
                continue
            if (d / "SKILL.md").is_file():
                return "refuted", "exists"
            files = [p for p in d.rglob("*") if p.is_file()]
            if any(p.name.lower() == "skill.md" for p in files):
                return "confirmed", "case_variant"
            if any(p.suffix.lower() == ".md" for p in files):
                return "confirmed", "markdown_without_skill_md"
            return "confirmed", ("empty_dir" if not files else "support_files_only")
        return "unverifiable", "dir_not_found"
    if rule == "agent/referenced-skills-exist":
        m = re.search(r"references skill '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        name = m.group(1)
        comp = f.get("component", "")
        ag = _agents(root)
        p = ag.get(comp)
        if p is None:
            return "unverifiable", "agent_not_found"
        fm, _ = _frontmatter(p)
        refs = (fm or {}).get("skills", [])
        if isinstance(refs, str):
            refs = [x.strip() for x in refs.split(",")]
        if name not in (refs or []):
            return "refuted", "not_declared"
        bare = name.split(":", 1)[1] if ":" in name else name
        if bare in _skills(root):
            return "refuted", "skill_exists"
        if "/" in bare and bare.rstrip("/").split("/")[-1] in _skills(root):
            return "refuted", "path_style_skill_exists"
        if ":" in name:
            plugins = set()
            for pj in root.rglob("plugin.json"):
                if pj.parent.name == ".claude-plugin":
                    d, _ = _load_json(pj)
                    if isinstance(d, dict) and isinstance(d.get("name"), str):
                        plugins.add(d["name"])
            if name.split(":", 1)[0] not in plugins:
                return "confirmed", "external_plugin"   # installed-plugin reference, not this repository's
        return "confirmed", "missing"
    if rule == "command/references-nonexistent-skill":
        m = re.search(r"Command '([^']+)' references skill '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        cname, sname = m.groups()
        cmds = _commands(root)
        cp = cmds.get(cname)
        if cp is None:
            return "unverifiable", "command_not_found"
        body = _body(cp)
        if not re.search(rf"(?<![\w./-])/{re.escape(sname)}(?![\w-])", body) and not re.search(rf"skill\s+[`'\"/]?{re.escape(sname)}", body, re.I):
            return "refuted", "token_absent"
        if sname in _skills(root):
            return "refuted", "skill_exists"
        if sname in cmds and sname != cname:
            return "refuted", "is_command"
        if sname in _agents(root):
            return "refuted", "is_agent"
        if sname.lower() in BUILTIN_SLASH:
            return "refuted", "builtin_or_generic_word"
        if sname.isdigit():
            return "refuted", "numeric_token"
        if re.search(rf"/{re.escape(sname)}[/.]", body) or re.search(rf"[\w.]/{re.escape(sname)}\b", body):
            return "refuted", "path_segment"
        return "confirmed", "dangling"
    if rule == "command/script-exists":
        m = re.search(r"references '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        ref = m.group(1)
        cname = f.get("component", "")
        cands = [p for p in _commands_all(root).get(cname, []) if ref in _body(p)]
        if not cands and cname not in _commands_all(root):
            return "unverifiable", "command_not_found"
        if not cands:
            return "refuted", "token_absent"
        cp = cands[0]
        if any(ch in ref for ch in "$<{~*"):
            return "refuted", "templated"
        if re.match(r"^(?:[A-Z][\w.-]*\.js|(?:foo|bar|baz|example|sample|placeholder|my[_-]?script|your[_-]?script|script|file|test)\.\w+|(?:\./)?path/to/.*)$", ref):
            return "refuted", "prose_mention"
        for cand in (cp.parent / ref, root / ref):
            if cand.exists():
                return "refuted", "resolves"
        base = Path(ref).name
        if any(p.name == base for p in root.rglob(base) if p.is_file()):
            return "confirmed", "misrouted"
        return "confirmed", "dead"
    if rule == "frontmatter/format-valid":
        comp = f.get("component", "")
        cands = _skills_all(root).get(comp, [])
        if not cands:
            return "unverifiable", "skill_not_found"
        if yaml is None:
            return "unverifiable", "no_yaml"
        for p in cands:
            text = p.read_text(errors="replace")
            m = FM_RE.match(text)
            if not m:
                if "no yaml frontmatter" in msg.lower():
                    if re.search(r"/(?:archive|_archive|deprecated|old)/", "/" + str(p.relative_to(root)).lower() + "/"):
                        return "confirmed", "archived_location"   # not a directory any client loads
                    if text.startswith("\ufeff---"):
                        return "confirmed", "bom_before_frontmatter"
                    return "confirmed", "no_frontmatter"
                continue
            try:
                fm = yaml.safe_load(m.group(1))
            except Exception:  # noqa: BLE001
                return "confirmed", "invalid_yaml"
            if not isinstance(fm, dict):
                return "confirmed", "invalid_yaml"
            if "name" not in fm and "'name'" in msg:
                return "confirmed", "missing_name"
        return "refuted", "frontmatter_valid"
    if rule == "content/hardcoded-machine-path":
        comp = f.get("component", "")
        sk = _skills(root)
        cands = list(sk.values()) + list(_commands(root).values()) + [root / "CLAUDE.md", root / "AGENTS.md"]
        if comp in sk:
            for p in sk[comp].parent.rglob("*"):
                if p.is_file() and p.suffix in (".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml", ".toml") \
                        and MACHINE_PATH_RE.search(p.read_text(errors="replace")):
                    return "confirmed", "named_component"
        for p in cands:
            if p.is_file() and (comp == p.parent.name or comp == p.stem or comp == p.name) and MACHINE_PATH_RE.search(p.read_text(errors="replace")):
                return "confirmed", "named_component"
        for p in cands:
            if p.is_file() and MACHINE_PATH_RE.search(p.read_text(errors="replace")):
                return "confirmed", "other_component"
        # Supporting files inside any skill directory (references/, scripts/) are in the rule's scan surface.
        for skill_md in sk.values():
            for p in skill_md.parent.rglob("*"):
                if p.is_file() and p.suffix in (".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml", ".toml") \
                        and MACHINE_PATH_RE.search(p.read_text(errors="replace")):
                    return "confirmed", "supporting_file"
        return "refuted", ""
    if rule == "mcp/unpinned-package":
        for c in _mcp_configs(root):
            servers = _servers(c)
            for name, sd in servers.items():
                if not isinstance(sd, dict):
                    continue
                parts = [str(sd.get("command", "")).rsplit("/", 1)[-1]] + [str(a) for a in sd.get("args", [])]
                parts = [p.lower().removesuffix(".cmd").removesuffix(".exe") for p in parts]
                runner = next((p for p in parts if p in ("npx", "bunx", "uvx", "pipx")), None)
                cmd = runner or parts[0]
                args = parts[parts.index(runner) + 1:] if runner else parts[1:]
                if cmd in ("npx", "bunx", "uvx", "pipx") and name in msg:
                    pkgs = [a for a in args if not a.startswith("-") and a not in ("run", "/c", "-c")]
                    if pkgs and ("@" not in pkgs[0].lstrip("@") or pkgs[0].endswith("@latest")):
                        rel = "/" + str(c.relative_to(root)).lower() + "/"
                        if re.search(r"/(?:tests?|testdata|fixtures?|__fixtures__|__snapshots__|benchmarks?|evaluation|corpus|vulnerable-configs)/", rel):
                            return "confirmed", "fixture_path"
                        if re.search(r"/(?:templates?|examples?|_templates|registry|sample|profiles|tutorials?|lessons?|config/source|\d\d-[a-z]+/projects)/", rel):
                            return "confirmed", "template_path"
                        if cmd in ("npx", "bunx") and ("--no-install" in args or "--offline" in args):
                            return "confirmed", "no_install"          # never fetches; runs only an installed package
                        if cmd in ("npx", "bunx") and pkgs[0] in ("tsx", "ts-node", "node", "bun") and any(("/" in a or a.endswith((".ts", ".js", ".mjs", ".py"))) for a in pkgs[1:]):
                            return "confirmed", "local_runner"        # runs a file in the repository; only the runner is fetched
                        if cmd == "npx" and "@" not in pkgs[0].lstrip("@"):
                            pjs = [d / "package.json" for d in [c.parent, *c.parent.parents] if d == root or root in d.parents]
                            for pj in pjs:
                                d, _ = _load_json(pj) if pj.is_file() else (None, False)
                                if isinstance(d, dict) and pkgs[0] in {**d.get("dependencies", {}), **d.get("devDependencies", {})}:
                                    return "confirmed", "project_local_dependency"   # resolved from node_modules, pinned by the lockfile
                                if isinstance(d, dict) and d.get("name") == pkgs[0]:
                                    return "confirmed", "own_package"   # the server's own repository declares its published package; npx still fetches the registry's latest
                        return "confirmed", cmd
                if cmd == "docker" and name in msg:
                    imgs = [a for a in args if a and not a.startswith("-") and a not in ("run", "exec")]
                    if imgs and "@" not in imgs[-1] and (":" not in imgs[-1] or imgs[-1].endswith(":latest")):
                        return "confirmed", "docker"
        return "refuted", ""
    if rule == "agent/description-required":
        _comp = str(f.get("component") or f.get("file") or "").lower()
        if re.search(r"(?:^|/)(?:readme|agents|claude|index|changelog|contributing|overview|[\w-]*-conventions)\.md$", _comp):
            return "confirmed", "doc_like_file"
        comp = f.get("component", "")
        p = _agents(root).get(comp)
        if p is None:
            return "unverifiable", "agent_not_found"
        stem = p.stem.removesuffix(".agent")
        if stem.lower() in ("readme", "index", "claude", "agents", "changelog", "contributing", "license", "template", "_template", "example") \
                or (stem.upper() == stem and any(ch.isalpha() for ch in stem) and len(stem) > 2):
            return "refuted", "non_agent_file"
        fm, _ = _frontmatter(p)
        in_assistant_dir = p.parent.parent.name in (".claude", ".github", ".opencode", ".cursor")
        if fm is None:
            # A root-level agents/ directory also holds instruction documents;
            # a file there without frontmatter is not evidence of a subagent.
            return "confirmed", ("no_frontmatter" if in_assistant_dir else "no_frontmatter_root_agents_dir")
        d = fm.get("description")
        if d is None:
            return "confirmed", "missing"
        if isinstance(d, str) and not d.strip():
            return "confirmed", "empty"
        return "refuted", ""
    if rule == "content/circular-references":
        m = re.search(r"Circular reference detected: (.+)$", msg)
        if not m:
            return "unverifiable", ""
        nodes = [n.strip() for n in m.group(1).split("->")]
        nodes = list(dict.fromkeys(nodes))
        comps = {**_commands(root), **_skills(root)}
        if any(n not in comps for n in nodes):
            return "refuted", "component_missing"
        bodies = {n: _body(comps[n]) for n in nodes}
        verb = {n: _edges(bodies[n], n, "verb") for n in nodes}
        tick = {n: verb[n] | _edges(bodies[n], n, "tick") for n in nodes}
        loose = {n: tick[n] | _edges(bodies[n], n, "mention") for n in nodes}
        if _has_cycle(verb, nodes):
            return "confirmed", "invocation_cycle"
        if _has_cycle(tick, nodes):
            return "refuted", "documented_command_cycle"
        if _has_cycle(loose, nodes):
            return "refuted", "mention_cycle"
        return "refuted", "no_cycle"
    if rule == "cross/multi-assistant-drift":
        files = [root / n for n in ("CLAUDE.md", "AGENTS.md", "GEMINI.md") if (root / n).is_file()]
        if len(files) < 2:
            return "refuted", "single_file"
        def sections(t):
            out, cur, buf = {}, "(root)", []
            for line in t.splitlines():
                mm = re.match(r"^#{1,6}\s+(.+)$", line)
                if mm:
                    out[cur] = "\n".join(buf).strip(); cur, buf = mm.group(1).strip(), []
                else:
                    buf.append(line)
            out[cur] = "\n".join(buf).strip()
            return {k: re.sub(r"\s+", " ", v) for k, v in out.items() if v}
        secs = [sections(p.read_text(errors="replace")) for p in files]
        shared_differs, shared_same = 0, 0
        for i in range(len(secs)):
            for j in range(i + 1, len(secs)):
                for k in set(secs[i]) & set(secs[j]):
                    if secs[i][k] != secs[j][k]:
                        shared_differs += 1
                    else:
                        shared_same += 1
        if shared_differs:
            return "confirmed", "diverged"
        if shared_same:
            return "refuted", "identical"
        return "confirmed", "unrelated_files"
    if rule == "content/mcp-skill-alignment":
        m = re.search(r"'([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        server = m.group(1)
        cfg = root / ".mcp.json"
        try:
            servers = json.loads(cfg.read_text()).get("mcpServers", {})
        except Exception:  # noqa: BLE001
            return "refuted", "config_unreadable"
        if server not in servers:
            return "refuted", "server_absent"
        consumers = list(_skills(root).values()) + list(_commands(root).values())
        consumers += [root / n for n in ("CLAUDE.md", "AGENTS.md", "GEMINI.md") if (root / n).is_file()]
        for d in (root / ".claude" / "agents", root / ".github" / "agents"):
            if d.is_dir():
                consumers += list(d.rglob("*.md"))
        text = "\n".join(p.read_text(errors="replace") for p in consumers if p.is_file()).lower()
        if re.search(r"\bmcp__\w+|\bmcp[_\- ]tool\b|\buse[_ ]mcp\b|\bmcp server\b", text):
            return "refuted", "generic_mcp_mention"
        if re.search(rf"(?<![\w-]){re.escape(server.lower())}(?![\w-])", text):
            return "refuted", "server_referenced"
        return "confirmed", ""
    if rule == "mcp/cross-assistant-divergence":
        m = re.search(r"server '([^']+)' is declared differently in (\S+) \(.*?\) and (\S+) ", msg)
        if not m:
            return "unverifiable", ""
        name, fa, fb = m.groups()
        def load(rel):
            cands = [root / rel] + [p for p in root.rglob(Path(rel).name) if p.is_file() and str(p).endswith(rel.replace("~/", ""))]
            for p in cands:
                if not p.is_file():
                    continue
                d, _ = _load_json(p)
                if not isinstance(d, dict):
                    continue
                for key in ("mcpServers", "servers", "mcp"):
                    if isinstance(d.get(key), dict) and name in d[key]:
                        return d[key][name]
            return None
        a, b = load(fa), load(fb)
        if a is None or b is None:
            return "refuted", "server_absent"
        norm = lambda s: json.dumps({k: s.get(k) for k in ("command", "args", "url", "type", "transport") if k in s}, sort_keys=True)
        return ("confirmed", "") if norm(a) != norm(b) else ("refuted", "identical")
    if rule == "content/broken-references":
        m = re.search(r"'([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        ref = m.group(1)
        comp = f.get("component", "")
        sk = _skills(root)
        base = sk[comp].parent if comp in sk else root
        for cand in (base / ref, base / "scripts" / ref, root / ref):
            if cand.exists():
                return "refuted", "resolves"
        basename = Path(ref).name
        exists_elsewhere = any(p.name == basename for p in root.rglob("*") if p.is_file()) if basename else False
        body = _body(sk[comp]) if comp in sk else ""
        idx = body.find(ref)
        window = body[max(0, idx - 300): idx + 300].lower() if idx >= 0 else ""
        if re.search(r"\b(create|generate|write|save|record|store|output to|will be created|if (?:this|it) (?:is )?missing|does not exist)\b", window):
            return "confirmed", "runtime_output"
        return ("confirmed", "misrouted") if exists_elsewhere else ("confirmed", "dead")

    if rule in ("mcp/json-duplicate-keys", "hooks/json-duplicate-keys"):
        m = re.search(r"Duplicate JSON key '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        key = m.group(1)
        names = (".mcp.json", "mcp.json", "settings.json", "hooks.json", "settings.local.json")
        for c in [p for p in root.rglob("*.json") if p.name in names and ".git" not in p.parts]:
            text = c.read_text(errors="replace")
            dupes: list[str] = []

            def hook(pairs, _d=dupes):
                seen = {}
                for k, v in pairs:
                    if k in seen:
                        _d.append(k)
                    seen[k] = v
                return seen

            try:
                json.loads(text, object_pairs_hook=hook)
            except json.JSONDecodeError:
                continue
            if key in dupes:
                return "confirmed", ""
        return "refuted", ""
    if rule == "claude-md/include-exists":
        m = re.search(r"Import '@([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        ref = m.group(1)
        looked = re.search(r"looked for (\S+?)\)", msg)
        if looked:
            abs_path = looked.group(1)
            rel = re.sub(r"^/tmp/he-[^/]+/repo/", "", abs_path)
            if rel != abs_path:
                target = root / rel
                if target.exists():
                    return "refuted", "exists"
                if re.search(r"\.local\.md$", ref, re.I):
                    return "confirmed", "local_import"      # per-machine file, uncommitted by design
                if re.search(r"(^|/)(fixtures?|__fixtures__|testdata|test-data)/", rel):
                    return "confirmed", "fixture_path"
                # Cursor rules reference files with @path relative to the project root.
                if "/.cursor/rules/" in str(target) and (root / ref.lstrip("/")).exists():
                    return "refuted", "resolves_from_root"
                if "/.cursor/rules/" in str(target) or target.suffix == ".mdc":
                    return "confirmed", "cursor_rule_import"
                return "confirmed", ""
        explicit = ref.startswith(("./", "../", "~/"))
        if ref.startswith("/") and not ref.lower().endswith((".md", ".txt", ".mdc", ".markdown", ".rst", ".json", ".yaml", ".yml", ".toml")):
            return "refuted", "path_alias"
        has_ext = ref.lower().endswith((".md", ".txt", ".mdc", ".markdown", ".rst", ".json", ".yaml", ".yml", ".toml"))
        if not explicit and not has_ext:
            return "refuted", "package_or_decorator"
        for ctx in list(root.rglob("CLAUDE.md")) + list(root.rglob("AGENTS.md")) + list(root.rglob("GEMINI.md")):
            if ".git" in ctx.parts:
                continue
            if ctx.is_file() and ("@" + ref) in ctx.read_text(errors="replace"):
                return ("refuted", "exists") if (ctx.parent / ref).exists() else ("confirmed", "")
        return "unverifiable", "import_not_found"
    if rule == "hooks/command-script-exists":
        m = re.search(r"references '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        pth = m.group(1)
        whole_command = " " in pth.strip()
        pth = pth.strip().split()[0] if pth.strip() else pth
        pth = re.sub(r"\$\{(?:CLAUDE_PROJECT_DIR|CURSOR_PROJECT_DIR|PROJECT_DIR|PWD):[-=][^}]*\}/?", "", pth)
        for var in ("$CLAUDE_PROJECT_DIR/", "${CLAUDE_PROJECT_DIR}/", "$CURSOR_PROJECT_DIR/", "$PROJECT_DIR/"):
            pth = pth.replace(var, "")
        if pth.startswith(("$", "~")):
            return "confirmed", "outside_repo_variable"   # $HOME, ~, $root: an install location, not a repository path
        holders = [p for p in _settings_files(root) if pth.split("/")[-1] in p.read_text(errors="replace")]
        if not holders:
            return "unverifiable", "not_in_settings"
        for h in holders:
            for base in (root, h.parent, h.parent.parent):
                if (base / pth).exists():
                    return "refuted", ("exists_path_had_args" if whole_command else "exists")
        base = Path(pth).name
        if any(p.name == base for p in root.rglob(base) if p.is_file()):
            return "confirmed", "misrouted"
        return "confirmed", "dead"
    if rule == "mcp/endpoint-integrity":
        _rel = "/" + str(f.get("file") or "").lower() + "/"
        if re.search(r"/(?:tests?|fixtures?|examples?|vulnerable-configs|samples?)/", _rel):
            return "confirmed", "fixture_path"
        _m = re.search(r"non-loopback host '([^']+)'", msg)
        if _m and (("." not in _m.group(1)) or _m.group(1).endswith((".local", ".internal", ".example.net", ".example.com", ".lan", ".localdomain")) or re.match(r"^(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.", _m.group(1))):
            return "confirmed", "internal_hostname"    # a compose/LAN/placeholder host, not a public endpoint
        if re.search(r"'(?:\./)?(?:node_modules|dist|build|target|out|venv|\.venv|\.[A-Za-z][\w.-]*)/", msg) and "does not exist" in msg:
            return "confirmed", "build_output"
        from urllib.parse import urlsplit
        m = re.search(r"server '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        name = m.group(1)
        for c in [p for p in root.rglob("*.json") if p.name in (".mcp.json", "mcp.json") and ".git" not in p.parts]:
            try:
                data = json.loads(c.read_text(errors="replace"))
            except json.JSONDecodeError:
                continue
            servers = (data.get("mcpServers") or data.get("servers") or {}) if isinstance(data, dict) else {}
            sd = servers.get(name)
            if not isinstance(sd, dict):
                continue
            url = str(sd.get("url", ""))
            if "http://" in msg:
                h = (urlsplit(url).hostname or "").lower()
                ok = url.startswith("http://") and h not in ("localhost", "127.0.0.1", "::1", "0.0.0.0") and not h.startswith("127.")
                return ("confirmed", "insecure_url") if ok else ("refuted", "")
            if "embeds credentials" in msg:
                u = urlsplit(url)
                return ("confirmed", "userinfo") if (u.username or u.password) else ("refuted", "")
            mm = re.search(r"(command|cwd) '([^']+)' does not exist", msg)
            if mm:
                if (root / mm.group(2)).exists():
                    return "refuted", "exists"
                if (c.parent / mm.group(2)).exists():
                    return "refuted", "exists_relative_to_config"
                return "confirmed", "missing_path"
        return "unverifiable", "server_not_found"
    if rule == "security/credential-file-present":
        import fnmatch as _fn
        m = re.search(r"'([^']+)' matches secret-file pattern '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        fname, pat = m.group(1), m.group(2)
        for p in root.rglob(Path(fname).name):
            if p.is_file() and _fn.fnmatch(p.name, pat):
                if any(x in p.name.lower() for x in ("example", "sample", "template", ".dist")):
                    return "refuted", "example_file"
                return "confirmed", pat
        return "refuted", ""
    if rule == "structural/symlink-escape":
        import os as _os
        m = re.search(r"'([^']+)' is a symlink to '([^']+)'", msg)
        if not m:
            return "unverifiable", ""
        for p in _walk_symlinks(root, Path(m.group(1)).name):
            try:
                Path(_os.path.realpath(p)).relative_to(root.resolve())
                return "refuted", "inside"
            except ValueError:
                return "confirmed", ""
        return "refuted", "not_symlink"
    if rule == "content/orphan-skills":
        comp = f.get("component", "")
        m = re.search(r"Skill '([^']+)'", msg)
        name = m.group(1) if m else comp
        for p in root.rglob("*.md"):
            if p.name == "SKILL.md" and p.parent.name == name:
                continue
            try:
                if re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", p.read_text(errors="replace")):
                    return "refuted", "referenced"
            except OSError:
                pass
        return "confirmed", ""
    return "unverifiable", ""


def main() -> None:
    per_rule = 60
    seed = 255
    if "--per-rule" in sys.argv:
        per_rule = int(sys.argv[sys.argv.index("--per-rule") + 1])
    if "--seed" in sys.argv:
        seed = int(sys.argv[sys.argv.index("--seed") + 1])
    exhaustive = set()
    if "--exhaustive" in sys.argv:
        arg = sys.argv[sys.argv.index("--exhaustive") + 1]
        exhaustive = set(CANDIDATES) - SAMPLED if arg == "all" else set(arg.split(","))
    workers = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 4
    from analyze import read_results  # noqa: E402
    recs = read_results()
    ok = [r for r in recs if r.get("status") == "ok" and r.get("commit")]
    rng = random.Random(seed)
    by_rule: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for r in ok:
        for f in r.get("findings", []):
            if f["rule"] in CANDIDATES:
                by_rule[f["rule"]].append((r, f))
    # Sample repositories per rule, then audit every finding of that rule in the sampled repos.
    plan: dict[str, list[tuple[dict, list]]] = {}
    for rule, pairs in by_rule.items():
        repos = defaultdict(list)
        for r, f in pairs:
            repos[r["full_name"]].append(f)
        names = sorted(repos)
        rng.shuffle(names)
        chosen = []
        count = 0
        for n in names:
            if rule not in exhaustive and count >= per_rule:
                break
            chosen.append((next(r for r, _ in pairs if r["full_name"] == n), repos[n]))
            count += len(repos[n])
        plan[rule] = chosen
    needed = {}
    for rule, items in plan.items():
        for r, fs in items:
            needed.setdefault(r["full_name"], (r, {}))[1][rule] = fs
    print(f"auditing {sum(len(v) for v in by_rule.values())} candidate findings across {len(needed)} repos", file=sys.stderr, flush=True)
    summary: dict = {rule: {"audited": 0, "confirmed": 0, "refuted": 0, "unverifiable": 0, "breakdown": defaultdict(int)} for rule in plan}

    def audit_repo(item):
        fn, (r, rules) = item
        rows = []
        root = clone_pinned(fn, r["commit"])
        if root is None:
            for rule, fs in rules.items():
                for f in fs:
                    rows.append({"repo": fn, "commit": r["commit"], "rule": rule, "component": f.get("component"),
                                 "verdict": "unverifiable", "sub": "clone_failed", "message": f.get("message", "")[:200]})
            return rows
        try:
            for rule, fs in rules.items():
                for f in fs:
                    try:
                        verdict, sub = check(rule, r, f, root)
                    except Exception as e:  # noqa: BLE001
                        verdict, sub = "unverifiable", f"error:{type(e).__name__}"
                    rows.append({"repo": fn, "commit": r["commit"], "rule": rule, "component": f.get("component"),
                                 "verdict": verdict, "sub": sub, "message": f.get("message", "")[:200]})
        finally:
            shutil.rmtree(root.parent, ignore_errors=True)
        return rows

    from concurrent.futures import ThreadPoolExecutor
    out = (DATA / "audit_findings.jsonl").open("w")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for i, rows in enumerate(ex.map(audit_repo, sorted(needed.items())), 1):
            for row in rows:
                s = summary[row["rule"]]
                if row["verdict"] != "unverifiable":
                    s["audited"] += 1
                s[row["verdict"]] += 1
                if row["sub"]:
                    s["breakdown"][row["sub"]] += 1
                out.write(json.dumps(row) + "\n")
            out.flush()
            if i % 20 == 0:
                print(f"  {i}/{len(needed)}", file=sys.stderr, flush=True)
    out.close()
    for s in summary.values():
        s["breakdown"] = dict(s["breakdown"])
    (DATA / "audit_summary.json").write_text(json.dumps(summary, indent=1))
    for rule, s in summary.items():
        n = s["audited"]
        print(f"{rule:36} audited={n:4} confirmed={s['confirmed']:4} ({100*s['confirmed']/n if n else 0:5.1f}%) {s['breakdown']}", file=sys.stderr)


if __name__ == "__main__":
    main()
