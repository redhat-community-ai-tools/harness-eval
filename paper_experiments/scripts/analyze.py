#!/usr/bin/env python3
"""Compute every number reported in the paper from data/results.jsonl.

Outputs:
  data/summary.json          all statistics, machine-readable
  data/manifest.jsonl        one line per scanned repo: url, commit, stratum, per-scope finding counts
  paper/numbers.tex          \\newcommand macros consumed by the paper (no hand-typed numbers)
  paper/tables_generated.tex Table 2 (defects by rule and stratum) and Table 3 (audited precision)
  figures/results.png        headline and per-rule prevalence figure

Strata (assigned from the tool's own component inventory):
  SETUP             two or more component types, or any non-instruction component
  COLLECTION        five or more skills and no component that composes them
Repositories whose only component is an instruction file (CLAUDE.md, AGENTS.md,
.cursorrules, ...) and repositories with no component are outside the corpus.
"""
from __future__ import annotations

import json
import re
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = DATA / "results.jsonl"
SCOPE = DATA / "rule_scope.json"
AUDIT = DATA / "audit_summary.json"
ADJUDICATIONS = DATA / "adjudications.jsonl"
# A rule enters the defect union only when at least this share of its
# adjudicated (repository, rule) pairs was judged a live defect.
CONSEQUENCE_BAR = 0.80
PAPER = ROOT / "paper"
FIG = ROOT / "figures"
PAPER.mkdir(exist_ok=True)
FIG.mkdir(exist_ok=True)

# The tool reports every instruction artifact (CLAUDE.md, AGENTS.md, GEMINI.md,
# .cursorrules, .cursor/rules/*.mdc, copilot-instructions.md) under one
# inventory key. Files it discovers but cannot type are "uncategorized" and are
# excluded from stratification, as the paper states.
INSTRUCTION_TYPES = {"claude_md"}
AGENTS_MD_TOOLS = {"OpenCode", "Codex CLI"}
IGNORED_TYPES = {"uncategorized"}

# Rules whose findings may enter prevalence figures, with display name and
# family: S security exposure, Q configuration that cannot work as written,
# P specification conformance (the Agent Skills spec requires it; Claude Code
# tolerates it), C cross-assistant inconsistency, A advisory split-off
# (never reported).
# A rule is in the reported set only if the audit (audit.py) confirms it at
# the paper's threshold; analyze.py reads the per-finding verdicts from
# audit_findings.jsonl and drops any rule below the bar. For a rule audited
# exhaustively, prevalence counts a repository only when at least one of its
# findings was re-derived AND its sub-class carries the stated consequence.
CANDIDATE_RULES = {
    "mcp/unpinned-package": ("Unpinned MCP package", "S"),
    "cross/overpermissive-grants": ("Arbitrary-execution grant", "S"),
    "security/dangerous-permission-grant": ("Destructive or privileged grant", "S"),
    "hooks/permission-prompt-disabled": ("Permission prompt disabled", "S"),
    "hooks/pre-trust-permissions": ("Lifecycle hook in project settings (advisory)", "A"),
    "hooks/local-settings-committed": ("Local settings committed", "S"),
    "hooks/api-key-helper": ("API key helper in project settings", "S"),
    "hooks/base-url-override": ("Provider base URL in project settings", "S"),
    "hooks/env-credential-override": ("Credential env var in project settings", "S"),
    "hooks/dangerous-command": ("Destructive or remote-exec hook", "S"),
    "content/allowed-tools-auto-approve": ("Skill pre-approves shell", "S"),
    "mcp/auto-approve-risk": ("MCP write tool auto-approved", "S"),
    "mcp/no-plaintext-secrets": ("Literal secret in MCP config", "S"),
    "mcp/endpoint-integrity": ("MCP endpoint integrity", "S"),
    "security/credential-file-present": ("Secret file committed in skill", "S"),
    "structural/symlink-escape": ("Symlink escaping the repository", "S"),
    "frontmatter/format-valid": ("Skill without frontmatter", "P"),
    "frontmatter/description-required": ("Skill description missing", "P"),
    "agent/description-required": ("Agent description missing", "Q"),
    "structural/skill-md-exists": ("Skill directory without SKILL.md", "Q"),
    "hooks/command-script-exists": ("Hook script missing", "Q"),
    "hooks/valid-structure": ("Hook without a command", "Q"),
    "hooks/matcher-matches-no-tool": ("Hook matcher matches no tool", "Q"),
    "hooks/permission-contradiction": ("Permission contradiction", "Q"),
    "mcp/valid-config": ("MCP config structurally invalid", "Q"),
    "mcp/json-duplicate-keys": ("Duplicate key in MCP config", "Q"),
    "hooks/json-duplicate-keys": ("Duplicate key in settings", "Q"),
    "claude-md/include-exists": ("Broken @import in context file", "Q"),
    "command/script-exists": ("Command mentions absent file (advisory)", "A"),
    "command/references-nonexistent-skill": ("Command invokes absent skill", "Q"),
    "agent/referenced-skills-exist": ("Agent declares absent skill", "Q"),
    "cross/multi-assistant-drift": ("Context files diverge across assistants", "C"),
    "mcp/cross-assistant-divergence": ("MCP server diverges across assistants", "C"),
    # advisory split-offs, computed for the text, never reported as defects
    "cross/grant-network-tool": ("Network-tool grant (advisory)", "A"),
    "cross/grant-indirect-exec": ("Indirect-execution grant (advisory)", "A"),
    "cross/grant-bare-tool": ("Bare tool grant (advisory)", "A"),
    "hooks/auto-accept-edits": ("Auto-accept edits committed (advisory)", "A"),
    "hooks/all-project-mcp": ("Project MCP servers pre-approved (advisory)", "A"),
    "hooks/pre-trust-allow": ("Allow list in project settings (advisory)", "A"),
    "content/allowed-tools-scoped": ("Scoped tool pre-approval (advisory)", "A"),
    "frontmatter/name-missing": ("Skill name field missing (advisory)", "A"),
}
# Audit sub-classes whose predicate holds but whose consequence is not the
# one the rule states. They count toward precision (the check re-derived the
# condition) and never toward prevalence.
NON_DEFECT_SUBS = {
    "frontmatter/description-required": {"no_frontmatter_duplicate"},
    # Claude Code defaults `name` to the directory; the Agent Skills spec requires it. Tolerated deviation.
    # A root-level agents/ directory is not evidence of a subagent definition.
    "agent/description-required": {"no_frontmatter_root_agents_dir", "doc_like_file"},
    # A reference into another installed plugin is not this repository's to satisfy.
    "agent/referenced-skills-exist": {"external_plugin"},
    # Plugin-style flat maps are valid; an empty url is a connector placeholder in official bundles.
    "mcp/valid-config": {"flat_server_map", "empty_url_placeholder"},
    # a skill in an archived directory is loaded by no client; a BOM before the block is a parser question
    "frontmatter/format-valid": {"missing_name", "archived_location", "bom_before_frontmatter"},
    # planted test corpora and shipped templates are not the repository's own live configuration;
    # an npx package present in the project's package.json resolves from node_modules
    "mcp/unpinned-package": {"fixture_path", "template_path", "project_local_dependency", "no_install", "local_runner"},
    # an http:// endpoint on a compose/LAN/placeholder host, a fixture, or a build output reported as missing
    "mcp/endpoint-integrity": {"fixture_path", "internal_hostname", "build_output"},
    # a dotfiles repository keeps user-scoped settings in git; not a project setting
    "hooks/permission-prompt-disabled": {"dotfiles_repo"},
    # $HOME/... hook paths point at an install location the repository does not carry.
    "hooks/command-script-exists": {"outside_repo_variable"},
    # CLAUDE.local.md-style imports are per-machine by design; fixture trees are deliberately broken.
    "claude-md/include-exists": {"local_import", "fixture_path"},
    "hooks/local-settings-committed": {"no_grants"},
    "mcp/auto-approve-risk": {"empty_list"},
    "hooks/env-credential-override": {"passthrough_or_empty", "placeholder"},
    "hooks/base-url-override": {"env_key_reference"},
    "content/allowed-tools-auto-approve": {"bash_scoped", "write_tool"},
    "hooks/dangerous-command": {"rm_rf_path"},
    "mcp/no-plaintext-secrets": {"high_entropy_value"},
    "structural/skill-md-exists": {"support_files_only", "empty_dir"},
}

# Rules whose predicate the audit re-derives but whose consequence it cannot
# decide from bytes (whether a difference between two files is intended;
# whether a file a reference names exists outside the tree). Every re-derived
# pair of these rules is a disagreement on consequence and goes to adjudication.
INTENT_RULES = {"cross/multi-assistant-drift", "mcp/cross-assistant-divergence", "claude-md/include-exists",
                "agent/referenced-skills-exist", "mcp/valid-config"}

# Illustrative, anonymized example per rule for the examples table (LaTeX).
EXAMPLES = {
    "frontmatter/format-valid": r"no \texttt{---} block; the spec requires one, Claude Code falls back to the body",
    "frontmatter/description-required": r"frontmatter without \texttt{description}; the spec requires it, Claude Code uses the first paragraph",
    "security/dangerous-permission-grant": r"\texttt{Bash(sudo:*)}, \texttt{Bash(kubectl delete:*)} in \texttt{permissions.allow}",
    "hooks/pre-trust-permissions": r"\texttt{SessionStart} hook in project settings; runs when the repository is opened",
    "hooks/api-key-helper": r"\texttt{apiKeyHelper} in project settings; the repository resolves the API key",
    "hooks/base-url-override": r"\texttt{ANTHROPIC\_BASE\_URL} in project settings; API traffic redirected",
    "hooks/env-credential-override": r"\texttt{env: \{GITHUB\_TOKEN: ghp\_\ldots\}} in project settings",
    "hooks/dangerous-command": r"hook command \texttt{curl \ldots | sh} or \texttt{git reset --hard}",
    "content/allowed-tools-auto-approve": r"skill \texttt{allowed-tools: [Bash]}; shell runs without a prompt while active",
    "mcp/auto-approve-risk": r"\texttt{autoApprove: [write\_file]} on an MCP server",
    "mcp/no-plaintext-secrets": r"\texttt{env: \{API\_KEY: sk-\ldots\}} in \texttt{.mcp.json}",
    "structural/skill-md-exists": r"\texttt{skills/foo/skill.md} or \texttt{skills/foo/README.md}; no \texttt{SKILL.md}",
    "hooks/valid-structure": r"hook entry with no \texttt{command}; the runtime ignores it",
    "hooks/matcher-matches-no-tool": r"\texttt{matcher: bash} on \texttt{PreToolUse}; tool names are case-sensitive",
    "mcp/valid-config": r"server with neither \texttt{command} nor \texttt{url}",
    "command/script-exists": r"command runs \texttt{scripts/x.py}; not committed",
    "command/references-nonexistent-skill": r"command says \texttt{/deploy}; no such skill or command",
    "agent/referenced-skills-exist": r"agent \texttt{skills: [x]}; no \texttt{x/SKILL.md}",
    "content/hardcoded-machine-path": r"\texttt{/Users/evan/projects/\ldots} or \texttt{C:\textbackslash Users\textbackslash\ldots} in a skill file",
    "mcp/unpinned-package": r"\texttt{npx -y @modelcontextprotocol/server-filesystem}, no version",
    "content/circular-references": r"skill A: \texttt{invoke /b}; skill B: \texttt{invoke /a}",
    "cross/overpermissive-grants": r"\texttt{Bash(awk:*)}, \texttt{Bash(python:*)}, \texttt{Bash(find:*)} in \texttt{permissions.allow}",
    "cross/multi-assistant-drift": r"\texttt{CLAUDE.md} and \texttt{AGENTS.md} share most sections; one was edited",
    "content/mcp-skill-alignment": r"server declared in \texttt{.mcp.json}; no component names it",
    "agent/description-required": r"subagent file with no \texttt{description}; it can never be delegated to",
    "hooks/permission-contradiction": r"\texttt{allow: Bash(git commit:*)} with \texttt{deny: Bash(git:*)}",
    "hooks/permission-prompt-disabled": r"\texttt{defaultMode: bypassPermissions} committed in project settings (honoured before Claude Code v2.1.257)",
    "hooks/local-settings-committed": r"\texttt{.claude/settings.local.json} in the tree",
    "mcp/cross-assistant-divergence": r"same server pinned in \texttt{.mcp.json}, unpinned in \texttt{.cursor/mcp.json}",
    "mcp/json-duplicate-keys": r"two \texttt{github} servers in one \texttt{.mcp.json}; the first is silently dropped",
    "hooks/json-duplicate-keys": r"two \texttt{permissions} blocks in \texttt{settings.json}",
    "claude-md/include-exists": r"\texttt{@docs/standards.md} in \texttt{CLAUDE.md}; no such file",
    "hooks/command-script-exists": r"hook runs \texttt{\$CLAUDE\_PROJECT\_DIR/.ai/start.py}; not committed",
    "mcp/endpoint-integrity": r"\texttt{url: http://host/sse} or \texttt{https://user:token@host}",
    "security/credential-file-present": r"\texttt{.env} or \texttt{*.pem} committed inside a skill",
    "structural/symlink-escape": r"\texttt{scripts/run.sh -> /tmp/\ldots}",
}
REFERENCE_RULE = "content/broken-references"
WITHDRAWN = {"content/orphan-skills", "security/cross-component-flow"}


def read_results(path: Path = RESULTS) -> list:
    """The scan records. The repository ships results.jsonl.gz (the plain file
    exceeds GitHub's size guidance); a plain results.jsonl beside it, written by
    scan.py, takes precedence when present."""
    import gzip
    if path.exists():
        text = path.read_text()
    elif path.with_suffix(".jsonl.gz").exists():
        text = gzip.open(path.with_suffix(".jsonl.gz"), "rt", encoding="utf-8").read()
    else:
        return []
    return [json.loads(l) for l in text.splitlines() if l.strip()]


def corpus(recs: list) -> list:
    """The analyzed corpus: repositories scanned ok with at least one harness
    component, one record per distinct pinned commit. Two names that resolve to
    the same commit are a rename or a mirror of one repository; the record
    with the higher star count (then the alphabetically first name) is kept."""
    ok = [r for r in recs if r.get("status") == "ok" and r.get("commit") and stratum(r) in ("SETUP", "COLLECTION")]
    best: dict = {}
    seen_forks: dict = {}
    seen_copies: dict = {}
    desc_file = DATA / "repo_descriptions.jsonl"
    descriptions = {}
    if desc_file.exists():
        for line in desc_file.read_text().splitlines():
            if line.strip():
                d = json.loads(line)
                descriptions[d["repo"]] = d["description"].strip()
    for r in sorted(ok, key=lambda r: (-(r.get("stars") or 0), -len(r.get("channels") or []), r["full_name"].lower())):
        inv = json.dumps(r["inventory"].get("component_types", {}), sort_keys=True)
        owner, name = r["full_name"].split("/", 1)
        # A fork carries the same repository name and the same component
        # inventory as its source; the higher-starred copy is kept.
        fork_key = (name.lower(), inv)
        if fork_key in seen_forks:
            continue
        seen_forks[fork_key] = r["full_name"]
        # A template-derived copy under another owner carries the template's
        # inventory and its README verbatim (a site generated from a starter).
        d = descriptions.get(r["full_name"], "")
        if len(d) >= 25:
            copy_key = (inv, d)
            if copy_key in seen_copies and seen_copies[copy_key] != owner.lower():
                continue
            seen_copies.setdefault(copy_key, owner.lower())
        best.setdefault(r["commit"], r)
    return sorted(best.values(), key=lambda r: r["full_name"].lower())


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return 100 * p, 100 * max(0.0, c - h), 100 * min(1.0, c + h)


def stratum(rec: dict) -> str:
    inv = rec.get("inventory", {})
    types = {k: v for k, v in inv.get("component_types", {}).items() if v and k not in IGNORED_TYPES}
    if not types:
        return "EMPTY"
    skills = types.get("skill", 0)
    non_instruction = set(types) - INSTRUCTION_TYPES
    # A collection is a published set of skills with nothing that composes them;
    # a context file alone does not compose, since collections carry one for contributors.
    if skills >= 5 and non_instruction <= {"skill"}:
        return "COLLECTION"
    # A setup assembles at least two component types (a context file and
    # skills, skills and hooks, an MCP declaration and settings, ...).
    if len(types) >= 2:
        return "SETUP"
    if not non_instruction:
        return "INSTRUCTION_ONLY"
    return "SPARSE"   # one component type, fewer than five skills: a file or a few files, not a configuration


_SEC = {"sh", "bash", "zsh", "dash", "fish", "env", "eval", "exec", "xargs", "sudo", "doas", "python", "python3",
        "perl", "ruby", "node", "bun", "deno", "php", "lua", "awk", "gawk", "mawk", "nawk", "sed", "find",
        "npx", "bunx", "uvx", "pipx"}


def remap(f: dict) -> None:
    """Split rules whose findings mix classes with different consequences, so
    that only the security class carries a headline. Applied identically to
    scan findings and to audit rows (both carry the rule's message)."""
    msg = f.get("message", "")
    if f["rule"] == "cross/overpermissive-grants":
        m = re.search(r"wildcard grant on '([^']+)'", msg)
        cmd = m.group(1).lower() if m else None
        if "unrestricted" in msg or re.search(r"entry 'Bash'", msg):
            f["grant_class"] = "unrestricted"
        elif cmd in _SEC:
            f["grant_class"] = "arbitrary-exec"
        elif cmd in ("curl", "wget"):
            f["rule"] = "cross/grant-network-tool"
        elif cmd:
            f["rule"] = "cross/grant-indirect-exec"
        else:
            f["rule"] = "cross/grant-bare-tool"
    elif f["rule"] == "hooks/permission-prompt-disabled" and "acceptEdits" in msg:
        f["rule"] = "hooks/auto-accept-edits"
    elif f["rule"] == "hooks/permission-prompt-disabled" and "enableAllProjectMcpServers" in msg:
        f["rule"] = "hooks/all-project-mcp"             # server approval only; tool prompts unaffected
    elif f["rule"] == "hooks/pre-trust-permissions" and "permissions.allow" in msg:
        f["rule"] = "hooks/pre-trust-allow"
    elif f["rule"] == "content/allowed-tools-auto-approve" and "scoped shell command or file writes" in msg:
        f["rule"] = "content/allowed-tools-scoped"     # the tool's own medium class: not arbitrary execution
    elif f["rule"] == "frontmatter/format-valid" and re.search(r"Field 'name' is missing", msg):
        f["rule"] = "frontmatter/name-missing"          # block present, name absent: clients default it


def load_adjudications() -> dict:
    """Verdict per (repo, rule) pair from adjudicate.py (LLM adjudication of
    the evidence for every pair where the tool's finding needs a consequence
    judgement). Missing file: no adjudication, sub-classes decide alone."""
    if not ADJUDICATIONS.exists():
        return {}
    out = {}
    for line in ADJUDICATIONS.read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            out[(row["repo"], row["rule"])] = row
    return out


def audit_pairs(repos: set | None = None) -> tuple[dict, dict, set]:
    """Read the per-finding audit rows (after remap). Returns
    (summary_by_rule, pair_state, disagreements) where pair_state maps
    (repo, rule) -> "agreed" (every finding re-derived with the stated
    consequence, and the consequence decidable) or "disagreement" (at least one
    finding refuted or unverifiable, a sub-class whose consequence does not
    hold, or a rule whose consequence the audit cannot decide)."""
    af = DATA / "audit_findings.jsonl"
    summary: dict = {}
    agreed: set = set()
    disagreed: set = set()
    seen: set = set()
    if not af.exists():
        return summary, {}, set()
    for line in af.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if repos is not None and row["repo"] not in repos:
            continue   # audited, but outside the analyzed corpus (a sparse, duplicate, or instruction-only repository)
        remap(row)
        rule = row["rule"]
        s = summary.setdefault(rule, {"audited": 0, "confirmed": 0, "refuted": 0, "unverifiable": 0,
                                      "consequential": 0, "breakdown": Counter(), "repos": set()})
        s["repos"].add(row["repo"])
        if row["verdict"] != "unverifiable":
            s["audited"] += 1
        s[row["verdict"]] += 1
        if row.get("sub"):
            s["breakdown"][row["sub"]] += 1
        key = (row["repo"], rule)
        consequential = row["verdict"] == "confirmed" and row.get("sub") not in NON_DEFECT_SUBS.get(rule, set())
        if consequential:
            s["consequential"] += 1
        seen.add(key)
        if row["verdict"] != "confirmed" or rule in INTENT_RULES:
            disagreed.add(key)          # a finding the audit did not re-derive, or a consequence it cannot decide
        elif consequential:
            agreed.add(key)             # at least one finding re-derived with the stated consequence
    for s in summary.values():
        s["breakdown"] = dict(s["breakdown"])
        s["audited_repos"] = len(s.pop("repos"))
    # A pair is agreed when the audit re-derived every finding and at least one
    # carries the stated consequence; a pair whose findings all fall in a
    # non-defect sub-class is a disagreement on consequence.
    state = {}
    for k in seen:
        state[k] = "disagreement" if (k in disagreed or k not in agreed) else "agreed"
    return summary, state, {k for k, v in state.items() if v == "disagreement"}


def load_audit(repos: set | None = None) -> tuple[dict, dict]:
    """Per-rule validation summary and the set of (repo, rule) pairs that count
    as defects: agreed pairs, plus disagreements the adjudicator judged a
    defect. A disagreement with no adjudication does not count."""
    summary, state, disagreed = audit_pairs(repos)
    adj = load_adjudications()
    pairs: set = set()
    for key, st in state.items():
        rule = key[1]
        a = summary[rule]
        a.setdefault("pairs", 0); a["pairs"] += 1
        if st == "agreed":
            a.setdefault("agreed_pairs", 0); a["agreed_pairs"] += 1
            pairs.add(key)
            continue
        a.setdefault("disagreements", 0); a["disagreements"] += 1
        row = adj.get(key)
        if row is None:
            a.setdefault("unadjudicated", 0); a["unadjudicated"] += 1
            continue
        a.setdefault("adjudicated", Counter())[row["verdict"]] += 1
        a.setdefault("adjudication_reasons", Counter())[row.get("reason", "other")] += 1
        if row["verdict"] == "defect":
            pairs.add(key)
    for a in summary.values():
        c = a.get("adjudicated", Counter())
        a["adjudicated"] = dict(c)
        a["adjudication_reasons"] = dict(a.get("adjudication_reasons", Counter()))
        a["adjudicated_n"] = c.get("defect", 0) + c.get("not_defect", 0) + c.get("uncertain", 0)
        a["adjudicated_defect"] = c.get("defect", 0)
        a.setdefault("pairs", 0); a.setdefault("agreed_pairs", 0); a.setdefault("disagreements", 0); a.setdefault("unadjudicated", 0)
        a["defect_pairs"] = a["agreed_pairs"] + a["adjudicated_defect"]
        # Consequence bar: share of all re-derived pairs that end as defects.
        a["defect_share"] = a["defect_pairs"] / a["pairs"] if a["pairs"] else None
    return summary, pairs


def main() -> None:
    scope = json.loads(SCOPE.read_text())
    recs = read_results()
    for r in recs:
        for f in r.get("findings", []):
            remap(f)
    audit, confirmed_pairs = load_audit({r["full_name"] for r in corpus(recs)})
    # A rule is exhaustive when every repository that fired it was audited.
    fired_repos = defaultdict(set)
    for r in corpus(recs):
        for f in r.get("findings", []):
            fired_repos[f["rule"]].add(r["full_name"])
    # (the audit covers every ok repository, duplicates included, so the
    # exhaustiveness check counts them all)
    for rid, a in audit.items():
        a["exhaustive"] = a["audited_repos"] >= len(fired_repos.get(rid, set())) and rid in fired_repos
    ok = corpus(recs)
    status = Counter(r.get("status") for r in recs)
    n_dupes = sum(1 for r in recs if r.get("status") == "ok" and r.get("commit") and stratum(r) in ("SETUP", "COLLECTION")) - len(ok)

    reported = {}     # every rule that meets the precision bar (listed in tables)
    gating = {}       # >= 50 audited: carries headline figures
    provisional = {}  # 13-49 audited, zero false positives: listed, kept out of every headline union
    observation = {}  # re-derived at the bar, but adjudication found the stated consequence in < CONSEQUENCE_BAR of pairs
    for rid, (name, fam) in CANDIDATE_RULES.items():
        a = audit.get(rid)
        if a is None or fam == "A":
            continue
        n, k = a["audited"], a["confirmed"]
        share = a.get("defect_share")
        if share is not None and share < CONSEQUENCE_BAR and n >= 13 and k / n >= 0.97:
            observation[rid] = (name, fam)
            continue
        if n >= 50 and k / n >= 0.97:
            reported[rid] = (name, fam); gating[rid] = (name, fam)
        elif n >= 13 and k == n:
            reported[rid] = (name, fam); provisional[rid] = (name, fam)
    # Headline union: every gating rule (all three families state a defect).
    headline = dict(gating)

    strata = defaultdict(list)
    for r in ok:
        r["stratum"] = stratum(r)
        strata[r["stratum"]].append(r)

    def has(r: dict, rid: str) -> bool:
        """A repository carries a rule's defect when the rule fired and, for a
        rule audited exhaustively, at least one finding was re-derived with the
        stated consequence. Raw firing is used only for rules without an
        exhaustive audit (never in a headline)."""
        if not any(f["rule"] == rid for f in r.get("findings", [])):
            return False
        if audit.get(rid, {}).get("exhaustive"):
            return (r["full_name"], rid) in confirmed_pairs
        return True

    def rate(rs: list, pred) -> tuple[int, int, tuple[float, float, float]]:
        k = sum(1 for r in rs if pred(r))
        return k, len(rs), wilson(k, len(rs))

    real_rules = set(scope)   # the registry; pseudo-rules added below are analysis splits, not rules
    beyond = {rid for rid, v in scope.items() if v["scope"] != "FILE"}
    for pseudo, base in (("hooks/pre-trust-allow", "hooks/pre-trust-permissions"), ("hooks/auto-accept-edits", "hooks/permission-prompt-disabled"), ("hooks/all-project-mcp", "hooks/permission-prompt-disabled"),
                         ("cross/grant-network-tool", "cross/overpermissive-grants"), ("cross/grant-indirect-exec", "cross/overpermissive-grants"),
                         ("cross/grant-bare-tool", "cross/overpermissive-grants"),
                         ("content/allowed-tools-scoped", "content/allowed-tools-auto-approve"), ("frontmatter/name-missing", "frontmatter/format-valid")):
        scope.setdefault(pseudo, dict(scope[base]))
    security_rules = {rid for rid, v in scope.items() if v["security"]}
    summary: dict = {"n_scanned": len(recs), "status": dict(status), "n_ok": len(ok), "n_duplicates": n_dupes,
                     "n_empty": sum(1 for r in recs if r.get("status") == "ok" and stratum(r) == "EMPTY"),
                     "n_instruction_only": sum(1 for r in recs if r.get("status") == "ok" and stratum(r) == "INSTRUCTION_ONLY"),
                     "n_sparse": sum(1 for r in recs if r.get("status") == "ok" and stratum(r) == "SPARSE"),
                     "strata": {s: len(v) for s, v in strata.items()},
                     "reported_rules": {rid: {"name": n, "family": f, "tier": ("gating" if rid in gating else "provisional")} for rid, (n, f) in reported.items()},
                     "gating_rules": list(gating), "provisional_rules": list(provisional), "headline_rules": list(headline),
                     "observation_rules": {rid: {"name": n, "family": f} for rid, (n, f) in observation.items()},
                     "consequence_bar": CONSEQUENCE_BAR,
                     "rule_scope_counts": dict(Counter(v["scope"] for rid, v in scope.items() if rid in real_rules)),
                     "rules_total": len(real_rules), "rules_beyond_file": len(beyond),
                     "rules_hand_corrected": sum(1 for rid, v in scope.items() if rid in real_rules and v["corrected"]),
                     "candidate_rules": [rid for rid, (n, f) in CANDIDATE_RULES.items() if f != "A"],
                     "per_stratum": {}}

    for s, rs in strata.items():
        d: dict = {"n": len(rs)}
        d["any_raw"] = rate(rs, lambda r: bool(r.get("findings")))
        d["any_error_raw"] = rate(rs, lambda r: any(f["severity"] == "error" for f in r.get("findings", [])))
        d["any_security_raw"] = rate(rs, lambda r: any(f["rule"] in security_rules for f in r.get("findings", [])))
        d["any_confirmed"] = rate(rs, lambda r: any(has(r, rid) for rid in headline))
        d["any_confirmed_defect"] = rate(rs, lambda r: any(has(r, rid) for rid, (n, f) in headline.items() if f != "P"))
        d["any_reported"] = rate(rs, lambda r: any(has(r, rid) for rid in reported))
        d["confirmed_beyond_file"] = rate(rs, lambda r: any(has(r, rid) for rid in headline if rid in beyond))
        d["confirmed_security"] = rate(rs, lambda r: any(has(r, rid) for rid, (n, f) in headline.items() if f == "S"))
        d["confirmed_security_incl_provisional"] = rate(rs, lambda r: any(has(r, rid) for rid, (n, f) in reported.items() if f == "S"))
        d["tolerated_only"] = rate(rs, lambda r: False)
        d["reference_rule"] = rate(rs, lambda r: has(r, REFERENCE_RULE))
        d["integrity_any"] = rate(rs, lambda r: any(has(r, rid) for rid, (n, f) in headline.items() if f == "Q"))
        d["spec_any"] = rate(rs, lambda r: any(has(r, rid) for rid, (n, f) in headline.items() if f == "P"))
        d["confirmed_cross"] = rate(rs, lambda r: any(has(r, rid) for rid, (n, f) in headline.items() if f == "C"))
        d["any_gate_raw"] = rate(rs, lambda r: any(f["rule"] in CANDIDATE_RULES and CANDIDATE_RULES[f["rule"]][1] != "A" for f in r.get("findings", [])))
        d["per_rule"] = {rid: rate(rs, lambda r, rid=rid: has(r, rid)) for rid in CANDIDATE_RULES}
        d["per_rule_raw"] = {rid: rate(rs, lambda r, rid=rid: any(f["rule"] == rid for f in r.get("findings", []))) for rid in CANDIDATE_RULES}
        # AGENTS.md is a cross-tool file; the discoverers attribute it to OpenCode and
        # Codex CLI. Multi-assistant counts only tools detected from a tool-specific file.
        d["multi_assistant"] = rate(rs, lambda r: len(set(r.get("inventory", {}).get("detected_tools", [])) - AGENTS_MD_TOOLS) > 1)
        comps = [r["inventory"]["component_count"] for r in rs if r.get("inventory")]
        toks = [r["inventory"]["budget"]["total_tokens"] or 0 for r in rs if r.get("inventory")]
        always = [r["inventory"]["budget"]["always_loaded"] or 0 for r in rs if r.get("inventory")]
        d["median_components"] = statistics.median(comps) if comps else 0
        d["max_components"] = max(comps) if comps else 0
        d["median_tokens"] = statistics.median(toks) if toks else 0
        d["max_tokens"] = max(toks) if toks else 0
        d["median_always_loaded"] = statistics.median(always) if always else 0
        sc = Counter()
        for r in rs:
            for f in r.get("findings", []):
                sc[scope.get(f["rule"], {}).get("scope", "FILE")] += 1
        d["findings_by_scope"] = dict(sc)
        tools = Counter(t for r in rs for t in r.get("inventory", {}).get("detected_tools", []))
        d["tools"] = dict(tools.most_common())
        durs = [r["duration_s"] for r in rs if r.get("duration_s")]
        d["median_duration_s"] = statistics.median(durs) if durs else 0
        d["p95_duration_s"] = sorted(durs)[int(0.95 * (len(durs) - 1))] if durs else 0
        summary["per_stratum"][s] = d

    # Discovery-channel check on setups: topic-only vs readme-only vs curated.
    setups = strata.get("SETUP", [])
    def chan(r, prefix):
        return any(c.startswith(prefix) for c in r.get("channels", []))
    summary["channel_check"] = {
        "topic_only": rate([r for r in setups if chan(r, "topic:") and not chan(r, "readme:") and not chan(r, "curated:")],
                           lambda r: any(has(r, rid) for rid in headline)),
        "readme_only": rate([r for r in setups if chan(r, "readme:") and not chan(r, "topic:") and not chan(r, "curated:")],
                            lambda r: any(has(r, rid) for rid in headline)),
        "curated": rate([r for r in setups if chan(r, "curated:")], lambda r: any(has(r, rid) for rid in headline)),
        "curated_all": rate([r for r in ok if chan(r, "curated:")], lambda r: any(has(r, rid) for rid in headline)),
        "curated_n_by_stratum": dict(Counter(r["stratum"] for r in ok if chan(r, "curated:"))),
        "agents": rate([r for r in ok if chan(r, "agents:")], lambda r: any(has(r, rid) for rid in headline)),
        "agents_raw": rate([r for r in ok if chan(r, "agents:")], lambda r: bool(r.get("findings"))),
        "agents_with_components": sum(1 for r in ok if chan(r, "agents:") and r["stratum"] != "EMPTY"),
    }
    # Assembled sub-stratum: setups with two or more distinct component types (excluding uncategorized).
    assembled = [r for r in setups if len({k for k, v in r["inventory"]["component_types"].items() if v and k not in IGNORED_TYPES}) >= 2]
    summary["assembled"] = {"n": len(assembled),
                            "any_confirmed": rate(assembled, lambda r: any(has(r, rid) for rid in headline)),
                            "confirmed_security": rate(assembled, lambda r: any(has(r, rid) for rid, (n, f) in headline.items() if f == "S")),
                            "confirmed_beyond_file": rate(assembled, lambda r: any(has(r, rid) for rid in headline if rid in beyond))}
    gm = Counter()
    for r in setups:
        for cls in {f.get("grant_class") for f in r["findings"] if f["rule"] == "cross/overpermissive-grants" and f.get("grant_class")}:
            gm[cls] += 1
    mech = Counter()
    for r in setups:
        for c in {m.group(1).lower() for f in r["findings"] if f["rule"] == "cross/overpermissive-grants"
                  for m in [re.search(r"wildcard grant on '([^']+)'", f["message"])] if m}:
            fam = ("interpreter" if c in ("python", "python3", "perl", "ruby", "node", "bun", "deno", "php", "lua") else
                   "shell" if c in ("sh", "bash", "zsh", "dash", "fish", "env", "eval", "exec", "sudo", "doas", "xargs") else
                   "package-runner" if c in ("npx", "bunx", "uvx", "pipx") else "shell-escape-tool")
            mech[fam] += 1
    summary["grant_mechanisms"] = {"unrestricted": gm.get("unrestricted", 0), **dict(mech)}
    summary["grant_setups"] = sum(1 for r in setups if any(f["rule"] == "cross/overpermissive-grants" for f in r["findings"]))
    summary["grant_mechanism_sum"] = sum(summary["grant_mechanisms"].values())
    tools_all = Counter(t for r in ok for t in r.get("inventory", {}).get("detected_tools", []))
    summary["tool_ranking"] = tools_all.most_common(8)
    flow = [r for r in ok if any(f["rule"] == "security/cross-component-flow" and "exfiltration" in f["message"].lower()
                                  for f in r.get("findings", []))]
    summary["flow_repos"] = len(flow)
    summary["flow_repo_names"] = [r["full_name"] for r in flow]
    summary["audit"] = audit
    af = DATA / "audit_findings.jsonl"
    _corpus_names = {r["full_name"] for r in ok}
    _rows = [json.loads(l) for l in af.read_text().splitlines() if l.strip()] if af.exists() else []
    summary["audit_repos"] = len({row["repo"] for row in _rows if row["repo"] in _corpus_names})
    summary["audit_findings_total"] = sum(1 for row in _rows if row["repo"] in _corpus_names)

    (DATA / "summary.json").write_text(json.dumps(summary, indent=1, default=float))
    with (DATA / "manifest.jsonl").open("w") as f:
        for r in ok:
            sc = Counter(scope.get(x["rule"], {}).get("scope", "FILE") for x in r.get("findings", []))
            rules = sorted({x["rule"] for x in r.get("findings", [])})
            f.write(json.dumps({"url": r["url"], "commit": r.get("commit"), "status": r.get("status"),
                                "stratum": r.get("stratum"), "channels": r.get("channels"),
                                "findings_by_scope": dict(sc), "rules_fired": rules}) + "\n")
    _write_tex(summary, scope)
    _write_fig(summary)
    print(json.dumps({k: summary[k] for k in ("n_scanned", "status", "n_ok", "strata")}), file=sys.stderr)
    for s, d in summary["per_stratum"].items():
        print(f"{s}: n={d['n']} any_confirmed={d['any_confirmed'][2][0]:.1f}% beyond={d['confirmed_beyond_file'][2][0]:.1f}%"
              f" raw={d['any_raw'][2][0]:.1f}% ref={d['reference_rule'][2][0]:.1f}%", file=sys.stderr)


def _m(name: str, val) -> str:
    if isinstance(val, float):
        val = f"{val:.1f}"
    return f"\\newcommand{{\\{name}}}{{{val}}}\n"


def _num(name: str, val) -> str:
    return _m(name, f"{val:,}" if isinstance(val, int) else val)


def _write_tex(s: dict, scope: dict) -> None:
    out = ["% Generated by scripts/analyze.py. Do not edit by hand.\n"]
    out.append(_num("nScanned", s["n_scanned"]))
    out.append(_num("nOk", s["n_ok"]))
    # The candidate funnel comes from the full candidate scan (data/candidate_funnel.json);
    # the shipped results carry the corpus only, so the counts are not recomputable from them.
    funnel_file = DATA / "candidate_funnel.json"
    funnel = json.loads(funnel_file.read_text()) if funnel_file.exists() else {}
    out.append(_num("nNoComponent", funnel.get("n_no_component", s["n_empty"])))
    out.append(_num("nInstructionOnly", funnel.get("n_instruction_only", s["n_instruction_only"])))
    out.append(_num("nSparse", funnel.get("n_sparse", s["n_sparse"])))
    out.append(_num("nDuplicates", funnel.get("n_duplicates", s["n_duplicates"])))
    out.append(_num("nCandidates", funnel.get("n_candidates", s["n_scanned"])))
    out.append(_num("nFailedScans", funnel.get("n_failed", 0)))
    out.append(_num("nRescanDrop", max(0, funnel.get("n_setup_or_collection", s["n_ok"]) - funnel.get("n_duplicates", 0) - s["n_ok"])))
    out.append(_num("nRules", s["rules_total"]))
    out.append(_num("nRulesBeyond", s["rules_beyond_file"]))
    out.append(_m("pctRulesBeyond", 100 * s["rules_beyond_file"] / s["rules_total"]))
    out.append(_num("nRulesCorrected", s["rules_hand_corrected"]))
    for k, v in s["rule_scope_counts"].items():
        out.append(_num("nRules" + k.replace("_", ""), v))
    out.append(_num("nReportedRules", len(s["reported_rules"])))
    out.append(_num("nGrantSetups", s.get("grant_setups", 0)))
    out.append(_num("GrantMechSum", s.get("grant_mechanism_sum", 0)))
    for rid in ("hooks/permission-prompt-disabled",):
        key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
        out.append(_num("n" + key + "Findings", s["audit"].get(rid, {}).get("audited", 0)))
    measured = [rid for rid in s["candidate_rules"] if rid in scope]
    out.append(_num("nMeasuredRules", len(measured)))
    for fam, L in (("S", "Sec"), ("Q", "Int"), ("P", "Spec"), ("C", "Cross")):
        out.append(_num("nMeasured" + L, sum(1 for rid in measured if CANDIDATE_RULES[rid][1] == fam)))
    msc = Counter(scope[rid]["scope"] for rid in measured)
    for k in ("FILE", "FILE_FS", "PAIRWISE", "SETUP"):
        out.append(_num("meas" + k.replace("_", "") + "Count", msc.get(k, 0)))
    out.append(_num("nGatingRules", len(s["gating_rules"])))
    out.append(_num("nHeadlineRules", len(s["headline_rules"])))
    out.append(_num("nProvisionalRules", len(s["provisional_rules"])))
    out.append(_num("nObservationRules", len(s["observation_rules"])))
    out.append(_num("ConsequenceBar", round(100 * s["consequence_bar"])))
    aud_eligible = {rid for rid in s["reported_rules"]} | set(s["observation_rules"])
    adj_n = sum(s["audit"][rid].get("adjudicated_n", 0) for rid in aud_eligible)
    adj_k = sum(s["audit"][rid].get("adjudicated_defect", 0) for rid in aud_eligible)
    out.append(_num("nAdjudicated", adj_n)); out.append(_num("nAdjudicatedDefect", adj_k))
    out.append(_num("nAdjudicatedNot", adj_n - adj_k))
    out.append(_m("pctAdjudicatedDefect", 100 * adj_k / max(1, adj_n)))
    out.append(_num("nPairs", sum(s["audit"][rid].get("pairs", 0) for rid in aud_eligible)))
    out.append(_num("nAgreedPairs", sum(s["audit"][rid].get("agreed_pairs", 0) for rid in aud_eligible)))
    out.append(_num("nDisagreements", sum(s["audit"][rid].get("disagreements", 0) for rid in aud_eligible)))
    out.append(_num("nDefectPairs", sum(s["audit"][rid].get("defect_pairs", 0) for rid in aud_eligible)))
    letters = {"SETUP": "Setup", "COLLECTION": "Coll"}
    for st in letters:
        if st not in s["per_stratum"]:
            L = letters[st]
            out.append(_num("n" + L, 0))
            for short in ("AnyRaw", "ErrRaw", "SecRaw", "Confirmed", "AnyReported", "Beyond", "ConfSec", "ConfSecProv", "ToleratedOnly", "RefRule", "Multi", "Integrity", "Spec", "Cross", "GateRaw", "ConfirmedDefect"):
                for m in ("", "Lo", "Hi"):
                    out.append(_m(L + short + m, 0.0))
                out.append(_num(L + short + "K", 0))
            for rid in CANDIDATE_RULES:
                key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
                for m in ("", "Lo", "Hi"):
                    out.append(_m(L + key + m, 0.0))
    for st, d in s["per_stratum"].items():
        L = letters[st]
        out.append(_num("n" + L, d["n"]))
        for key, short in [("any_raw", "AnyRaw"), ("any_error_raw", "ErrRaw"), ("any_security_raw", "SecRaw"),
                           ("any_confirmed", "Confirmed"), ("any_reported", "AnyReported"), ("confirmed_beyond_file", "Beyond"),
                           ("confirmed_security", "ConfSec"), ("confirmed_security_incl_provisional", "ConfSecProv"),
                           ("tolerated_only", "ToleratedOnly"), ("reference_rule", "RefRule"),
                           ("multi_assistant", "Multi"), ("integrity_any", "Integrity"), ("spec_any", "Spec"), ("any_confirmed_defect", "ConfirmedDefect"),
                           ("confirmed_cross", "Cross"), ("any_gate_raw", "GateRaw")]:
            k, n, (p, lo, hi) = d[key]
            out.append(_m(L + short, p)); out.append(_m(L + short + "Lo", lo)); out.append(_m(L + short + "Hi", hi))
            out.append(_num(L + short + "K", k))
        out.append(_num(L + "MedComp", int(d["median_components"])))
        out.append(_num(L + "MaxComp", int(d["max_components"])))
        out.append(_num(L + "MedTok", int(d["median_tokens"])))
        out.append(_num(L + "MaxTok", int(d["max_tokens"])))
        out.append(_num(L + "MedAlways", int(d["median_always_loaded"])))
        out.append(_m(L + "MedDur", d["median_duration_s"])); out.append(_m(L + "PNinetyfiveDur", d["p95_duration_s"]))
        fb = d["findings_by_scope"]; tot = sum(fb.values()) or 1
        out.append(_m(L + "PctFindingsBeyond", 100 * (tot - fb.get("FILE", 0)) / tot))
        for rid, (name, fam) in CANDIDATE_RULES.items():
            key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
            k, n, (p, lo, hi) = d["per_rule"][rid]
            out.append(_m(L + key, p)); out.append(_m(L + key + "Lo", lo)); out.append(_m(L + key + "Hi", hi))
    out.append(_num("nAuditedFindings", sum(a["audited"] for a in s.get("audit", {}).values())))
    out.append(_num("nAuditedRepos", s.get("audit_repos", 0)))
    out.append(_num("nGatingFindings", sum(s["audit"][r]["audited"] for r in s["reported_rules"] if r in s.get("audit", {}))))
    ranking = ", ".join(f"{name} ({n})" for name, n in s["tool_ranking"][:6])
    out.append(f"\\newcommand{{\\ToolRanking}}{{{ranking}}}\n")
    out.append(_num("nFlowRepos", s["flow_repos"]))
    for k, v in s["grant_mechanisms"].items():
        out.append(_num("Grant" + "".join(w.capitalize() for w in k.split("-")), v))
    out.append(_m("FlowRepoWord", "repository" if s["flow_repos"] == 1 else "repositories"))
    out.append(_m("ProvisionalRuleWord", "rule is" if len(s["provisional_rules"]) == 1 else "rules are"))
    out.append(_m("ProvisionalEnterWord", "enters" if len(s["provisional_rules"]) == 1 else "enter"))
    asm = s["assembled"]
    out.append(_num("nAssembled", asm["n"]))
    for key, short in (("any_confirmed", "AsmConfirmed"), ("confirmed_security", "AsmConfSec"), ("confirmed_beyond_file", "AsmBeyond")):
        k, n, (p, lo, hi) = asm[key]
        out.append(_m(short, p)); out.append(_m(short + "Lo", lo)); out.append(_m(short + "Hi", hi))
    integ = {rid: name.lower() for rid, (name, fam) in CANDIDATE_RULES.items() if fam == "Q" and rid in s["reported_rules"]}
    dset = s["per_stratum"].get("SETUP", {})
    items = sorted(((dset["per_rule"][rid][2][0], dset["per_rule"][rid][0], desc) for rid, desc in integ.items() if rid in dset.get("per_rule", {}) and dset["per_rule"][rid][0] > 0), reverse=True)
    lst = "; ".join(f"{desc} in \\pc{{{p:.1f}}} ({k})" for p, k, desc in items)
    out.append(f"\\newcommand{{\\IntegrityList}}{{{lst}}}\n")
    out.append(_num("nIntegrityZero", sum(1 for rid in integ if rid in dset.get("per_rule", {}) and dset["per_rule"][rid][0] == 0)))
    specr = {rid: name.lower() for rid, (name, fam) in CANDIDATE_RULES.items() if fam == "P" and rid in s["reported_rules"]}
    sitems = sorted(((dset["per_rule"][rid][2][0], dset["per_rule"][rid][0], desc) for rid, desc in specr.items() if rid in dset.get("per_rule", {}) and dset["per_rule"][rid][0] > 0), reverse=True)
    slst = "; ".join(f"{desc} in \\pc{{{p:.1f}}} ({k})" for p, k, desc in sitems)
    out.append(f"\\newcommand{{\\SpecList}}{{{slst}}}\n")
    cc = s["channel_check"]
    out.append(_num("ChanAgentsWithComponents", cc["agents_with_components"]))
    for key in ("topic_only", "readme_only", "curated", "agents", "agents_raw"):
        k, n, (p, lo, hi) = cc[key]
        K = "".join(w.capitalize() for w in key.split("_"))
        out.append(_m("Chan" + K, p)); out.append(_num("Chan" + K + "N", n))
    KNOWN_SUBS = ["dead", "misrouted", "runtime_output", "invocation_cycle", "documented_command_cycle",
                  "mention_cycle", "no_cycle", "generic_mcp_mention", "server_referenced",
                  "no_frontmatter", "invalid_yaml", "missing_name", "name_mismatch", "arbitrary_exec",
                  "bash_star", "bare_tool", "bypassPermissions", "dontAsk", "acceptEdits", "all_mcp",
                  "diverged", "identical", "referenced"]
    all_audit_rules = set(CANDIDATE_RULES) | {REFERENCE_RULE} | WITHDRAWN
    for rid in sorted(all_audit_rules):
        key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
        if rid not in s.get("audit", {}):
            out.append(_num("Aud" + key + "N", 0)); out.append(_num("Aud" + key + "K", 0))
            for m in ("", "Lo", "Hi"):
                out.append(_m("Aud" + key + m, 0.0))
        for sub in KNOWN_SUBS:
            subkey = "Aud" + key + "".join(w.capitalize() for w in sub.split("_"))
            if sub not in s.get("audit", {}).get(rid, {}).get("breakdown", {}):
                out.append(_m(subkey, 0.0))
    for rid in sorted(all_audit_rules):
        key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
        a = s.get("audit", {}).get(rid)
        if a is None:
            status = "was not exercised by the corpus and carries no figure"
        elif rid in s["gating_rules"]:
            status = "meets the bar and enters the gating tier"
        elif rid in s["provisional_rules"]:
            status = "re-derived without a false positive on fewer than fifty findings and is reported provisionally, outside every headline figure"
        elif rid in s["observation_rules"]:
            status = "re-derives mechanically but adjudication found the stated consequence in too few cases; reported as an observation outside every defect figure"
        elif a["audited"] < 13:
            status = "fired on too few repositories in this corpus to be validated and carries no figure"
        else:
            status = "fell below the precision bar and carries no figure"
        out.append(f"\\newcommand{{\\Status{key}}}{{{status}}}\n")
        if a is not None:
            out.append(_num("Aud" + key + "Conseq", a.get("consequential", 0)))
            out.append(_m("Aud" + key + "ConseqPct", 100 * a.get("consequential", 0) / max(1, a["confirmed"])))
            out.append(_num("Adj" + key + "N", a.get("adjudicated_n", 0)))
            out.append(_num("Adj" + key + "K", a.get("adjudicated_defect", 0)))
            out.append(_num("Adj" + key + "Pairs", a.get("pairs", 0)))
            out.append(_num("Adj" + key + "Agreed", a.get("agreed_pairs", 0)))
            out.append(_num("Adj" + key + "Defects", a.get("defect_pairs", 0)))
            out.append(_m("Adj" + key + "Pct", 100 * (a.get("defect_share") or 0)))
        else:
            for m in ("N", "K", "Pairs", "Agreed", "Defects"):
                out.append(_num("Adj" + key + m, 0))
            out.append(_m("Adj" + key + "Pct", 0.0))
    ref = s.get("audit", {}).get(REFERENCE_RULE, {})
    for sub in ("dead", "misrouted", "runtime_output"):
        subkey = "".join(w.capitalize() for w in sub.split("_"))
        out.append(_num("RefSplit" + subkey, round(100 * ref.get("breakdown", {}).get(sub, 0) / max(1, ref.get("audited", 1)) / 5) * 5))
    for rid, a in s.get("audit", {}).items():
        key = "".join(w.capitalize() for w in rid.replace("/", "-").split("-"))
        p, lo, hi = wilson(a["confirmed"], a["audited"])
        out.append(_num("Aud" + key + "N", a["audited"])); out.append(_num("Aud" + key + "K", a["confirmed"]))
        out.append(_m("Aud" + key, p)); out.append(_m("Aud" + key + "Lo", lo)); out.append(_m("Aud" + key + "Hi", hi))
        for sub, v in a.get("breakdown", {}).items():
            subkey = "".join(w.capitalize() for w in re.sub(r"[^A-Za-z_]", "", sub).split("_") if w)
            if not subkey or sub not in KNOWN_SUBS:
                continue
            out.append(_m("Aud" + key + subkey, 100 * v / max(1, a["audited"])))
    (PAPER / "numbers.tex").write_text("".join(out))

    # Tables
    rep = s["reported_rules"]
    order = sorted(rep, key=lambda r: (rep[r]["tier"] != "gating", {"S": 0, "Q": 1, "P": 2, "C": 3}.get(rep[r]["family"], 4),
                                       -s["per_stratum"].get("SETUP", {}).get("per_rule", {}).get(r, (0, 0, (0,)))[2][0]))
    t2 = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}lrrr@{}}\n\\toprule\n",
          "Rule (family) & Scope & Setups & Collections \\\\\n\\midrule\n"]
    def pct(st, rid):
        d = s["per_stratum"].get(st)
        return f"{d['per_rule'][rid][2][0]:.1f}\\%" if d else "--"
    for rid in order:
        name, fam = rep[rid]["name"], rep[rid]["family"]
        sc = scope.get(rid, {"scope": "FILE"})["scope"].replace("_", "\\_")
        mark = "" if rep[rid]["tier"] == "gating" else "$^{p}$"
        t2.append(f"{name} ({fam}){mark} & {sc} & {pct('SETUP', rid)} & {pct('COLLECTION', rid)} \\\\\n")
    t2.append("\\midrule\n")
    def row(label, key):
        cells = []
        for st in ("SETUP", "COLLECTION"):
            d = s["per_stratum"].get(st)
            cells.append(f"{d[key][2][0]:.1f}\\%" if d else "--")
        return f"{label} & & " + " & ".join(cells) + " \\\\\n"
    t2.append(row("Any security defect (S, gating)", "confirmed_security"))
    t2.append(row("Any cannot-work defect (Q, gating)", "integrity_any"))
    if any(v["family"] == "P" for rid, v in s["reported_rules"].items() if rid in s["gating_rules"]):
        t2.append(row("Any spec-conformance defect (P, gating)", "spec_any"))
    if any(v["family"] == "C" for rid, v in s["reported_rules"].items() if rid in s["gating_rules"]):
        t2.append(row("Any cross-assistant defect (C, gating)", "confirmed_cross"))
    t2.append(row("Any confirmed defect (S and Q, gating)", "any_confirmed_defect"))
    t2.append(row("Any confirmed finding (S, Q, and P, gating)", "any_confirmed"))
    t2.append(row("Any confirmed finding (incl.\\ provisional)", "any_reported"))
    t2.append(row("Raw gate output before audit", "any_gate_raw"))
    t2.append("\\midrule\n")
    t2.append(row("Reference does not resolve", "reference_rule").replace("& & ", "& FILE\\_FS & "))
    t2.append("\\bottomrule\n\\end{tabular}\n")
    t3 = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}lrrrrr@{}}\n\\toprule\n",
          "Rule (family) & Audited & Agreement (95\\% CI) & Pairs & Adjud. & Defect \\\\\n\\midrule\n"]
    for rid in order:
        a = s["audit"][rid]
        p, lo, hi = wilson(a["confirmed"], a["audited"])
        mark = "" if rep[rid]["tier"] == "gating" else "$^{p}$"
        t3.append(f"{rep[rid]['name']} ({rep[rid]['family']}){mark} & {a['audited']} & {p:.1f}\\% ({lo:.1f}--{hi:.1f}) & {a['pairs']} & {a['disagreements']} & {a['defect_pairs']} ({100 * (a['defect_share'] or 0):.0f}\\%) \\\\\n")
    t3.append("\\bottomrule\n\\end{tabular}\n")
    # Observations: rules that re-derive but whose adjudicated consequence falls below the bar.
    obs = s["observation_rules"]
    to = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}lrrrl@{}}\n\\toprule\n",
          "Rule (family) & Pairs & Adjud. & Defect & Most common non-defect reason \\\\\n\\midrule\n"]
    for rid in sorted(obs, key=lambda r: -(s["audit"][r].get("defect_share") or 0)):
        a = s["audit"][rid]
        reasons = {k: v for k, v in a.get("adjudication_reasons", {}).items() if k != "live_config"}
        top = max(reasons, key=reasons.get).replace("_", " ") if reasons else "--"
        to.append(f"{obs[rid]['name']} ({obs[rid]['family']}) & {a['pairs']} & {a['disagreements']} & {a['defect_pairs']} ({100 * (a['defect_share'] or 0):.0f}\\%) & {top} \\\\\n")
    to.append("\\bottomrule\n\\end{tabular}\n")
    (PAPER / "table_observations.tex").write_text("".join(to))
    (PAPER / "table_rules.tex").write_text("".join(t2))
    dset = s["per_stratum"].get("SETUP", {})
    te = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}p{2.15cm}rp{4.05cm}@{}}\n\\toprule\n",
          "Defect & Setups & What it looks like \\\\\n\\midrule\n"]
    for rid in order:
        k, n, (p, lo, hi) = dset["per_rule"][rid]
        mark = "" if rep[rid]["tier"] == "gating" else "$^{p}$"
        te.append(f"{rep[rid]['name']}{mark} & {p:.1f}\\% ({k}) & {EXAMPLES.get(rid, '')} \\\\\n")
    te.append("\\bottomrule\n\\end{tabular}\n")
    (PAPER / "table_examples.tex").write_text("".join(te))
    (PAPER / "table_precision.tex").write_text("".join(t3))
    # Table 1: rule set by scope
    sc = s["rule_scope_counts"]
    t1 = ["% Generated by scripts/analyze.py\n"]
    for k in ("FILE", "FILE_FS", "PAIRWISE", "SETUP"):
        t1.append(f"\\newcommand{{\\scope{k.replace('_', '')}Count}}{{{sc.get(k, 0)}}}\n")
    (PAPER / "table_scope_counts.tex").write_text("".join(t1))
    # Every measured rule with its outcome, so the rule count closes.
    t2b = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}llrrl@{}}\n\\toprule\n",
           "Rule & Fam. & Findings & Agree. & Outcome \\\\\n\\midrule\n"]
    for rid, (name, fam) in CANDIDATE_RULES.items():
        if fam == "A":
            continue
        a = s["audit"].get(rid)
        if a is None:
            n_f, agr, outcome = 0, "--", "no finding in the corpus"
        else:
            n_f = a["audited"]
            agr = f"{100 * a['confirmed'] / max(1, a['audited']):.0f}\\%"
            if rid in s["gating_rules"]:
                outcome = "gating"
            elif rid in s["provisional_rules"]:
                outcome = "provisional"
            elif rid in s["observation_rules"]:
                outcome = "observation (consequence bar)"
            elif a["audited"] < 13:
                outcome = "too few findings"
            else:
                outcome = "below the agreement bar"
        t2b.append(f"{rid.replace('_', '-')} & {fam} & {n_f} & {agr} & {outcome} \\\\\n")
    t2b.append("\\bottomrule\n\\end{tabular}\n")
    (PAPER / "table_withdrawn.tex").write_text("".join(t2b))
    out_counts = Counter()
    for rid, (name, fam) in CANDIDATE_RULES.items():
        if fam == "A":
            continue
        a = s["audit"].get(rid)
        out_counts["none" if a is None else "gating" if rid in s["gating_rules"] else "provisional" if rid in s["provisional_rules"]
                   else "observation" if rid in s["observation_rules"] else "few" if a["audited"] < 13 else "below"] += 1
    with (PAPER / "numbers.tex").open("a") as nf:
        for k, label in (("none", "nRulesNoFinding"), ("few", "nRulesTooFew"), ("below", "nRulesBelowBar")):
            nf.write(f"\\newcommand{{\\{label}}}{{{out_counts.get(k, 0)}}}\n")
    # Table 5: catalog by category with scope mix and reported count
    cats = defaultdict(lambda: {"n": 0, "scopes": Counter(), "reported": 0})
    code = {"FILE": "F", "FILE_FS": "F+", "PAIRWISE": "P", "SETUP": "S"}
    for rid, v in scope.items():
        if rid not in s.get("candidate_rules", []) and rid not in s["rule_scope_counts"] and rid.startswith(("hooks/pre-trust-allow", "hooks/auto-accept-edits", "hooks/all-project-mcp", "cross/grant-", "content/allowed-tools-scoped", "frontmatter/name-missing")):
            continue
        cat = rid.split("/")[0]
        cats[cat]["n"] += 1
        cats[cat]["scopes"][code[v["scope"]]] += 1
        if rid in rep:
            cats[cat]["reported"] += 1
    t5 = ["% Generated by scripts/analyze.py\n", "\\begin{tabular}{@{}lrlr@{}}\n\\toprule\n",
          "Category & Rules & Scope mix & Reported \\\\\n\\midrule\n"]
    for cat in sorted(cats, key=lambda c: -cats[c]["n"]):
        d = cats[cat]
        mix = ", ".join(f"{n}{k}" for k, n in sorted(d["scopes"].items(), key=lambda kv: -kv[1]))
        t5.append(f"{cat.replace('_', '-')} & {d['n']} & {mix} & {d['reported'] or '--'} \\\\\n")
    tot = Counter(code[v["scope"]] for rid, v in scope.items() if not rid.startswith(("hooks/pre-trust-allow", "hooks/auto-accept-edits", "hooks/all-project-mcp", "cross/grant-", "content/allowed-tools-scoped", "frontmatter/name-missing")))
    mix = ", ".join(f"{n}{k}" for k, n in sorted(tot.items(), key=lambda kv: -kv[1]))
    t5.append("\\midrule\n")
    t5.append(f"Total & {len(scope)} & {mix} & {len(rep)} \\\\\n\\bottomrule\n\\end{{tabular}}\n")
    (PAPER / "table_catalog.tex").write_text("".join(t5))


def _write_fig(s: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.2), gridspec_kw={"width_ratios": [0.8, 1.6]})
    names = {"SETUP": "Setups", "COLLECTION": "Collections"}
    cols = {"SETUP": "#c0392b", "COLLECTION": "#34495e"}
    xs, ys, err, labels = [], [], [], []
    for i, st in enumerate(("SETUP", "COLLECTION")):
        d = s["per_stratum"].get(st)
        if not d:
            continue
        k, n, (p, lo, hi) = d["any_confirmed_defect"]
        k2, n2, (p2, lo2, hi2) = d["any_confirmed"]
        xs.append(i); ys.append(p2); err.append([p - lo, hi - p]); labels.append(f"{names[st]}\n(n={n})")
        ax1.bar(i, p2, color="#d5d8dc", width=0.6)
        ax1.bar(i, p, color=cols[st], width=0.6)
        ax1.errorbar(i, p, yerr=[[p - lo], [hi - p]], fmt="none", ecolor="black", capsize=4)
        ax1.text(i, hi2 + 1, f"{p:.1f}% defect\n{p2:.1f}% any finding", ha="center", fontsize=8, fontweight="bold")
    ax1.set_xticks(xs); ax1.set_xticklabels(labels); ax1.set_ylabel("Prevalence among repositories (%)")
    ax1.set_title("Confirmed defects (S+Q) and findings (incl. P)", fontsize=10); ax1.set_ylim(0, max(ys + [10]) * 1.45)
    d = s["per_stratum"].get("SETUP", {})
    fam_col = {"S": "#c0392b", "Q": "#3b5f8a", "P": "#7f8c8d", "C": "#8e44ad"}
    rows = [(s["reported_rules"][rid]["name"], d["per_rule"][rid][2], s["reported_rules"][rid]["family"]) for rid in s["headline_rules"]]
    rows.sort(key=lambda r: r[1][0])
    for i, (name, (p, lo, hi), fam) in enumerate(rows):
        ax2.barh(i, p, color=fam_col.get(fam, "#3b5f8a")); ax2.errorbar(p, i, xerr=[[p - lo], [hi - p]], fmt="none", ecolor="black", capsize=3)
        ax2.text(hi + 0.3, i, f"{p:.1f}", va="center", fontsize=9)
    ax2.set_yticks(range(len(rows))); ax2.set_yticklabels([f"{r[0]} ({r[2]})" for r in rows]); ax2.set_xlabel("Setup prevalence (%)")
    ax2.set_title("Gating-tier prevalence among setups (95% CI)")
    from matplotlib.patches import Patch
    ax2.legend(handles=[Patch(color=fam_col[f], label=lab) for f, lab in (("S", "security"), ("Q", "cannot work"), ("P", "spec conformance"))
                        if any(r[2] == f for r in rows)], loc="lower right", fontsize=8, frameon=False)
    for ax in (ax1, ax2):
        ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    fig.tight_layout(); fig.savefig(FIG / "results.png", dpi=200); fig.savefig(FIG / "results.pdf")
    (FIG / "results_values.json").write_text(json.dumps({"left": {st: round(s["per_stratum"][st]["any_confirmed_defect"][2][0], 1)
                                                                  for st in ("SETUP", "COLLECTION") if st in s["per_stratum"]},
                                                         "right": {n: round(p, 1) for n, (p, lo, hi), _f in rows}}, indent=1))


if __name__ == "__main__":
    main()
