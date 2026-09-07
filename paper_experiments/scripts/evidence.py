#!/usr/bin/env python3
"""Extract the lines behind every disagreement, for adjudication.

A (repository, rule) pair is a disagreement when the audit did not fully
confirm the tool: a finding refuted or unverifiable, a sub-class whose
consequence does not hold, or a rule whose consequence the audit cannot decide
from bytes (analyze.INTENT_RULES). For each such pair, re-clone at the pinned commit and write a compact evidence
record per (repository, rule): the settings entry, the server definition,
the frontmatter head, the import line and its resolution, the differing
sections. Output: data/evidence.jsonl. No repository content beyond the
quoted lines is retained.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit import (_agents, _frontmatter, _hook_entries, _load_json, _mcp_configs, _servers,  # noqa: E402
                   _settings_files, _skills_all, clone_pinned, EXEC_CMDS, FM_RE)
from analyze import CANDIDATE_RULES, NON_DEFECT_SUBS, remap, stratum  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"
# Every measured rule that clears the agreement bar (>= 13 re-derived findings,
# >= 97% agreement) is adjudicated, whatever tier it ends up in; the tier is
# decided afterwards by analyze.py from the verdicts.
_audit = json.loads((DATA / "audit_summary.json").read_text())
REPORTED = {rid for rid, (name, fam) in CANDIDATE_RULES.items() if fam != "A"
            and _audit.get(rid, {}).get("audited", 0) >= 13
            and _audit[rid]["confirmed"] / _audit[rid]["audited"] >= 0.97}
from analyze import read_results  # noqa: E402
recs = {r["full_name"]: r for r in read_results()}


def head(p: Path, n: int = 4) -> str:
    try:
        return " | ".join(p.read_text(errors="replace").splitlines()[:n])[:220]
    except OSError:
        return "(unreadable)"


def sections(t: str) -> dict:
    out, cur, buf = {}, "(root)", []
    for line in t.splitlines():
        m = re.match(r"^#{1,6}\s+(.+)$", line)
        if m:
            out[cur] = "\n".join(buf).strip(); cur, buf = m.group(1).strip(), []
        else:
            buf.append(line)
    out[cur] = "\n".join(buf).strip()
    return {k: v for k, v in out.items() if v}


def evidence(rule: str, msgs: list[str], root: Path) -> str:
    out = []
    if rule == "mcp/unpinned-package":
        names = {m.group(1) for msg in msgs for m in [re.search(r"server '([^']+)'", msg)] if m}
        for c in _mcp_configs(root):
            for n, sd in _servers(c).items():
                if n in names and isinstance(sd, dict):
                    out.append(f"{c.relative_to(root)} [{n}]: {sd.get('command')} {' '.join(map(str, sd.get('args', [])))}"[:200])
    elif rule == "cross/overpermissive-grants":
        entries = {m.group(1) for msg in msgs for m in [re.search(r"entry '([^']+)'", msg)] if m}
        out.append("permissions.allow: " + ", ".join(sorted(entries))[:260])
    elif rule == "content/allowed-tools-auto-approve":
        tools = {m.group(1) for msg in msgs for m in [re.search(r"includes '([^']+)'", msg)] if m}
        for name, paths in _skills_all(root).items():
            for p in paths:
                fm, body = _frontmatter(p)
                a = (fm or {}).get("allowed-tools")
                if a and any(t in (a if isinstance(a, list) else str(a)) for t in tools):
                    out.append(f"{p.parent.relative_to(root)}: allowed-tools={a!s:.90} desc={str((fm or {}).get('description',''))[:80]!r}")
        out = out[:4]
    elif rule == "frontmatter/format-valid":
        for name, paths in _skills_all(root).items():
            for p in paths:
                if not FM_RE.match(p.read_text(errors="replace")):
                    out.append(f"{p.relative_to(root)}: {head(p, 3)}")
        out = out[:4]
    elif rule == "frontmatter/description-required":
        for name, paths in _skills_all(root).items():
            for p in paths:
                fm, _ = _frontmatter(p)
                if fm is not None and not fm.get("description"):
                    out.append(f"{p.relative_to(root)}: fm={json.dumps(fm)[:150]}")
    elif rule == "agent/description-required":
        for name, p in _agents(root).items():
            fm, _ = _frontmatter(p)
            if fm is None or not fm.get("description"):
                out.append(f"{p.relative_to(root)}: {head(p, 3)}")
        out = out[:4]
    elif rule == "agent/referenced-skills-exist":
        names = {m.group(1) for msg in msgs for m in [re.search(r"skill '([^']+)'", msg)] if m}
        out.append("declared but absent: " + ", ".join(sorted(names))[:150])
        out.append("skills present: " + ", ".join(sorted(_skills_all(root)))[:200])
    elif rule == "claude-md/include-exists":
        for msg in msgs[:4]:
            m = re.search(r"Import '@([^']+)'.*looked for (\S+?)\)", msg)
            if not m:
                continue
            ref, looked = m.groups()
            rel = re.sub(r"^/tmp/he-[^/]+/repo/", "", looked)
            ctx = ""
            for cand in root.rglob("*"):
                if cand.is_file() and cand.suffix in (".md", ".mdc") and ".git" not in cand.parts:
                    try:
                        for line in cand.read_text(errors="replace").splitlines():
                            if "@" + ref in line:
                                ctx = f"{cand.relative_to(root)}: {line.strip()[:120]}"; break
                    except OSError:
                        pass
                if ctx:
                    break
            base = Path(ref).name
            elsewhere = [str(p.relative_to(root)) for p in root.rglob(base) if p.is_file()][:2]
            out.append(f"{ctx} -> looked {rel}; same basename elsewhere: {elsewhere}")
    elif rule == "hooks/permission-prompt-disabled":
        for p in _settings_files(root):
            d, _ = _load_json(p)
            if isinstance(d, dict):
                perm = d.get("permissions", {}) if isinstance(d.get("permissions"), dict) else {}
                keys = {k: d.get(k) for k in ("enableAllProjectMcpServers", "skipDangerousModePermissionPrompt") if k in d}
                if perm.get("defaultMode"):
                    keys["defaultMode"] = perm["defaultMode"]
                if keys:
                    out.append(f"{p.relative_to(root)}: {json.dumps(keys)}")
    elif rule == "hooks/local-settings-committed":
        p = root / ".claude" / "settings.local.json"
        if p.is_file():
            d, _ = _load_json(p)
            allow = (d.get("permissions", {}) or {}).get("allow", []) if isinstance(d, dict) and isinstance(d.get("permissions"), dict) else []
            out.append(f".claude/settings.local.json: {len(allow)} allow entries, e.g. {allow[:3]}"[:220])
    elif rule == "mcp/cross-assistant-divergence":
        for msg in msgs[:3]:
            m = re.search(r"server '([^']+)' is declared differently in (\S+) \(.*?\) and (\S+) ", msg)
            if not m:
                continue
            name, fa, fb = m.groups()
            defs = []
            for rel in (fa, fb):
                for c in [root / rel] + [p for p in root.rglob(Path(rel).name) if p.is_file()]:
                    if c.is_file() and name in _servers(c):
                        sd = _servers(c)[name]
                        defs.append(f"{rel}: {sd.get('command','')} {' '.join(map(str, sd.get('args', [])))} {sd.get('url','')}".strip()[:110])
                        break
            out.append(f"[{name}] " + " || ".join(defs))
    elif rule == "mcp/valid-config":
        for msg in msgs[:3]:
            out.append(msg[:160])
    elif rule == "cross/multi-assistant-drift":
        files = [root / n for n in ("CLAUDE.md", "AGENTS.md", "GEMINI.md") if (root / n).is_file()]
        secs = [sections(p.read_text(errors="replace")) for p in files]
        diff, same = [], 0
        for i in range(len(secs)):
            for j in range(i + 1, len(secs)):
                for k in set(secs[i]) & set(secs[j]):
                    (diff if secs[i][k] != secs[j][k] else [None]) .append(k) if secs[i][k] != secs[j][k] else None
                    same += secs[i][k] == secs[j][k]
        sizes = ", ".join(f"{p.name}={len(p.read_text(errors='replace'))}c" for p in files)
        out.append(f"{sizes}; shared sections differing: {diff[:6]}; identical shared: {same}")
        if diff:
            k = diff[0]
            a, b = secs[0].get(k, ""), secs[1].get(k, "")
            out.append(f"'{k}': A={a[:90]!r} B={b[:90]!r}")
    return "\n".join(out)[:900]


def main() -> None:
    from analyze import audit_pairs  # noqa: E402
    rows = [json.loads(l) for l in (DATA / "audit_findings.jsonl").read_text().splitlines() if l.strip()]
    _, state, _ = audit_pairs()
    # --all: every re-derived pair (agreed ones included), for a full reading
    # of the counted defects; written to evidence_all.jsonl.
    everything = "--all" in sys.argv
    out_path = DATA / ("evidence_all.jsonl" if everything else "evidence.jsonl")
    per: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        remap(r)
        st = state.get((r["repo"], r["rule"]))
        if r["rule"] in REPORTED and (st == "disagreement" or (everything and st is not None)):
            per[r["repo"]][r["rule"]].append(r.get("message", ""))
    print(f"{sum(len(v) for v in per.values())} {'re-derived' if everything else 'disagreement'} pairs across {len(per)} repositories", file=sys.stderr, flush=True)

    def one(item):
        repo, rules = item
        rec = recs[repo]
        root = clone_pinned(repo, rec["commit"])
        outs = []
        if root is None:
            return [{"repo": repo, "rule": ru, "evidence": "(clone failed)"} for ru in rules]
        try:
            for ru, msgs in rules.items():
                try:
                    ev = evidence(ru, msgs, root)
                except Exception as e:  # noqa: BLE001
                    ev = f"(error {type(e).__name__}: {e})"
                outs.append({"repo": repo, "commit": rec["commit"][:12], "stars": rec.get("stars", 0), "stratum": stratum(rec),
                             "rule": ru, "n_findings": len(msgs), "evidence": ev})
        finally:
            shutil.rmtree(root.parent, ignore_errors=True)
        return outs

    with ThreadPoolExecutor(max_workers=8) as ex, out_path.open("w") as f:
        for i, outs in enumerate(ex.map(one, sorted(per.items())), 1):
            for o in outs:
                f.write(json.dumps(o) + "\n")
            f.flush()
            if i % 50 == 0:
                print(f"  {i}/{len(per)}", file=sys.stderr, flush=True)
    print("done", file=sys.stderr)


if __name__ == "__main__":
    main()
