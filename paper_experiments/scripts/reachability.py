#!/usr/bin/env python3
"""Reachable-impact check for the two headline security classes (reviewer Q5).

For a seeded sample of setups with an arbitrary-execution grant, re-clone at
the pinned commit and ask: does a component the repository ships (skill,
command, hook, context file) instruct the agent to run that interpreter or
tool? For unpinned MCP servers: does a component name the server or one of
its tools? Records counts and one anonymized example per class (commit hash
only) in data/reachability.json and paper/reachability.tex.
"""
from __future__ import annotations

import json
import random
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
sys.path.insert(0, str(ROOT / "scripts"))
from audit import clone_pinned  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 40
rng = random.Random(255)
from analyze import read_results  # noqa: E402
recs = read_results()
ok = [r for r in recs if r.get("status") == "ok" and r.get("commit")]


def components(root: Path) -> list[Path]:
    out = []
    for p in root.rglob("*.md"):
        if ".git" in p.parts or "node_modules" in p.parts:
            continue
        if p.name in ("SKILL.md", "CLAUDE.md", "AGENTS.md", "GEMINI.md") or any(x in p.parts for x in ("commands", "agents", "prompts")):
            out.append(p)
    for p in (root / ".claude" / "settings.json", root / ".claude" / "hooks.json"):
        if p.is_file():
            out.append(p)
    return out


grant_re = re.compile(r"entry 'Bash\(\s*(?:[\w./-]*/)?([\w.+-]+)")
grants = [(r, sorted({m.group(1).lower() for f in r["findings"] if f["rule"] == "cross/overpermissive-grants"
                      for m in [grant_re.search(f["message"])] if m and m.group(1).lower() not in ("*",)}))
          for r in ok if any(f["rule"] == "cross/overpermissive-grants" for f in r["findings"])]
_SEC = {"sh", "bash", "zsh", "dash", "fish", "env", "eval", "exec", "xargs", "sudo", "doas", "python", "python3", "perl",
        "ruby", "node", "bun", "deno", "php", "lua", "awk", "gawk", "mawk", "nawk", "sed", "find", "npx", "bunx", "uvx", "pipx"}
grants = [(r, [c for c in cmds if c in _SEC]) for r, cmds in grants]
grants = [(r, cmds) for r, cmds in grants if cmds]
unp_re = re.compile(r"'([^']+)'")
unpinned = [(r, sorted({unp_re.search(f["message"]).group(1) for f in r["findings"] if f["rule"] == "mcp/unpinned-package" and unp_re.search(f["message"])}))
            for r in ok if any(f["rule"] == "mcp/unpinned-package" for f in r["findings"])]
unpinned = [(r, names) for r, names in unpinned if names]
rng.shuffle(grants); rng.shuffle(unpinned)

res = {"grants": {"eligible": len(grants), "sampled": 0, "clone_failed": 0, "reachable": 0, "examples": []},
       "unpinned": {"eligible": len(unpinned), "sampled": 0, "clone_failed": 0, "reachable": 0, "examples": []}}

for r, cmds in grants[:N]:
    root = clone_pinned(r["full_name"], r["commit"])
    if root is None:
        res["grants"]["clone_failed"] += 1
        continue
    res["grants"]["sampled"] += 1
    hit = None
    try:
        for p in components(root):
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue   # a dangling symlink or an unreadable file
            for c in cmds:
                # Invocation context only: the command at the start of a fenced-code or backticked line,
                # or "run/execute/invoke <cmd>", or the command followed by a script or -c/-e/-m argument.
                inv = (re.search(rf"(?m)^\s*(?:\$\s*)?{re.escape(c)}\s+\S", text)
                       or re.search(rf"`{re.escape(c)}\s+[^`]+`", text)
                       or re.search(rf"\b(?:run|execute|invoke|call)\s+(?:the\s+)?`?{re.escape(c)}\b", text, re.I)
                       or re.search(rf"\b{re.escape(c)}\s+(?:-c|-m|-e|\S+\.(?:py|js|ts|sh|rb|pl))\b", text))
                if inv:
                    hit = (c, str(p.relative_to(root)))
                    break
            if hit:
                break
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)
    if hit:
        res["grants"]["reachable"] += 1
        if len(res["grants"]["examples"]) < 3:
            res["grants"]["examples"].append({"commit": r["commit"], "grant": f"Bash({hit[0]}:*)", "component": hit[1]})
    print(f"grant {r['full_name']} {'REACHABLE ' + str(hit) if hit else '-'}", file=sys.stderr, flush=True)

for r, names in unpinned[:N]:
    root = clone_pinned(r["full_name"], r["commit"])
    if root is None:
        res["unpinned"]["clone_failed"] += 1
        continue
    res["unpinned"]["sampled"] += 1
    hit = None
    try:
        for p in components(root):
            if p.name in ("settings.json", "hooks.json"):
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue   # a dangling symlink or an unreadable file.lower()
            for n in names:
                if re.search(rf"mcp__{re.escape(n.lower())}__|(?<![\w-]){re.escape(n.lower())}(?![\w-])", text):
                    hit = (n, str(p.relative_to(root)))
                    break
            if hit:
                break
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)
    if hit:
        res["unpinned"]["reachable"] += 1
        if len(res["unpinned"]["examples"]) < 3:
            res["unpinned"]["examples"].append({"commit": r["commit"], "server": hit[0], "component": hit[1]})
    print(f"unpinned {r['full_name']} {'REACHABLE ' + str(hit) if hit else '-'}", file=sys.stderr, flush=True)

(DATA / "reachability.json").write_text(json.dumps(res, indent=1))
g, u = res["grants"], res["unpinned"]
tex = ["% Generated by scripts/reachability.py\n",
       f"\\newcommand{{\\ReachGrantSampled}}{{{g['sampled']}}}\n", f"\\newcommand{{\\ReachGrantHit}}{{{g['reachable']}}}\n",
       f"\\newcommand{{\\ReachGrantPct}}{{{100*g['reachable']/max(1,g['sampled']):.0f}}}\n",
       f"\\newcommand{{\\ReachGrantEligible}}{{{g['eligible']}}}\n", f"\\newcommand{{\\ReachGrantFailed}}{{{g['clone_failed']}}}\n",
       f"\\newcommand{{\\ReachUnpSampled}}{{{u['sampled']}}}\n", f"\\newcommand{{\\ReachUnpHit}}{{{u['reachable']}}}\n",
       f"\\newcommand{{\\ReachUnpPct}}{{{100*u['reachable']/max(1,u['sampled']):.0f}}}\n"]
ex = g["examples"][0] if g["examples"] else {"commit": "", "grant": "", "component": ""}
tex.append(f"\\newcommand{{\\ReachGrantExGrant}}{{{ex['grant']}}}\n\\newcommand{{\\ReachGrantExComp}}{{{ex['component'].replace('_', chr(92)+'_')}}}\n\\newcommand{{\\ReachGrantExCommit}}{{{ex['commit'][:12]}}}\n")
ex = u["examples"][0] if u["examples"] else {"commit": "", "server": "", "component": ""}
tex.append(f"\\newcommand{{\\ReachUnpExServer}}{{{ex['server'].replace('_', chr(92)+'_')}}}\n\\newcommand{{\\ReachUnpExComp}}{{{ex['component'].replace('_', chr(92)+'_')}}}\n\\newcommand{{\\ReachUnpExCommit}}{{{ex['commit'][:12]}}}\n")
(ROOT / "paper" / "reachability.tex").write_text("".join(tex))
print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != 'examples'} for k, v in res.items()}))
