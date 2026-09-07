#!/usr/bin/env python3
"""Scan a seeded random sample of the frame with harness-eval.

For each repository: shallow single-branch clone, record the resolved commit,
run `harness-eval harness-lint --format json` under a timeout, record the
component inventory and findings, delete the working copy. No third-party
content is retained. Resumable: repositories already in the results file are
skipped.

usage: scan.py [N_REPOS] [SEED] [--workers K] [--all] [--only FILE] [--channel PREFIX] [--rescan-stale]
  --all scans every frame entry in seeded order instead of a sample.
  --rescan-stale re-scans repositories whose recorded tool commit is not the
    current one and whose findings include a rule touched since (listed in
    STALE_RULES), so every finding in the results file comes from the same
    rule semantics. Records are replaced in place.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
FRAME = DATA / "frame.jsonl"
RESULTS = DATA / "results.jsonl"
CLONE_TIMEOUT = 300


def _tool_commit() -> str | None:
    """Git commit of the installed harness-eval, when it is an editable checkout."""
    try:
        import harness_eval
        src = Path(harness_eval.__file__).resolve()
        for parent in src.parents:
            if (parent / ".git").exists():
                r = subprocess.run(["git", "-C", str(parent), "rev-parse", "HEAD"], capture_output=True, text=True)
                return r.stdout.strip() or None
    except Exception:  # noqa: BLE001
        return None
    return None


TOOL_COMMIT = _tool_commit()
# Rules whose semantics changed during the study run; a repository that fired
# any of them under an earlier tool commit is re-scanned.
STALE_RULES = {"agent/referenced-skills-exist", "command/references-nonexistent-skill"}
LINT_TIMEOUT = 180


def _load_frame() -> list[dict]:
    return [json.loads(line) for line in FRAME.read_text().splitlines() if line.strip()]


def _ensure_plain_results() -> None:
    """scan.py appends to the plain file; recover it from the shipped .gz when absent."""
    gz = RESULTS.with_suffix(".jsonl.gz")
    if not RESULTS.exists() and gz.exists():
        import gzip
        RESULTS.write_text(gzip.open(gz, "rt", encoding="utf-8").read())


def _done() -> set[str]:
    if not RESULTS.exists():
        return set()
    return {json.loads(line)["full_name"] for line in RESULTS.read_text().splitlines() if line.strip()}


def _inventory(report: dict) -> dict:
    insp = report.get("inspection", {})
    comps = {k: len(v) for k, v in insp.items() if isinstance(v, list) and v}
    return {
        "component_types": comps,
        "component_count": report.get("component_count", sum(comps.values())),
        "detected_tools": report.get("detected_tools", []),
        "budget": {k: report.get("budget", {}).get(k) for k in ("total_tokens", "always_loaded", "on_demand", "by_type")},
    }


def _findings(report: dict, clone_root: str = "") -> list[dict]:
    out = []
    for ctype, comps in report.get("inspection", {}).items():
        if not isinstance(comps, list):
            continue
        for c in comps:
            for f in c.get("findings", []):
                file = f.get("file") or ""
                if clone_root and file.startswith(clone_root):
                    file = file[len(clone_root):].lstrip("/")
                out.append({"rule": f.get("rule"), "severity": f.get("severity"),
                            "component_type": ctype, "component": c.get("name"),
                            "file": file, "line": f.get("line"),
                            "message": (f.get("message") or "")[:400]})
    return out


def scan_one(entry: dict) -> dict:
    fn = entry["full_name"]
    t0 = time.time()
    rec: dict = {"full_name": fn, "url": f"https://github.com/{fn}", "channels": entry.get("channels", []),
                 "stars": entry.get("stars", 0), "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    tmp = tempfile.mkdtemp(prefix="he-")
    try:
        dest = Path(tmp) / "repo"
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        cp = subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "--quiet",
                             f"https://github.com/{fn}.git", str(dest)],
                            capture_output=True, text=True, timeout=CLONE_TIMEOUT, env=env)
        if cp.returncode != 0:
            rec["status"] = "clone_failed"
            rec["error"] = cp.stderr.strip()[-200:]
            return rec
        sha = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        rec["commit"] = sha
        # Presence of files the tool does not itself inventory but the study reports on.
        rec["files"] = {
            "settings_local": (dest / ".claude" / "settings.local.json").is_file(),
            "settings": (dest / ".claude" / "settings.json").is_file(),
            "mcp_json": (dest / ".mcp.json").is_file(),
            "claude_md": (dest / "CLAUDE.md").is_file(),
            "agents_md": (dest / "AGENTS.md").is_file(),
            "gemini_md": (dest / "GEMINI.md").is_file(),
            "cursorrules": (dest / ".cursorrules").is_file() or (dest / ".cursor" / "rules").is_dir(),
            "copilot": (dest / ".github" / "copilot-instructions.md").is_file(),
            "claude_skills": (dest / ".claude" / "skills").is_dir(),
            "claude_agents": (dest / ".claude" / "agents").is_dir(),
            "claude_commands": (dest / ".claude" / "commands").is_dir(),
        }
        lp = subprocess.run(["harness-eval", "harness-lint", str(dest), "--format", "json", "--enforce", "advisory"],
                            capture_output=True, text=True, timeout=LINT_TIMEOUT, cwd=str(dest))
        out = lp.stdout
        start = out.find("{")
        if start < 0:
            rec["status"] = "lint_failed"
            rec["error"] = (lp.stderr or out)[-300:]
            return rec
        try:
            report = json.loads(out[start:])
        except json.JSONDecodeError as e:
            rec["status"] = "lint_failed"
            rec["error"] = f"json: {e}"
            return rec
        rec["status"] = "ok"
        rec["tool_version"] = report.get("metadata", {}).get("version")
        rec["tool_commit"] = TOOL_COMMIT
        rec["inventory"] = _inventory(report)
        rec["findings"] = _findings(report, str(dest.resolve()))
        rec["rules_checked"] = report.get("metadata", {}).get("rules_checked")
        return rec
    except subprocess.TimeoutExpired:
        rec["status"] = "timeout"
        return rec
    except Exception as e:  # noqa: BLE001
        rec["status"] = "error"
        rec["error"] = str(e)[:200]
        return rec
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        rec["duration_s"] = round(time.time() - t0, 2)


def main() -> None:
    _ensure_plain_results()
    argv = sys.argv[1:]
    skip = {argv[i + 1] for i, a in enumerate(argv) if a in ("--workers", "--channel", "--only") and i + 1 < len(argv)}
    args = [a for a in argv if not a.startswith("--") and a not in skip]
    n = int(args[0]) if args else 400
    seed = int(args[1]) if len(args) > 1 else 255
    workers = 6
    if "--workers" in sys.argv:
        workers = int(sys.argv[sys.argv.index("--workers") + 1])
    frame = _load_frame()
    rng = random.Random(seed)
    order = frame[:]
    rng.shuffle(order)
    if "--channel" in sys.argv:
        prefix = sys.argv[sys.argv.index("--channel") + 1]
        order = [e for e in frame if any(c.startswith(prefix) for c in e.get("channels", []))]
    elif "--only" in sys.argv:
        # scan exactly the repositories listed in a file (one full_name per line)
        wanted = {l.strip() for l in open(sys.argv[sys.argv.index("--only") + 1]) if l.strip()}
        order = [e for e in frame if e["full_name"] in wanted]
    elif "--all" not in sys.argv:
        order = order[:n]
    if "--rescan-stale" in sys.argv:
        recs = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()]
        stale = {r["full_name"] for r in recs if r.get("status") == "ok" and r.get("tool_commit") != TOOL_COMMIT
                 and any(f["rule"] in STALE_RULES for f in r.get("findings", []))}
        keep = [r for r in recs if r["full_name"] not in stale]
        RESULTS.write_text("".join(json.dumps(r) + "\n" for r in keep))
        order = [e for e in frame if e["full_name"] in stale]
        print(f"re-scanning {len(order)} stale repositories", file=sys.stderr, flush=True)
    done = _done()
    todo = [e for e in order if e["full_name"] not in done]
    print(f"frame {len(frame)}, sample {len(order)}, done {len(done)}, todo {len(todo)}", file=sys.stderr, flush=True)
    with RESULTS.open("a") as f, ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_one, e): e for e in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            rec = fut.result()
            f.write(json.dumps(rec) + "\n")
            f.flush()
            if i % 10 == 0:
                print(f"  {i}/{len(todo)} last={rec['full_name']} {rec['status']}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
