#!/usr/bin/env python3
"""Write data/repos.md: every repository in the corpus (scanned ok, at least
one harness component, one entry per distinct pinned commit) with its URL, stars,
stratum, pinned commit, and a one-line description taken from the first
prose line of its README at the pinned commit. Descriptions are cached in
data/repo_descriptions.jsonl so the script is resumable."""
from __future__ import annotations

import json
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CACHE = DATA / "repo_descriptions.jsonl"
RAW = "https://raw.githubusercontent.com/{}/{}/{}"
README_NAMES = ("README.md", "readme.md", "README.MD", "Readme.md", "README", "README.rst", "README.txt")


def _get(url: str) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": "harness-eval-study"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read(20000).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


def first_line(text: str) -> str:
    """First prose sentence: skip headings, badges, images, HTML, tables, code,
    lists, and lines that only introduce something (ending in a colon)."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    # Banners, language switchers, and promotions sit above the title; the
    # description is the first paragraph after the first heading when there is one.
    m = re.search(r"^#{1,2} .*$", text, flags=re.M)
    if m and text[m.end():].strip():
        text = text[m.end():]
    buf: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            if buf:
                break
            continue
        if line.startswith(("#", "![", "[![", "|", "---", "===", "*", "-", "+", "•", "$", "npm ", "pip ", "npx ", "git ", "curl ")):
            if buf:
                break
            continue
        line = line.lstrip("> ")
        line = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", line)
        line = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", line)
        line = re.sub(r"[*_`]", "", line).strip()
        if not line:
            continue
        if not buf and (len(line) < 20 or line.endswith(":") or not line[0].isalnum() or line.count("|") >= 2):
            continue
        buf.append(line)
        joined = " ".join(buf)
        m = re.search(r"^(.{20,}?[.!?])(\s|$)", joined)
        if m:
            return m.group(1)[:160]
        if len(joined) > 160:
            return joined[:157].rsplit(" ", 1)[0] + "..."
    joined = " ".join(buf)
    return joined[:160] if len(joined) >= 20 else ""


def describe(fn: str, commit: str, branch: str) -> str:
    for ref in (commit, branch, "main", "master"):
        if not ref:
            continue
        for name in README_NAMES:
            t = _get(RAW.format(fn, ref, name))
            if t is not None:
                d = first_line(t)
                if d:
                    return d
        if ref == commit:
            continue
    return ""


def main() -> None:
    from analyze import read_results  # noqa: E402
    recs = read_results()
    sys.path.insert(0, str(ROOT / "scripts"))
    from analyze import corpus  # noqa: E402
    recs = corpus(recs)
    frame = {json.loads(l)["full_name"]: json.loads(l) for l in (DATA / "frame.jsonl").read_text().splitlines() if l.strip()}
    cache: dict[str, str] = {}
    if CACHE.exists():
        for l in CACHE.read_text().splitlines():
            if l.strip():
                d = json.loads(l)
                cache[d["repo"]] = d["description"]
    todo = [r for r in recs if r["full_name"] not in cache]
    print(f"{len(recs)} repositories, {len(todo)} descriptions to fetch", file=sys.stderr, flush=True)
    with CACHE.open("a") as f, ThreadPoolExecutor(max_workers=8) as ex:
        def one(r):
            return r["full_name"], describe(r["full_name"], r.get("commit", ""), frame.get(r["full_name"], {}).get("default_branch", "main"))
        for i, (fn, d) in enumerate(ex.map(one, todo), 1):
            cache[fn] = d
            f.write(json.dumps({"repo": fn, "description": d}) + "\n")
            f.flush()
            if i % 200 == 0:
                print(f"  {i}/{len(todo)}", file=sys.stderr, flush=True)
    from analyze import stratum  # noqa: E402
    rows = []
    for r in sorted(recs, key=lambda r: -(frame.get(r["full_name"], {}).get("stars") or r.get("stars") or 0)):
        fn = r["full_name"]
        stars = frame.get(fn, {}).get("stars") or r.get("stars") or 0
        desc = cache.get(fn, "").replace("|", "\\|")
        rows.append(f"| [{fn}](https://github.com/{fn}) | {stars:,} | {stratum(r)} | `{(r.get('commit') or '')[:12]}` | {desc} |")
    out = ["# Repositories in the corpus\n",
           f"\n{len(rows)} public GitHub repositories carrying at least one harness component, scanned at the pinned commit. "
           "The description is the first prose line of the repository's README at that commit; empty when the README has none.\n",
           "\n| Repository | Stars | Stratum | Commit | Description |\n|---|---|---|---|---|\n"]
    (DATA / "repos.md").write_text("".join(out) + "\n".join(rows) + "\n")
    print(f"wrote data/repos.md ({len(rows)} rows)", file=sys.stderr)


if __name__ == "__main__":
    main()
