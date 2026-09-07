#!/usr/bin/env python3
"""Write data/defects_table.csv (and .xlsx when openpyxl is installed): one row per
counted (repository, rule) pair in the analyzed corpus, with what harness-eval
reported, what the audit re-derived, what the adjudicator ruled, and an empty
column for a human verdict. A blind copy without the audit and adjudicator
columns is written beside it for an independent reading.

  verdict_table.py           write the tables
  verdict_table.py score     read the human column back and report agreement
                             and Cohen's kappa against the adjudicator (rows
                             the adjudicator did not see are scored against the
                             audit's decision)
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adjudicate import RULE_DEFINITIONS  # noqa: E402
from analyze import NON_DEFECT_SUBS, audit_pairs, corpus, load_adjudications, read_results, remap  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"
OUT = DATA / "defects_table.csv"
BLIND = DATA / "defects_table_blind.csv"
MD_DIR = DATA / "defects_table"  # one Markdown table per rule, browsable on GitHub
COLS = ["repo", "url", "stratum", "rule", "what_the_rule_claims", "harness_file", "harness_file_url",
        "harness_eval_result", "audit_result", "llm_review", "counted_as_defect", "your_verdict", "your_note"]


def build() -> list[dict]:
    from analyze import stratum

    recs = {r["full_name"]: r for r in corpus(read_results())}
    summary, state, _ = audit_pairs(set(recs))
    # only the rules that carry a figure or an observation in the paper
    paper = json.loads((DATA / "summary.json").read_text())
    keep_rules = set(paper["reported_rules"]) | set(paper["observation_rules"])
    state = {k: v for k, v in state.items() if k[1] in keep_rules}
    adj = load_adjudications()
    rows_audit: dict = {}
    for line in (DATA / "audit_findings.jsonl").read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            remap(row)
            if row["repo"] in recs:
                rows_audit.setdefault((row["repo"], row["rule"]), []).append(row)
    ev = {}
    for name in ("evidence_all.jsonl", "evidence.jsonl"):
        p = DATA / name
        if p.exists():
            for line in p.read_text().splitlines():
                if line.strip():
                    e = json.loads(line)
                    ev.setdefault((e["repo"], e["rule"]), e)
    out = []
    for (repo, rule), st in sorted(state.items()):
        rec = recs[repo]
        commit = rec.get("commit", "")
        findings = [f for f in rec.get("findings", []) if f["rule"] == rule]
        files = []
        for f in findings:
            if f.get("file") and f["file"] not in files:
                files.append(f["file"])
        audit_rows = rows_audit.get((repo, rule), [])
        subs = sorted({f"{r['verdict']}/{r.get('sub') or '-'}" for r in audit_rows})
        a = adj.get((repo, rule))
        if st == "agreed":
            counted = "yes"
            llm = "Not reviewed: the scanner and the audit script agree, so the LLM was not asked."
        elif a is None:
            counted = "no"
            llm = "Not reviewed."
        else:
            counted = "yes" if a["verdict"] == "defect" else "no"
            label = {"defect": "Defect.", "not_defect": "Not a defect."}.get(a["verdict"], "Uncertain.")
            text = a.get("explanation") or a.get("note") or ""
            llm = f"{label} {text}".strip()
        out.append({
            "repo": repo, "url": f"https://github.com/{repo}/tree/{commit}", "stratum": stratum(rec), "rule": rule,
            "what_the_rule_claims": RULE_DEFINITIONS.get(rule, ""),
            "harness_file": "; ".join(files),
            "harness_file_url": "\n".join(f"https://github.com/{repo}/blob/{commit}/{f}" for f in files),
            "harness_eval_result": "\n".join(dict.fromkeys(f["message"] for f in findings)),
            "audit_result": ("agreed" if st == "agreed" else "disagreement") + " (" + "; ".join(subs) + ")",
            "llm_review": llm,
            "counted_as_defect": counted,
            "your_verdict": "", "your_note": "",
        })
    return out


def write(rows: list[dict]) -> None:
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)
    blind_cols = [c for c in COLS if c not in ("audit_result", "llm_review", "counted_as_defect")]
    with BLIND.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=blind_cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font

        wb = Workbook()
        ws = wb.active
        ws.title = "defects"
        ws.append(COLS)
        for c in ws[1]:
            c.font = Font(bold=True)
        for r in rows:
            ws.append([r[c] for c in COLS])
        widths = {"repo": 34, "url": 40, "stratum": 11, "rule": 32, "what_the_rule_claims": 50, "harness_file": 40,
                  "harness_file_url": 50, "harness_eval_result": 60, "audit_result": 32, "llm_review": 60,
                  "counted_as_defect": 10, "your_verdict": 14, "your_note": 30}
        for i, c in enumerate(COLS, 1):
            ws.column_dimensions[ws.cell(row=1, column=i).column_letter].width = widths[c]
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
        ws.freeze_panes = "A2"
        wb.save(OUT.with_suffix(".xlsx"))
        print(f"wrote {OUT.with_suffix('.xlsx')}", file=sys.stderr)
    except ImportError:
        print("openpyxl not installed; CSV only", file=sys.stderr)
    print(f"wrote {OUT} and {BLIND} ({len(rows)} rows)", file=sys.stderr)


def _cell(text: str, limit: int = 220) -> str:
    text = " ".join(str(text).split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text.replace("|", "\\|")


def write_markdown(rows: list[dict]) -> None:
    """Render the same rows as Markdown tables, one file per rule, so they can be
    read on GitHub (the CSV is too large for GitHub's table view and has
    multi-line cells). Verdicts are still entered in the .xlsx/.csv."""
    MD_DIR.mkdir(exist_ok=True)
    for old in MD_DIR.glob("*.md"):
        old.unlink()
    by_rule: dict[str, list[dict]] = {}
    for r in rows:
        by_rule.setdefault(r["rule"], []).append(r)
    index = ["# Defect table (browsable view)", "",
             "One Markdown file per rule; each row is one (repository, rule) pair from `defects_table.csv`.",
             "Rows the audit disagreed with the scanner on (and the adjudicator ruled on) are listed first.",
             "Enter human verdicts in `defects_table.xlsx` (column `your_verdict`: `defect` / `not_defect`),",
             "then run `python3 scripts/verdict_table.py score`.", "",
             "| Rule | Pairs | Agreed | Disagreements | Counted as defect |", "|---|---:|---:|---:|---:|"]
    for rule in sorted(by_rule):
        rs = by_rule[rule]
        n_dis = sum(1 for r in rs if r["audit_result"].startswith("disagreement"))
        n_yes = sum(1 for r in rs if r["counted_as_defect"] == "yes")
        fn = rule.replace("/", "__") + ".md"
        index.append(f"| [{rule}]({fn}) | {len(rs)} | {len(rs) - n_dis} | {n_dis} | {n_yes} |")
        rs = sorted(rs, key=lambda r: (not r["audit_result"].startswith("disagreement"), r["repo"]))
        lines = [f"# {rule}", "", RULE_DEFINITIONS.get(rule, ""), "",
                 f"{len(rs)} pairs: {len(rs) - n_dis} agreed, {n_dis} disagreements, {n_yes} counted as defects.",
                 "[Back to index](README.md)", "",
                 "| # | Repository | Stratum | Harness file | harness-eval result | Audit result | LLM review | Counted |",
                 "|---:|---|---|---|---|---|---|---|"]
        for i, r in enumerate(rs, 1):
            files = r["harness_file"].split("; ") if r["harness_file"] else []
            urls = r["harness_file_url"].split("\n") if r["harness_file_url"] else []
            links = ", ".join(f"[{_cell(f, 60)}]({u})" for f, u in zip(files, urls)) or "-"
            lines.append("| " + " | ".join([
                str(i), f"[{r['repo']}]({r['url']})", r["stratum"], links,
                _cell(r["harness_eval_result"]), _cell(r["audit_result"], 120), _cell(r["llm_review"], 300),
                r["counted_as_defect"]]) + " |")
        (MD_DIR / fn).write_text("\n".join(lines) + "\n")
    index += ["", f"Total: {len(rows)} pairs."]
    (MD_DIR / "README.md").write_text("\n".join(index) + "\n")
    print(f"wrote {MD_DIR}/ ({len(by_rule)} rule files)", file=sys.stderr)


def score() -> None:
    rows = list(csv.DictReader(OUT.open(newline="")))
    pairs = []
    for r in rows:
        v = (r.get("your_verdict") or "").strip().lower().replace(" ", "_")
        if v not in ("defect", "not_defect"):
            continue
        pairs.append(("defect" if r["counted_as_defect"] == "yes" else "not_defect", v))
    n = len(pairs)
    if not n:
        print("no filled rows")
        return
    agree = sum(1 for a, b in pairs if a == b) / n
    pa_d = sum(1 for a, _ in pairs if a == "defect") / n
    pb_d = sum(1 for _, b in pairs if b == "defect") / n
    pe = pa_d * pb_d + (1 - pa_d) * (1 - pb_d)
    kappa = (agree - pe) / (1 - pe) if pe < 1 else 1.0
    res = {"n": n, "agreement": round(agree, 4), "kappa": round(kappa, 4)}
    (DATA / "defects_table_score.json").write_text(json.dumps(res, indent=1))
    print(json.dumps(res))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "score":
        score()
    else:
        rows = build()
        write(rows)
        write_markdown(rows)
