# Scanning the Harness: study artifact

Data, scripts, and figures for *Scanning the Harness: An Empirical Study of
Supply-Chain Defects in AI Coding-Agent Configurations*. Every number in the study
regenerates from the files in this directory with the harness-eval version in this
repository (7.15.0). Paper TeX sources are not included in this tree.

## What was measured

3,171 public GitHub repositories that carry several harness files: 2,660 **setups**
(at least two component types, e.g. a context file with skills, or an MCP declaration
with settings) and 511 **collections** (five or more published skills). Every repository
is pinned to a commit; `data/repos.md` lists them with stars and a one-line description.

Thirty-one harness-eval rules were measured: rules whose condition is decidable from
the bytes of the configuration and whose consequence is a security exposure, a
configuration that cannot work as written, a departure from the Agent Skills
specification, or an inconsistency between two assistants' declarations.

## How every finding was validated

1. **Scan.** `scripts/scan.py` runs harness-eval on each repository at its pinned commit
   (`data/results.jsonl.gz`).
2. **Independent re-derivation.** `scripts/audit.py` re-clones each flagged repository and
   re-derives every finding with its own implementation of the rule's documented condition
   (`data/audit_findings.jsonl`, `data/audit_summary.json`; 8,547 findings across 1,115
   repositories).
3. **Adjudication of disagreements.** For every (repository, rule) pair on which the scanner
   and the re-derivation disagree, or whose consequence cannot be decided from bytes,
   `scripts/evidence.py` extracts the evidence and `scripts/adjudicate.py` asks a language
   model, with the prompt in the script and the API key from a local `.env`
   (see `.env.example`), for a verdict, a reason code, and a plain-language explanation
   (`data/adjudications.jsonl`). 744 pairs were re-derived; 586 agreed, 158 were adjudicated,
   640 count as defects.
4. **Independent second reading.** A separate model session, with no access to the audit or
   the adjudicator, re-read every counted pair against the repository and the current
   platform documentation (`data/defects_table_reviewed.csv`). `scripts/second_reader.py`
   scores it against the table (`data/second_reader_score.json`): 93.3% agreement, Cohen's
   kappa 0.76. Its rule-level objections were checked against the platform documentation
   and, where they held, became fixes in harness-eval 7.15.0 before the corpus was rescanned.

## Results

| | Setups | Collections |
|---|---|---|
| Repositories | 2,660 | 511 |
| Any confirmed security defect | 16.0% | 3.7% |
| Any configuration that cannot work as written | 0.8% | 0.0% |
| Any skill outside the Agent Skills specification | 2.4% | 3.5% |
| Any confirmed defect (security or cannot-work) | 16.7% | 3.7% |
| Any confirmed finding (all gating rules) | 18.4% | 6.8% |
| Raw output of the same rules before validation | 25.5% | 9.6% |

Per-rule agreement, pair counts, and adjudication outcomes are in `data/summary.json`
and `data/audit_summary.json`; `data/summary.json` holds every figure the study prints.

## Layout

| Path | Contents |
|---|---|
| `figures/` | The results figure and the values it was drawn from. |
| `data/frame.jsonl`, `data/corpus_repos.txt` | The candidate list the scan reads, and the names of the corpus repositories. |
| `data/results.jsonl.gz` | Scan output per corpus repository: pinned commit, component inventory, findings. |
| `data/manifest.jsonl`, `data/repos.md`, `data/repo_descriptions.jsonl` | Per-repository URL, commit, stratum, discovery channel, rules fired; the human-readable table. |
| `data/rule_scope.json` | Every measured rule with its analysis scope (automated pass and hand review). |
| `data/audit_findings.jsonl`, `data/audit_summary.json` | The re-derivation verdict and sub-class for every finding, and per-rule agreement. |
| `data/evidence.jsonl`, `data/evidence_all.jsonl` | The evidence extracted for the adjudicated pairs (and for every re-derived pair). |
| `data/adjudications.jsonl` | The adjudicator's verdict, reason code, and plain-language explanation per pair. |
| `data/defects_table.{csv,xlsx}`, `data/defects_table_blind.csv`, `data/defects_table/` | Every re-derived pair with the harness file, the scanner's finding, the re-derivation result, the adjudicator's review, and a column for a verdict; a blind copy; one Markdown table per rule. |
| `data/defects_table_reviewed.csv`, `data/second_reader_score.json` | The independent second reading of every pair and its agreement with the table. |
| `data/reachability.json` | The seeded samples showing granted interpreters and unpinned servers are invoked by a component. |
| `data/candidate_funnel.json` | The counts the design section prints for how the corpus was arrived at. |
| `docs/FLOW_READING.md` | The reading behind the negative result on credential-to-network flow. |
| `scripts/` | The pipeline; `make help` lists the targets. |

## Reproducing

```bash
uv sync --all-extras                # from the repository root: installs harness-eval 7.15.0
cd paper_experiments
make audit evidence                 # re-clones the flagged repositories at their pinned commits
make adjudicate                     # needs ANTHROPIC_API_KEY; resumable, skips recorded pairs
make reach analyze verdicts
```

`make standalone` and `make paper` need the TeX sources (`paper/main.tex` and generated macros). Those files are not in this tree; `analyze.py` will recreate `paper/` locally if you run it.

`make scan` rescans the corpus from scratch with the installed harness-eval; it takes about an
hour with eight workers. No third-party repository content is stored here: the artifact consists
of URLs, pinned commits, findings, and the lines of evidence behind each adjudicated pair.
