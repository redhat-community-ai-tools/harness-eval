# Regenerate the study behind "Scanning the Harness" from the pinned corpus.
PY ?= python3

all: classify audit evidence adjudicate reach analyze verdicts pack

scan:             ## scan the corpus (data/corpus_repos.txt) with the installed harness-eval; resumable
	$(PY) scripts/scan.py --only data/corpus_repos.txt --workers 8

classify:         ## classify every rule by analysis scope (rerun after any tool change)
	$(PY) scripts/classify_rules.py

audit: classify   ## re-derive every finding of the measured rules from fresh clones at the pinned commits
	$(PY) scripts/audit.py --per-rule 100 --exhaustive all --workers 8

evidence:         ## extract the evidence behind every disagreement (re-clones at pinned commits)
	$(PY) scripts/evidence.py && $(PY) scripts/evidence.py --all

adjudicate:       ## LLM adjudication of the disagreements (ANTHROPIC_API_KEY in the environment or .env); resumable
	$(PY) scripts/adjudicate.py

reach:            ## reachable-impact sample for grants and unpinned servers
	$(PY) scripts/reachability.py 40

analyze:          ## write data/summary.json, data/manifest.jsonl, figures, and paper macros
	$(PY) scripts/analyze.py
	@if [ -f paper/main.tex ]; then $(PY) scripts/inline_paper.py; else echo 'skip standalone: paper/main.tex not in this tree'; fi

verdicts:         ## data/defects_table.{csv,xlsx}, the per-rule Markdown view, and the second-reading score
	$(PY) scripts/verdict_table.py && $(PY) scripts/second_reader.py

repos:            ## data/repos.md, the corpus table with stars and descriptions
	$(PY) scripts/repo_table.py

standalone:       ## single-file paper (needs paper/main.tex, not in this tree)
	$(PY) scripts/inline_paper.py

pack:             ## data/results.jsonl.gz from the plain scan output
	$(PY) scripts/pack_results.py

paper:            ## compile the paper (needs acmart.cls on the TeX path or in paper/)
	cd paper && latexmk -pdf -interaction=nonstopmode -quiet main.tex

help:
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'
