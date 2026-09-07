#!/usr/bin/env python3
"""Write data/results.jsonl.gz with the analyzed corpus only (setups and
collections, one record per pinned commit). The plain results.jsonl that
scan.py writes holds every candidate and is not committed."""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze import corpus, read_results  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"
recs = corpus(read_results())
with gzip.open(DATA / "results.jsonl.gz", "wt", encoding="utf-8") as f:
    for r in recs:
        f.write(json.dumps(r) + "\n")
print(f"packed {len(recs)} corpus records", file=sys.stderr)
