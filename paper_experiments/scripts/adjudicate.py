#!/usr/bin/env python3
"""Adjudicate findings with an LLM.

Input: data/evidence.jsonl (one record per repository and rule: the exact
lines behind the finding, extracted by scripts/evidence.py at the pinned
commit). For each record the model is asked one question, with the rule's
definition and the evidence: is this a defect the maintainer would fix, a
condition that holds but has no consequence in this repository (a test
fixture, a shipped template, a per-assistant variant, a file created at run
time), or not decidable from the evidence? Output: data/adjudications.jsonl
with verdict, reason category, a plain-language explanation, and the model used.

The API key is read from ANTHROPIC_API_KEY in the environment or a local
.env file (never committed). Records already present in the output are
skipped, so the run is resumable.

usage: adjudicate.py [--rule R] [--model M] [--limit N]
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
EVIDENCE = DATA / "evidence.jsonl"
OUT = DATA / "adjudications.jsonl"
MODEL = "claude-sonnet-5"

RULE_DEFINITIONS = {
    "mcp/unpinned-package": "An MCP server declaration runs a package (npx, uvx, pipx, docker image) with no version, tag, or digest, so the registry decides what runs on every start.",
    "cross/overpermissive-grants": "permissions.allow contains Bash(*), a bare Bash, or a wildcard grant on a command that executes arbitrary code (shells, interpreters, package runners, awk/sed/find).",
    "content/allowed-tools-auto-approve": "A skill's allowed-tools pre-approves an unrestricted shell (Bash, Bash(*), or a wildcard on an arbitrary-execution command) for whoever installs the skill.",
    "frontmatter/format-valid": "A SKILL.md has no YAML frontmatter block. The Agent Skills specification requires one with a name and a description; Claude Code still loads the file and uses the directory name and the first paragraph instead, other consumers may reject it.",
    "frontmatter/description-required": "A SKILL.md frontmatter has no description. The Agent Skills specification requires it; Claude Code uses the first paragraph of the body instead, other consumers may reject the skill.",
    "agent/description-required": "A subagent definition has no description, which the platform requires to delegate to it.",
    "agent/referenced-skills-exist": "A subagent declares a skill in its frontmatter that no directory in the repository provides.",
    "claude-md/include-exists": "A context file imports @path and the file does not exist relative to the importing file, so the runtime silently skips it.",
    "mcp/valid-config": "An MCP configuration does not parse or declares a server with no way to reach it.",
    "hooks/permission-prompt-disabled": "Committed project settings set permissions.defaultMode to a non-prompting mode (bypassPermissions, dontAsk) for everyone who opens the repository. Claude Code honoured this from project settings before v2.1.257; later versions ignore it there. enableAllProjectMcpServers only pre-approves the project's MCP servers and is reported separately as advisory.",
    "hooks/local-settings-committed": "A per-machine .claude/settings.local.json is committed, shipping one developer's approved grants to every clone.",
    "cross/multi-assistant-drift": "Two assistants' context files (CLAUDE.md, AGENTS.md, GEMINI.md) share section headings whose bodies differ: one copy was edited and the other was not.",
    "mcp/cross-assistant-divergence": "The same MCP server name is declared with a different command, arguments, or URL in two assistants' configurations.",
}

PROMPT = """You are adjudicating a static-analysis finding on a public repository's AI coding-agent configuration.

Rule: {rule}
Definition: {definition}

Repository: {repo} (commit {commit}, {stratum})
Evidence (verbatim lines from the repository):
{evidence}

Decide whether this is a defect the maintainer would fix if shown it. Answer with one JSON object and nothing else:
{{"verdict": "defect" | "not_defect" | "uncertain", "reason": "<one of: live_config, test_fixture, shipped_template, per_assistant_variant, generated_file, runtime_created_file, equivalent_declarations, documentation_copy, scoped_not_arbitrary, external_dependency, conditional_reference, other>", "explanation": "<two or three short sentences in plain, simple words: what the file actually contains, why that is or is not a problem for someone who clones this repository, written for a reader who is not an expert>"}}

Guidance: a condition inside test fixtures, benchmark corpora, or example templates is not_defect (test_fixture / shipped_template). A difference that only substitutes one assistant's name or paths for another's, or a file marked as generated from the other, is not_defect (per_assistant_variant / generated_file). An import of a file the tooling creates at run time, or one the author marked optional, is not_defect. Two declarations that resolve to the same server are equivalent_declarations. A grant scoped to a fixed subcommand is scoped_not_arbitrary."""


def main() -> None:
    argv = sys.argv[1:]
    only = argv[argv.index("--rule") + 1] if "--rule" in argv else None
    model = argv[argv.index("--model") + 1] if "--model" in argv else MODEL
    limit = int(argv[argv.index("--limit") + 1]) if "--limit" in argv else None
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key and (DATA.parent / ".env").exists():
        for line in (DATA.parent / ".env").read_text().splitlines():
            if line.startswith("ANTHROPIC_API_KEY="):
                key = line.split("=", 1)[1].strip().strip('"')
    if not key:
        sys.exit("ANTHROPIC_API_KEY not set (environment or .env)")
    import anthropic  # noqa: PLC0415

    client = anthropic.Anthropic(api_key=key)
    done = set()
    if OUT.exists():
        for line in OUT.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                done.add((r["repo"], r["rule"]))
    records = [json.loads(l) for l in EVIDENCE.read_text().splitlines() if l.strip()]
    todo = [r for r in records if (r["repo"], r["rule"]) not in done and (only is None or r["rule"] == only)]
    if limit:
        todo = todo[:limit]
    with OUT.open("a") as out:
        for i, r in enumerate(todo, 1):
            prompt = PROMPT.format(rule=r["rule"], definition=RULE_DEFINITIONS.get(r["rule"], ""), repo=r["repo"],
                                   commit=r.get("commit", ""), stratum=r.get("stratum", ""), evidence=r["evidence"])
            for attempt in range(4):
                try:
                    msg = client.messages.create(model=model, max_tokens=300, temperature=0,
                                                 messages=[{"role": "user", "content": prompt}])
                    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
                    verdict = json.loads(text[text.index("{"): text.rindex("}") + 1])
                    break
                except Exception as e:  # noqa: BLE001
                    verdict = {"verdict": "uncertain", "reason": "other", "note": f"error: {type(e).__name__}"}
                    time.sleep(2 * (attempt + 1))
            out.write(json.dumps({"repo": r["repo"], "rule": r["rule"], "commit": r.get("commit"), **verdict, "model": model}) + "\n")
            out.flush()
            if i % 25 == 0:
                print(f"  {i}/{len(todo)}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
