# Rule taxonomy

Every rule is classified on two independent axes: its **evidence class** (how
trustworthy a finding is) and its **analysis scope** (how much of the setup the
rule must see). The axes are recorded on `RuleMeta` (`tier` and `scope`) and are
the single source of truth; the tables in [`rules-reference.md`](rules-reference.md)
and the README are generated from them by `scripts/gen_rules_reference.py`.

## Axis 1: evidence class (tier)

A rule's evidence is either **structural** or **heuristic**.

- **Structural rules** are decidable from the files themselves. "This `.mcp.json`
  pins no version", "this referenced file does not exist on disk", "these two
  `allow` grants contradict a `deny`" are facts, not opinions. A structural rule
  can be promoted to a validated tier once the corpus study shows it is right in
  practice, or placed at gating when the condition is a filesystem or parse fact
  (missing file, duplicate JSON key, committed secret-named file, broken
  `@import`) rather than a precision estimate.
- **Heuristic rules** are judgments about prose: whether a description is vague,
  whether guidance is redundant, whether an instruction hedges. There is no
  ground truth in the file, only a signal, so heuristic rules are **always
  advisory** and never gate.

Structural rules carry one of three tiers:

- **gating** — safe to block a build on. `harness-gate` runs exactly this set.
  Two ways in: corpus-validated at **>=97% precision on >=50 re-derived
  findings** plus a consequence review, or a decidable FILE/FILE_FS integrity
  check whose finding is a fact about the tree.
- **provisional** — zero false positives observed on the corpus, but on fewer
  than 50 findings, so precision is not yet established at the gating bar. Run
  them with `harness-gate --include-provisional` when you want an early signal.
- **advisory** — everything else, including every heuristic rule. Reported, never
  gated.

The gating and provisional sets are pinned by `tests/test_rule_taxonomy.py`, so a
tier change is a deliberate, reviewed edit.

## Axis 2: analysis scope

Scope records how much context a rule needs. It is what a per-file linter
fundamentally cannot fake.

| Scope | Needs | Example |
|-------|-------|---------|
| `FILE` | One component's text or one settings/MCP file | `mcp/unpinned-package` reads a single `.mcp.json` server spec. |
| `FILE_FS` | That file **plus** the filesystem around it | `claude-md/include-exists` resolves an `@import` and checks the target exists on disk. |
| `PAIRWISE` | **Two** components compared against each other | `content/duplicate-detection` flags two skills that are near-copies. |
| `SETUP` | The **whole** component graph or an aggregate | `content/orphan-skills` needs every reference edge in the setup to know a skill is unreferenced. |

A per-file scanner sees one file at a time with no memory of the others, so it
can decide `FILE` and `FILE_FS` rules but is **structurally blind to `PAIRWISE`
and `SETUP` classes**: it can never notice that two skills duplicate each other,
that a skill is orphaned, or that a credential flows from one component to a
network sink in another, because those findings only exist in the relationships
*between* files. Building the cross-component graph is the reason harness-eval
exists.

## Promotion criteria

A structural rule that needs corpus evidence is promoted to **gating** when the
validation pipeline in the `harness-eval-experiments` repository shows both:

1. **>=97% precision on >=50 re-derived findings** — each candidate finding is
   independently re-derived at the repository's pinned commit by a check written
   without reference to the rule's implementation, and at least 50 such findings
   confirm at 97% or better.
2. **A consequence review** — the confirmed findings represent real problems
   (broken portability, a committed secret, a dead grant), not technically-true
   trivia.

Rules that clear the precision bar but on too few findings sit at **provisional**
until enough evidence accumulates. Decidable integrity checks (missing file,
duplicate JSON key, committed secret, broken import) may also sit at **gating**
without waiting on that sample size. Rules whose evidence is linguistic never
leave **advisory**.
