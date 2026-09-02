# Report Format (Review)

## Section Order

The report must follow this exact section order:

1. What This Evaluation Checks (hardcoded intro)
2. Inventory
3. Token Budget
4. Evaluation Summary
5. Cross-Type Optimization
6. Suggestions
7. Per-Component Analysis

---

## What This Evaluation Checks

Always start the report with this exact text (hardcoded, do not modify):

```
## What This Evaluation Checks

This review combines two passes:

**Lint (deterministic)** runs 108 rules checking structure, frontmatter, token budget,
broken references, duplicate detection, security patterns (injection, credentials,
exfiltration, obfuscation, reverse shells), AST behavioral analysis, taint tracking,
MCP permission analysis, and tool poisoning detection.

**Review (qualitative)** reads every file and evaluates specificity, redundancy,
trigger quality, token efficiency, instruction clarity, content quality, and
cross-component coherence. Produces KEEP/REVIEW/REMOVE verdicts.
```

---

## Inventory

| Type | Count | Total Tokens | Errors | Warnings |
|------|-------|-------------|--------|----------|
| Skills | [N] | [N] | [N] | [N] |
| Commands | [N] | [N] | [N] | [N] |
| CLAUDE.md | [N] | [N] | [N] | [N] |
| Hooks | [N] | [N] | [N] | [N] |
| Agents | [N or 0] | [N] | [N] | [N] |
| Rules | [N or 0] | [N] | [N] | [N] |
| Output Styles | [N or 0] | [N] | [N] | [N] |

## Token Budget

  Always-loaded (CLAUDE.md, hooks): [N] tokens ([pct]%)
  On-demand (skills, commands, agents): [N] tokens ([pct]%)

  By type:
    [type]    [tokens] tokens ([pct]%)

---

## Evaluation Summary

This section comes BEFORE per-component analysis. It gives the bird's-eye view.

```
## Evaluation Summary

[one-sentence overall assessment]

Structure:   [summary]
Security:    [summary]
Coherence:   [summary]
Efficiency:  [summary]
Redundancy:  [summary]

Reviewed [N] skills, [M] commands, CLAUDE.md, [H] hooks, [A] agents, [R] rules, [O] output styles.
Total: [tokens] tokens.
Cross-type: [count]/21 checks flagged.
```

---

## Cross-Type Optimization

[All 21 checks from cross-type-checks.md, answered YES/NO with one-line explanation]

---

## Suggestions

[Numbered actionable items. Each is one line. Only recommend changes
that make a real difference.]

---

## Per-Component Analysis

For each component, provide:

### component-name                              [KEEP/REVIEW/REMOVE]
  Tokens: [N]
  Type: [skill/command/agent/claude_md/hooks/rule/output_style]

  Lint: [N] failures
    FAIL  [rule-name] — [one sentence explaining WHY it failed]
    FAIL  [rule-name] — [one sentence explaining WHY it failed]
  Or: Lint: all pass

  Qualitative Assessment:
    [2-3 sentences: what this component does, whether it adds value,
    whether it's well-built. Reference specific content.]

  Issues found:
    [category] [description] -> [suggestion]
  Or: No issues found.

For clean components with no issues, use a compact one-line format:
### component-name                              KEEP
  Tokens: [N] | Lint: all pass | [one-line assessment]

---

## Timing

At the very end:

```
Duration: [X minutes Y seconds]
```
