# Defect table (browsable view)

One Markdown file per rule; each row is one (repository, rule) pair from `defects_table.csv`.
Rows the audit disagreed with the scanner on (and the adjudicator ruled on) are listed first.
Enter human verdicts in `defects_table.xlsx` (column `your_verdict`: `defect` / `not_defect`),
then run `python3 scripts/verdict_table.py score`.

| Rule | Pairs | Agreed | Disagreements | Counted as defect |
|---|---:|---:|---:|---:|
| [agent/description-required](agent__description-required.md) | 23 | 22 | 1 | 22 |
| [agent/referenced-skills-exist](agent__referenced-skills-exist.md) | 7 | 0 | 7 | 3 |
| [claude-md/include-exists](claude-md__include-exists.md) | 23 | 0 | 23 | 11 |
| [content/allowed-tools-auto-approve](content__allowed-tools-auto-approve.md) | 121 | 121 | 0 | 121 |
| [cross/multi-assistant-drift](cross__multi-assistant-drift.md) | 71 | 0 | 71 | 29 |
| [cross/overpermissive-grants](cross__overpermissive-grants.md) | 83 | 83 | 0 | 83 |
| [frontmatter/description-required](frontmatter__description-required.md) | 4 | 4 | 0 | 4 |
| [frontmatter/format-valid](frontmatter__format-valid.md) | 78 | 78 | 0 | 78 |
| [hooks/local-settings-committed](hooks__local-settings-committed.md) | 22 | 19 | 3 | 19 |
| [mcp/cross-assistant-divergence](mcp__cross-assistant-divergence.md) | 22 | 0 | 22 | 8 |
| [mcp/endpoint-integrity](mcp__endpoint-integrity.md) | 5 | 1 | 4 | 1 |
| [mcp/unpinned-package](mcp__unpinned-package.md) | 272 | 258 | 14 | 260 |
| [mcp/valid-config](mcp__valid-config.md) | 13 | 0 | 13 | 1 |

Total: 744 pairs.
