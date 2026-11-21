# Threat Model

## What this tool protects

harness-eval is a static analysis tool for AI agent setups: instruction files,
skills, commands, hooks, agents, MCP configurations and pipeline harnesses. It
auto-detects the tools a repository uses (Claude Code, Cursor, Copilot,
Gemini CLI, Codex, OpenCode, Windsurf, Cline, fullsend), builds one component
graph across them, and runs deterministic rules against it. No LLM, no network,
same answer every run.

Every rule declares its **effect** — what a finding means — and the four
commands select on that declaration:

| Command | Runs | Purpose |
|---------|------|---------|
| `harness-autonomy` | `block` + `policy` rules at gating or provisional tier | The merge decision: can this change land without a person? |
| `harness-gate` | `block` rules at gating tier | Is the configuration broken? |
| `harness-security` | `policy` + `signal` rules, security `block` rules, YARA, optional OSV lookup | What should a security reviewer read? |
| `harness-lint` | `advice` rules plus system analysis | How healthy is the setup? |

## Attacker model

The primary attacker is a **malicious or compromised component** installed into
an AI agent setup. This includes:

- Skills, commands, or hooks contributed by untrusted authors
- Third-party modules installed via package managers
- MCP server configurations pointing to attacker-controlled endpoints
- Prompt injection payloads embedded in documentation or agent instructions

The attacker has write access to one or more setup files but does not control
the host OS or the AI runtime itself.

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
|----------|-------------|----------------|
| Local files | User-authored instruction files, project config | Third-party skills, community modules |
| MCP servers | Locally configured servers | Remote endpoints, localhost proxies |
| Agent instructions | User-written system prompts | AI-generated or imported content |
| Hook scripts | Project-owned scripts | Scripts referencing external URLs or piping to shell |
| Suppressions and policy | CODEOWNERS-protected files | Files editable by any contributor |

## What it defends against

- **Credential theft**: detects references to sensitive paths (~/.ssh,
  ~/.aws/credentials), environment variables ($OPENAI_API_KEY), and taint
  flows from credential sources to network sinks
- **Data exfiltration**: flags network calls that carry file contents or
  secrets, including cross-component flows where one skill reads credentials
  and another has network access
- **Prompt injection**: identifies coercive overrides, stealth persistence
  instructions, and prompt exfiltration patterns
- **Privilege escalation**: detects permission escalation in agent instructions,
  confused deputy attacks where agents reference skills with capabilities they
  explicitly disallow
- **Obfuscation**: flags base64-encoded payloads, encoded strings, and reverse
  shell patterns
- **Supply chain risks**: validates MCP server configurations, detects
  cross-component flows through phantom MCP tool references, and scans for
  known CVEs via OSV.dev

## What it does NOT defend against

- **Runtime behavior**: the tool performs static analysis only; it cannot
  observe what an AI agent actually does at runtime
- **LLM hallucination or misuse**: if the model generates harmful output from
  benign instructions, that is outside the scope of static setup analysis
- **Network-level attacks**: man-in-the-middle, DNS hijacking, or attacks on
  the transport layer are not detectable from setup files
- **Logic bugs in user code**: the tool checks setup configuration, not
  application correctness
- **Fully trusted insiders**: if an attacker controls the entire project
  including CODEOWNERS, branch protection, and all trust-sensitive files
  described below, they can disable checks. The trust model below is designed
  to limit this — not by preventing a full project owner from disabling the
  tool, but by ensuring that **a contributor who can edit scanned files cannot
  silently suppress findings** unless the project has granted them that
  authority.

## Trust model for suppressions, baseline and policy

Three mechanisms let a user acknowledge or suppress findings. Each carries a
trust assumption about who may edit the file:

### Inline suppressions

`<!-- evaluator-ignore: rule/id -->` (file-wide) and
`<!-- evaluator-ignore-next-line: rule/id -->` (single line) suppress findings
in the file where they appear. Because the suppression lives inside the scanned
file, anyone who can edit that file can suppress its non-block findings.

**Block-effect rules ignore inline suppressions.** A scanned file cannot waive
its own blocking defects — the finding fires regardless of any
`evaluator-ignore` comment. This applies across all four commands;
`harness-autonomy` lists an inline-suppressed block finding in its blocking
output rather than hiding it.

Non-block rules (`policy`, `signal`, `advice`) remain inline-suppressible
across all commands.

**Trust assumption:** for non-block rules, inline suppressions are trusted when
the file is reviewed by a human before merge. In an auto-merge flow (ADLC),
where changes may land without human review, a contributor could add a
suppression to hide an advisory or policy finding. Projects using
`harness-autonomy` in an auto-merge policy should protect instruction files
with CODEOWNERS or equivalent review requirements so that suppression edits
require approval.

### Baseline file

`harness-eval baseline . --output .harness-eval-baseline.json` captures
current findings. Subsequent runs with `--baseline` treat baselined findings
as pre-existing and exclude them from the verdict. `harness-autonomy` counts
baselined suppressions in its `coverage` block rather than hiding them.

**Trust assumption:** the baseline file records the state of the setup at a
point in time. A contributor who can edit the baseline file can mark new
findings as pre-existing. The baseline file should be protected by CODEOWNERS
or kept outside the scanned tree so that only trusted reviewers can update it.

### Autonomy policy file

```yaml
# .harness-eval/autonomy-policy.yaml
accept:
  - rule: harness/image-unpinned
    file: harness/*.yaml
    reason: platform images float by design; tracked in SEC-42
```

The policy file tells `harness-autonomy` which `policy` findings the project
has accepted. Accepted findings appear as `waived` with the recorded reason;
they are never hidden. Only `policy` rules can be accepted — a `block` rule in
the policy file is logged as a policy-file problem and the entry is not
applied.

**Trust assumption:** the policy file is an explicit trust decision. A
contributor who can edit it can waive any policy finding, turning a
`REVIEW_REQUIRED` verdict into `PASS`. The policy file should be:

- **Kept outside the repository** (e.g., a separate config checkout or a path
  managed by the CI system such as `/opt/harness-policy/`), or
- **Protected by CODEOWNERS** so that changes require approval from a
  designated reviewer.

The README documents both approaches. Without either, an auto-merge pipeline
trusts contributors not to widen their own trust boundaries.

## Mitigations and layered defense

harness-eval is one layer in a defense-in-depth strategy:

1. **Static analysis** (this tool): catch configuration defects and trust
   boundary changes before deployment
2. **CI gating**: `harness-autonomy` provides a three-outcome verdict (PASS,
   FAIL, REVIEW_REQUIRED) for merge policies. `harness-gate` gates on
   validated block rules. `harness-security` surfaces security-relevant
   findings for human review
3. **Baseline suppression**: adopt incrementally without alert fatigue using
   `harness-eval baseline`; `harness-autonomy` reports suppressed findings in
   its coverage block
4. **Bound evidence**: JSON and SARIF output carry coverage (which rules ran,
   which did not apply and why), scan evidence (setup fingerprint, git
   revision, digests of the rule catalog, severity configuration and policy
   file), enabling audit and caching of verdicts
5. **LLM-assisted review**: optional semantic review mode for deeper analysis
   of flagged components
6. **SARIF integration**: export findings to GitHub Code Scanning for
   visibility across the team
