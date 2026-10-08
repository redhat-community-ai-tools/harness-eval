# Install

harness-eval is available as a CLI tool, a GitHub Action, a Tekton Task (OpenShift Pipelines), a Claude Code plugin, and Cursor commands. Pick whichever fits your workflow.

## CLI tool

Install from PyPI:

```bash
pip install harness-eval                # core: autonomy, gate, security, lint, rules (no LLM)
pip install harness-eval[llm]           # adds the Gemini and Anthropic SDKs for review and security --review
                                        # (--provider openai needs no extra: standard library only)
pip install harness-eval[tiktoken]      # exact token counting via tiktoken
pip install harness-eval[llm,tiktoken]  # everything
```

Run:

```bash
harness-eval harness-autonomy .                     # decidable checks for auto-merge; exit 0 PASS, 1 FAIL, 2 REVIEW_REQUIRED
harness-eval harness-autonomy . --policy policy.yaml --format json   # with a trusted policy file; JSON carries coverage + evidence
harness-eval harness-lint .                         # quality lint: advice rules + system analysis
harness-eval harness-lint . --all                   # every one of the 92 rules
harness-eval harness-lint . --rules-from-target     # also load YAML from <path>/.harness-eval/rules
harness-eval harness-lint . --watch                 # re-run automatically on file changes
harness-eval harness-lint . --fail-on-error         # exit code 1 on errors (CI gate)
harness-eval harness-lint . --fail-on-warning       # exit code 1 on any finding (strict)
harness-eval harness-lint . --format sarif          # SARIF output for GitHub code scanning
harness-eval harness-lint . --format json           # JSON output for scripts

# Resource limits on the agent-setup files a scan reads (all scanning commands)
harness-eval harness-lint . --max-total-bytes 500000000 --max-files 200000
harness-eval harness-gate .                         # validated block rules only; exits 1 on errors and warnings, no LLM
harness-eval harness-review . --provider gemini     # LLM-based rubric review (requires [llm] extra)
harness-eval harness-review . --provider openai --base-url https://llm.example/v1 --model my-model   # any OpenAI-compatible server
harness-eval harness-security .                     # policy + heuristic security rules, YARA
harness-eval harness-security . --cve               # add networked OSV vulnerability lookup
harness-eval harness-security . --review            # security scan + LLM semantic review (requires [llm] extra)
harness-eval harness-security . --fail-on-warning   # exit code 1 on any security finding
harness-eval rules                          # list all 92 rules
harness-eval rules --effect block           # list the decidable-defect rules
harness-eval rules --category security      # list security rules only
harness-eval rules --target hooks           # list rules that apply to hooks
harness-eval rules --format json            # machine-readable rule list
```

The scanner uses the same discovered-file inventory for linting, fingerprints,
and `--watch`, and parses each component once per scan. This keeps repeated
scans consistent and avoids re-reading the same setup through separate code
paths. Target YAML rules are isolated to the current scan; installed Python
rule providers are loaded only from the trusted `harness_eval.rules` entry-point
group.

For safety, scans reject oversized agent-setup files before discovery reads
them; unrelated repository content (build outputs, datasets, vendored code)
never counts. The defaults are 10 MB per file, 250 MB total, 100,000 files, and
directory depth 50. `harness-autonomy`, `harness-lint`, `harness-gate`, `harness-security`,
`harness-review`, and `baseline` all accept
`--max-file-bytes`, `--max-total-bytes`, `--max-files`, and `--max-depth`.

`harness-review` and `harness-security --review` need an LLM: `--provider gemini` (`GEMINI_API_KEY`) or `anthropic` (`ANTHROPIC_API_KEY`) with the `[llm]` extra, or `--provider openai` (`OPENAI_API_KEY`, `OPENAI_BASE_URL` or `--base-url`) against OpenAI, Azure OpenAI, vLLM, Ollama, LiteLLM or any other OpenAI-compatible server, with no extra.

Run `harness-eval doctor` to see which optional capabilities are installed and which env vars are configured.

Optional: YARA malware signature scanning for security: `pip install harness-eval[yara]`

### Suppressing false positives

Add `<!-- evaluator-ignore: rule/id -->` to any file for file-wide suppression, or `<!-- evaluator-ignore-next-line: rule/id -->` for a single line. Use `--baseline` for incremental adoption, `--exclude` to skip files, or `--enforce advisory` to report without failing CI. See the [README](../README.md#suppressing-findings) for details.

## GitHub Action

Add one file to your repo. Every PR gets security + lint checks with inline annotations on the diff.

Create `.github/workflows/harness-eval.yml`:

```yaml
name: Harness Checks
on:
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read
  pull-requests: write

jobs:
  lint-and-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: redhat-community-ai-tools/harness-eval/.github/actions/harness-eval@main
```

No API key needed. No LLM calls. Fully deterministic. Posts a summary comment on the PR showing which components were scanned, which rules ran, and pass/fail status.

### Options

```yaml
      - uses: redhat-community-ai-tools/harness-eval/.github/actions/harness-eval@main
        with:
          path: "."              # directories to scan, one per line (default: repo root)
          autonomy: "true"       # harness-autonomy: block + policy rules; fails on FAIL and REVIEW_REQUIRED
          autonomy-policy: ""    # path of a trusted policy file for harness-autonomy
          preset: "recommended"  # severity preset for lint: recommended or strict
          security-gate: "true"  # run security checks
          lint-gate: "true"      # run the quality lint (advice rules; lint-all: "true" for all 92)
          lint-fail-on: "error"  # "error" (default) or "warning" (strict)
          sarif: "true"          # inline PR annotations via Code Scanning
          comment: "true"        # post summary comment on PRs
          version: ""            # pin a specific version (default: latest)
```

### Multiple directories

For monorepos or repos with nested agent configs:

```yaml
      - uses: redhat-community-ai-tools/harness-eval/.github/actions/harness-eval@main
        with:
          path: |
            .
            internal/scaffold/agent-configs
            apps/frontend
```

### Recursive discovery

By default, harness-eval scans the repo root for agent config files (CLAUDE.md, skills, commands, hooks, MCP configs, agents). Use `--recursive` to search the entire directory tree for agent configs in nested directories. This is useful for monorepos and repos with scaffold templates.

CLI:

```bash
harness-eval harness-autonomy . --recursive
harness-eval harness-lint . --recursive
harness-eval harness-security . --recursive
```

GitHub Action:

```yaml
      - uses: redhat-community-ai-tools/harness-eval/.github/actions/harness-eval@main
        with:
          recursive: "true"
```

Directories like `.git/`, `__pycache__/`, `node_modules/`, `.venv/`, `vendor/`, `.tox/`, `worktrees/`, and `tests/fixtures/` (relative to the scan root) are automatically excluded from the recursive search.

Note: `--recursive` follows symlinks within the project directory but skips symlinks that point outside the project boundary.

### What appears on the PR

The action posts a comment showing:
- **Security checks**: pass/fail with rule count
- **Lint checks**: pass/fail with error and warning counts (warnings are non-blocking)
- **Code scanning**: SARIF upload status and finding count
- **Scanned components**: table showing which files were checked and how many rules ran on each
- **Rules by category**: table showing which rule categories ran and their results

Findings also appear as inline annotations on the PR diff via GitHub Code Scanning.

### Manual CI setup

If you prefer manual setup over the action:

```yaml
- run: pip install harness-eval
- run: harness-eval harness-security . --fail-on-warning
- run: harness-eval harness-lint . --fail-on-error
- run: harness-eval harness-lint . --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## OpenShift Pipelines (Tekton Task)

Run harness-eval as a CI gate in OpenShift Pipelines. Requires the OpenShift Pipelines operator. No image build needed; the Task installs `harness-eval` from PyPI at runtime using the standard UBI9 Python base image.

```bash
# Apply the Task and Pipeline
oc apply -f tekton/task-harness-eval.yaml
oc apply -f tekton/pipeline-harness-eval.yaml

# Run a scan
oc create -f tekton/pipelinerun-example.yaml
```

For air-gapped clusters, build from the included `Containerfile` and override the `image` parameter. See [`docs/openshift.md`](openshift.md) for full documentation including parameters and troubleshooting.

## Claude Code plugin

Install the plugin from within Claude Code:

```
/plugin marketplace add redhat-community-ai-tools/harness-eval
/plugin install harness-eval@harness-eval
/reload-plugins
```

Requires `uv` (a single standalone binary, see [astral.sh/uv](https://docs.astral.sh/uv/)). The skills use `uvx` to fetch the CLI on demand; if `uv` isn't available, `pip install harness-eval` instead.

The 5 commands appear in the `/` menu:
- `/harness-eval:harness-autonomy`
- `/harness-eval:harness-gate`
- `/harness-eval:harness-lint`
- `/harness-eval:harness-security`
- `/harness-eval:harness-review`

No API key needed for harness-autonomy/harness-gate/harness-lint/harness-security. Claude evaluates in-session for harness-review.

To update: re-run the install command. `uvx` always picks up the latest version from PyPI unless you pin it (e.g., `uvx --from harness-eval==7.13.0`).

## Cursor commands

Copy `.cursor/commands/` from [this repo](https://github.com/redhat-community-ai-tools/harness-eval) into your project. The 5 commands appear in Cursor's command palette:
- `/harness-autonomy`
- `/harness-gate`
- `/harness-lint`
- `/harness-security`
- `/harness-review`

The commands use `uvx` to fetch the CLI on demand. If `uvx` is not available in your Cursor environment, install the CLI manually first: `pip install harness-eval`.

No API key needed. Cursor evaluates in-session for harness-review.

## Pre-commit hook

Run harness-eval automatically before every commit. The hook only fires when agent setup files change (CLAUDE.md, skills/, commands/, .claude/, .mcp.json, etc.), so it adds zero overhead to commits that only touch source code.

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/redhat-community-ai-tools/harness-eval
    rev: v7.13.0  # pin to a release tag
    hooks:
      - id: harness-gate
      - id: harness-lint
      - id: harness-security  # optional: security scan
```

Always pin `rev:` to a release tag, not a branch. Update the tag when you upgrade harness-eval.

Test without installing:

```bash
pre-commit try-repo https://github.com/redhat-community-ai-tools/harness-eval harness-lint
```

## Session hook (Claude Code)

Run harness-lint automatically during a Claude Code session whenever agent setup files are edited. The hook fires on Write/Edit of harness-relevant files only, so it does not add latency to other tool calls.

Add to your project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "command": "bash -c 'FILE=\"$TOOL_INPUT_FILE_PATH\"; [[ \"$FILE\" =~ (CLAUDE\\.md|AGENTS\\.md|GEMINI\\.md|SKILL\\.md|\\.mcp\\.json|settings\\.json|\\.claude/|\\.cursor/|skills/|commands/) ]] && harness-eval harness-lint . --fail-on-error || true'"
      }
    ]
  }
}
```

To disable: remove the hook entry from `.claude/settings.json`.

For a standalone hook script with more control, see `scripts/session-hook.sh` in the harness-eval repo.
