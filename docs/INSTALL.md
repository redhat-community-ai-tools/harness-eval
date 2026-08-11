# Install

harness-eval is available as a CLI tool, a GitHub Action, a Tekton Task (OpenShift Pipelines), a Claude Code plugin, and Cursor commands. Pick whichever fits your workflow.

## CLI tool

Install from PyPI:

```bash
pip install harness-eval                # core: lint, security scan, rules (no LLM)
pip install harness-eval[llm]           # adds LLM support for review, security --review, skill --rubric
pip install harness-eval[tiktoken]      # exact token counting via tiktoken
pip install harness-eval[llm,tiktoken]  # everything
```

Run:

```bash
harness-eval harness-lint .                         # deterministic lint (92 rules)
harness-eval harness-lint . --watch                 # re-run automatically on file changes
harness-eval harness-lint . --fail-on-error         # exit code 1 on errors (CI gate)
harness-eval harness-lint . --fail-on-warning       # exit code 1 on any finding (strict)
harness-eval harness-lint . --format sarif          # SARIF output for GitHub code scanning
harness-eval harness-lint . --format json           # JSON output for scripts
harness-eval harness-review . --provider gemini     # LLM-based rubric review (requires [llm] extra)
harness-eval harness-security .                     # deterministic security scan
harness-eval harness-security . --review            # security scan + LLM semantic review (requires [llm] extra)
harness-eval harness-security . --fail-on-warning   # exit code 1 on any security finding
harness-eval skill-review ./skills/my-skill --context . --rubric   # deep-evaluate one skill (requires [llm] extra)
harness-eval rules                          # list all 92 rules
harness-eval rules --category security      # list security rules only
harness-eval rules --target hooks           # list rules that apply to hooks
harness-eval rules --format json            # machine-readable rule list
```

`review`, `security --review`, and `skill --rubric` require the `[llm]` extra and either `GEMINI_API_KEY` or `ANTHROPIC_API_KEY`.

Run `harness-eval doctor` to see which optional capabilities are installed and which env vars are configured.

Optional: YARA malware signature scanning for security: `pip install harness-eval[yara]`

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
          preset: "recommended"  # recommended, strict, security, or pre-workflow
          security-gate: "true"  # run security checks (18 rules)
          lint-gate: "true"      # run lint checks (92 rules)
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
harness-eval harness-lint . --recursive
harness-eval harness-security . --recursive
```

GitHub Action:

```yaml
      - uses: redhat-community-ai-tools/harness-eval/.github/actions/harness-eval@main
        with:
          recursive: "true"
```

Directories like `.git/`, `__pycache__/`, `node_modules/`, `.venv/`, `vendor/`, and `.tox/` are automatically excluded from the recursive search.

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

Requires the CLI installed first (the plugin skills call it for the deterministic scan):

```bash
pip install harness-eval
```

Then install the plugin from within Claude Code:

```
/plugin marketplace add redhat-community-ai-tools/harness-eval
/plugin install harness-eval@harness-eval
/reload-plugins
```

The 5 commands appear in the `/` menu:
- `/harness-eval:harness-lint`
- `/harness-eval:harness-review`
- `/harness-eval:harness-security`
- `/harness-eval:skill-review`
- `/harness-eval:skill-verify`

No API key needed for harness-lint/harness-security/skill-verify. Claude evaluates in-session for harness-review and skill-review.

To update: re-run the install command.

## Cursor commands

Requires the CLI tool installed first (Cursor commands call it for the deterministic scan):

```bash
pip install harness-eval
```

Then copy `.cursor/commands/` from [this repo](https://github.com/redhat-community-ai-tools/harness-eval) into your project. The 5 commands appear in Cursor's command palette:
- `/harness-lint`
- `/harness-review`
- `/harness-security`
- `/skill-review`
- `/skill-verify`

No API key needed for harness-review/harness-security/skill-review. Cursor evaluates in-session.
