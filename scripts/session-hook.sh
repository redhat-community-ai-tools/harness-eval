#!/usr/bin/env bash
# PostToolUse hook for Claude Code: runs harness-lint when agent setup files change.
# Only fires on Write/Edit of harness-relevant files; exits immediately otherwise.
#
# Install by adding to your project's .claude/settings.json:
#
#   {
#     "hooks": {
#       "PostToolUse": [
#         {
#           "matcher": "Write|Edit",
#           "command": "bash /path/to/harness-eval/scripts/session-hook.sh"
#         }
#       ]
#     }
#   }

set -euo pipefail

# The tool input is passed via TOOL_INPUT env var (JSON).
# Extract the file path from Write (file_path) or Edit (file_path) input.
FILE_PATH="${TOOL_INPUT_FILE_PATH:-}"
if [ -z "$FILE_PATH" ]; then
    # Try parsing from JSON if the direct env var isn't set
    if command -v jq &>/dev/null && [ -n "${TOOL_INPUT:-}" ]; then
        FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // empty' 2>/dev/null || true)
    fi
fi

if [ -z "$FILE_PATH" ]; then
    exit 0
fi

# Check if the changed file is a harness-relevant file
HARNESS_PATTERN='(CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.clinerules|\.windsurfrules|SKILL\.md|command\.md|\.mcp\.json|settings\.json)'
HARNESS_DIR_PATTERN='(\.claude/|\.cursor/|\.opencode/|\.codex/|\.gemini/|\.lola/|skills/|commands/)'

if ! echo "$FILE_PATH" | grep -qE "$HARNESS_PATTERN|$HARNESS_DIR_PATTERN"; then
    exit 0
fi

# Find project root (walk up to find CLAUDE.md or .claude/)
PROJECT_ROOT="$(pwd)"

# Run lint, fail-on-error only (warnings are informational during editing)
harness-eval harness-lint "$PROJECT_ROOT" --fail-on-error 2>&1 || true
