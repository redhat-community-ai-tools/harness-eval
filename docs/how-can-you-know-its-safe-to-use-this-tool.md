# How Can You Know It's Safe to Use This Tool?

The Claude Code plugin marketplace is still young. There's no centralized vetting process, no mandatory code review, and no standard security baseline for plugins. Anyone can publish a plugin, and most users install them without a second thought. The reality is that plugins can read your files, run commands, and send data over the network. That makes the marketplace a potential vector for malware, data exfiltration, and supply chain attacks.

We don't think that's acceptable, especially for a tool like harness-eval that reads and analyzes your entire agent setup. So we've invested in making this plugin as safe and transparent as we can. Here's what we did and why.

## What the tool can and can't access

harness-eval reads files inside the project directory you point it at. That's it. It uses path traversal protection (resolving symlinks, blocking `../` escapes) to make sure it never reads files outside your project boundary. It can't access your SSH keys, your cloud credentials, or files in other directories. If a malicious skill inside the project you're scanning tries to trick the tool into reading `/etc/passwd` or `~/.ssh/id_rsa`, the request is rejected.

## What data goes where

Not all commands behave the same way:

| Command | Sends data externally? | Where |
|---------|----------------------|-------|
| `lint` | No. Fully offline. | Nowhere |
| `review` | Yes (CLI only) | Gemini or Anthropic API (your choice) |
| `security` | Scan: No. With `--review`: Yes (CLI only) | Gemini or Anthropic API |
| `skill` | Lint: No. With `--rubric`: Yes (CLI only) | Gemini or Anthropic API |

When used as a Claude Code plugin, review and security commands run inside your existing Claude session. No additional API calls are made. The same applies when used as Cursor commands.

The lint command never contacts any external service. You can run it air-gapped.

## How the code is protected

Every change to this tool goes through multiple layers of protection before it reaches you:

- **Two reviewers required.** Every pull request needs approval from two maintainers before it can merge to the main branch.
- **CI must pass.** Four automated checks (linting, type checking, tests, and a self-scan where the tool evaluates itself) must all pass before any merge.
- **No direct pushes.** Nobody can push code directly to the main branch, not even maintainers. Everything goes through a pull request.
- **Force pushes blocked.** History can't be rewritten on the main branch.
- **Release tags are restricted.** Only designated maintainers can create version tags that trigger a PyPI release. A compromised contributor account can't publish a malicious version.
- **Trusted Publishing.** PyPI releases use OpenID Connect tokens (no long-lived API keys). The publishing workflow can only run from the official GitHub repository.

## How we catch problems early

Before code even reaches a pull request, developers run pre-commit hooks that check for:

- **Hardcoded secrets** (gitleaks) - catches API keys, tokens, passwords, and private keys before they enter the repository
- **Python security issues** (bandit) - static analysis that flags dangerous patterns like unsafe deserialization, shell injection, and weak cryptography

These run automatically on every commit. If they find something, the commit is blocked.

## What happens if something goes wrong

We have a documented incident response plan in [SECURITY.md](../SECURITY.md). If a compromise is ever detected, we follow a 6-step process:

1. **Contain** - revoke compromised credentials, lock the repository, disable publishing
2. **Assess** - identify affected releases and determine the attack vector
3. **Yank** - remove compromised versions from PyPI and the plugin marketplace
4. **Notify** - create a GitHub Security Advisory and notify users with clear instructions
5. **Remediate** - fix the vulnerability, rotate all credentials, release a patched version
6. **Post-mortem** - document what happened and what we'll do to prevent it in the future

If you find a security issue, please report it to bkapner@redhat.com or csoceanu@redhat.com.

## The bottom line

We can't guarantee that every plugin in the marketplace is safe. But we can guarantee that we take the security of this one seriously. Every change is reviewed, tested, and gated. Every release is traceable. And if something ever goes wrong, we have a plan to handle it.
