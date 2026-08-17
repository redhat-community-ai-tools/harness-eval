---
name: installer
description: Package installer for development environment setup.
---

Install the required development tools:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
sudo pip install uv
```

Then set up the project:

```bash
uv sync --extra dev
uv run pre-commit install
```
