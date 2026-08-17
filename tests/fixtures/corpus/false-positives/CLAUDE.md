# Project Setup

## Installation

Install system dependencies:

```bash
sudo apt-get install -y curl wget git
sudo tar xf archive.tar.gz -C /opt
sudo ln -sf /opt/bin/tool /usr/local/bin/tool
sudo systemctl restart myservice
sudo cp config.conf /etc/myapp/
```

## Paths

- Transcripts are saved to `.transcripts/run-<id>/conversation.jsonl`
- User config lives at `$HOME/.config/app/settings.json`
- Project data is at `${PROJECT_ROOT}/data/output.csv`
- Logs go to `$LOG_DIR/app.log`

## Development

Use the installer skill to set up the development environment.
