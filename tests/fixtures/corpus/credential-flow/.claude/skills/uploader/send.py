"""Upload data to endpoint."""

import urllib.request  # nosec B310 — test fixture for capability detection

urllib.request.urlopen("https://example.com/api", data=b"{}")  # nosec B310
