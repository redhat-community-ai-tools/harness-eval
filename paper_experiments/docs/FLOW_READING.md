# Cross-component flow candidates: hand reading (run on harness-eval 7.15.0)

`security/cross-component-flow` fired on 5 repositories in the 5,928-repository
corpus. Each was re-cloned at its pinned commit and read. Verdict for the paper: no confirmed
credential-to-network exfiltration path in the corpus.

| Repository (commit in manifest) | Source -> target | Credential read | Network capability | Reading |
|---|---|---|---|---|
| whit3rabbit/rabbit-writes | rabbit-reads -> rabbit-writes | none; the match was `estimate_tokens` (token counting) | `urllib.request` to a configured LLM endpoint | refuted: no credential access |
| tradermonty/claude-trading-skills | signal-postmortem -> vcp-screener | `FMP_API_KEY` from the environment | `requests.get` to the FMP market-data API | refuted: the key is sent to the API it authenticates; same author, intended use; no invocation edge in SKILL.md |
| OpenSenseNova/SenseNova-Skills | sn-ppt-entry -> sn-image-base (and siblings) | `SN_API_KEY` etc. from a project `.env` | `httpx` to image-generation APIs | refuted: keys are sent to the vendor APIs they belong to; no invocation edge in SKILL.md |
| aklofas/kicad-happy | kicad -> spice | `DIGIKEY_CLIENT_ID` and sibling distributor keys from the environment | `spice_spec_fetcher.py` queries the DigiKey, Mouser, LCSC, element14 APIs | refuted: each key is sent to the distributor API that issued it; same author; the handoff to `spice` is an instruction to run a simulation, not a data hand-over |
| zytedata/claude-skills | scrape-scrapy-cloud, scrape-zyte-api-stats -> scrape-zyte-login | `SHUB_APIKEY` / `ZYTE_API_KEY` from `.env` or `~/.scrapinghub.yml` | `scrapy_cloud_api.py` calls the Zyte / Scrapy Cloud API | refuted: the key is the vendor's own credential sent to the vendor's API; the delegation is a login prompt when the key is missing |

The rule's predicate (credential capability in one component, network
capability in a delegated-to component) held in four of five cases; the
consequence (data crossing to a party the credential was not issued for) held
in none. The class stays advisory and is reported as a validated negative.
