# CyberNews Auto

> **Live dashboard:** TODO — add GitHub Pages URL
> **API docs:** TODO — add deployed `/docs` URL

CyberNews Auto is a self-hostable cyber threat-intelligence platform. It combines an automated **ingestion pipeline** (trusted cybersecurity RSS feeds → LLM extraction → structured intel), a **CVE risk-scoring engine** (NVD CVSS + CISA KEV + FIRST EPSS collapsed into a single 0–100 priority score), a **read-only REST API** over the collected data, and a **dependency-free live dashboard** for search, analytics, and an interactive threat graph — all backed by plain JSON databases with crash-safe atomic writes.

It watches trusted cybersecurity RSS feeds, uses an LLM to summarize and classify new stories, enriches CVE-based stories with NVD CVSS, CISA KEV, and FIRST EPSS data, scores and persists each item to JSON databases for dashboard views and persistent entity tracking, and can optionally distribute a threat-card image to X.

The project is designed to run on a schedule through GitHub Actions, while also supporting local runs for development and debugging.

## Features

- Pulls cybersecurity articles from RSS feeds such as The Hacker News, BleepingComputer, Dark Reading, CyberScoop, and Krebs on Security.
- Filters out old articles and previously posted URLs.
- Uses Groq LLaMA to extract severity, CVE, affected target, threat actor, tweet text, card summary, and a plain-English explanation. Extraction is hardened with Pydantic schema validation, retries with exponential backoff, and automatic fallback to a second model.
- Validates CVE IDs before enrichment to avoid posting placeholder or invented CVEs.
- Looks up CVSS scores from the NVD API, KEV (Known Exploited Vulnerabilities) status from CISA, and EPSS (Exploit Prediction Scoring System) metrics.
- Tracks vulnerability lifecycles and threat actor campaigns persistently in `vulnerabilities.json` and `actors.json`.
- Uses exact-match CVE deduplication to only tweet about an existing CVE if its threat status escalates (e.g., Disclosed -> Actively Exploited).
- Persists a scored feed record for every processed item, so the dashboard and API stay populated whether or not distribution is enabled.
- Optional X/Twitter distribution (disabled by default via `POST_TO_X`) — generates a shareable threat-card PNG and posts one link-free item per run. When enabled, the prompt forbids URLs and a `strip_links` safety net removes any the model slips in (X bills link posts at a higher rate); dotted technical terms (e.g. `Node.js`, `asp.net`, `.io`) and the CVSS/EPSS suffix are preserved.
- Provides a dynamic Streamlit dashboard and a highly customized static HTML dashboard with KEV/EPSS visual badges.
- Includes an instant intel-search bar on the static dashboard: type a CVE ID, threat actor, malware family, or vendor and get a rendered dossier (CVSS/EPSS/KEV metrics, lifecycle timeline, campaign history, and related feed items) generated client-side from the existing JSON databases.
- Sends optional crash alerts to Discord.

## Project Structure

```text
.
|-- .github/workflows/ingest.yml       # Scheduled GitHub Actions ingestion workflow
|-- .github/workflows/tests.yml        # CI: runs the unit tests on push / PR
|-- cyber_agent.py                     # Staged pipeline: ingest, dedup, extract, enrich, score, persist, distribute
|-- entity_model.py                    # Entity lifecycle tracking and exact deduplication logic
|-- scoring.py                         # Risk-prioritization model (CVSS + EPSS + KEV + recency)
|-- semantic.py                        # Dependency-free TF-IDF cosine near-duplicate detection
|-- api.py                             # Read-only FastAPI service over the JSON data
|-- guardrails.py                      # Input-sanitation layer for the API (injection/abuse screening)
|-- requirements-api.txt               # API-only dependencies (kept out of the lean bot runtime)
|-- render.yaml                        # One-click free deploy of the API to Render
|-- tests/                             # pytest unit suite (engine logic, persistence, scoring, API)
|-- dashboard.py                       # Streamlit dashboard for local analytics
|-- index.html                         # Static browser dashboard powered by database.json
|-- database.json                      # Posted threat feed used by dashboards
|-- vulnerabilities.json               # Relational entity database tracking CVE lifecycles
|-- actors.json                        # Relational entity database tracking threat actor campaigns
|-- posted_urls.txt                    # URL history used to avoid duplicate posts
|-- requirements.txt                   # Python dependencies
|-- Roboto-Bold.ttf                    # Font used for threat-card image generation
`-- Roboto-Medium.ttf                  # Font used for threat-card image generation
```

## Requirements

- Python 3.10 or newer
- A Groq API key
- Optional X API credentials with permission to create posts and upload media (only if `POST_TO_X=true`)
- Optional Discord webhook URL for crash alerts
- Optional GitHub repository secrets if running through GitHub Actions

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Environment Variables

The pipeline reads credentials from environment variables:

```text
GROQ_API_KEY
POST_TO_X
X_API_KEY
X_API_SECRET
X_ACCESS_TOKEN
X_ACCESS_TOKEN_SECRET
DISCORD_WEBHOOK_URL
```

`GROQ_API_KEY` is the only required value — the ingestion, enrichment, scoring,
and persistence pipeline runs on it alone.

`POST_TO_X` gates the optional X/Twitter distribution and **defaults to
`false`**. The `X_API_KEY` / `X_API_SECRET` / `X_ACCESS_TOKEN` /
`X_ACCESS_TOKEN_SECRET` credentials are only needed when `POST_TO_X=true`; with
distribution off they can be left unset.

`DISCORD_WEBHOOK_URL` is optional (crash alerts only).

Do not hardcode real API credentials in source files. Use local environment variables for development and GitHub Actions secrets for deployment.

## Local Setup

1. Clone or open the project folder.

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Set the required environment variables.

   PowerShell example:

   ```powershell
   $env:GROQ_API_KEY="your_groq_key"
   $env:X_API_KEY="your_x_api_key"
   $env:X_API_SECRET="your_x_api_secret"
   $env:X_ACCESS_TOKEN="your_x_access_token"
   $env:X_ACCESS_TOKEN_SECRET="your_x_access_token_secret"
   $env:DISCORD_WEBHOOK_URL="your_discord_webhook_url"
   ```

4. Run the agent:

   ```bash
   python cyber_agent.py
   ```

The agent posts at most one tweet per run. It exits after successfully processing and posting one eligible article.

## Running the Dashboards

### Static Dashboard

The static dashboard is `index.html`. It fetches `database.json` from the same directory and refreshes every five minutes. It includes visual pulse-badges for actively exploited vulnerabilities.

At the top of the page is an **intel-search bar**. Typing a query (for example `CVE-2026-4020`, `Sapphire Sleet`, `ransomware`, or `WordPress`) searches across `database.json`, `vulnerabilities.json`, and `actors.json` and renders an intelligence report in place:

- **CVE matches** produce a vulnerability dossier with CVSS, EPSS, KEV, an event count, and the full lifecycle timeline.
- **Threat-actor matches** produce an actor dossier with aliases, first-seen date, and campaign history.
- **Keyword matches** also list related items from the live feed.

The search runs entirely client-side against the already-published JSON, so it works on GitHub Pages with no backend and no exposed API keys.

Every report is **shareable**: the URL hash reflects the current view (`#q=CVE-2026-4020`, `#analytics`, `#graph`, …), so a link opens straight to that report or tab and the browser's back/forward buttons work. Each report has a **Copy link** button and an **Export PDF** button (a dependency-free print stylesheet that isolates the report and preserves the dark theme).

The dashboard also has an **Analytics** tab with custom, dependency-free SVG charts computed live in the browser: threats over time, a severity-distribution donut, risk-priority bands, top targeted products, and the most active threat actors. Like the search, it reads the existing JSON — no chart library, no backend.

A **Threat Graph** tab renders an interactive, force-directed network (also hand-rolled, no library) linking threat actors, CVEs, and their targets/products. CVE nodes are sized and colored by risk score; hovering highlights a node's connections, dragging repositions nodes, and clicking an actor or CVE opens its dossier via the intel search.

The dashboard prefers the **live REST API** (`api.py`, deployed) for its data
and transparently falls back to the static JSON snapshot if the API is
unreachable (cold free-tier instance, offline, or local dev). A small badge in
the refresh bar shows which source is in use (`● live API` / `● cached
snapshot`). Set `API_BASE = ''` in `index.html` to force static-only mode.

For best results, serve the folder with a local HTTP server:

```bash
python -m http.server 8000
```

Then open:

```text
http://localhost:8000/index.html
```

### Streamlit Dashboard

Run:

```bash
streamlit run dashboard.py
```

The Streamlit dashboard reads `database.json`, shows threat counts, severity distribution, a KEV active-exploit metric, and a searchable threat feed.

## Architecture

The agent runs as an explicit, stage-based pipeline rather than one monolithic
loop. Each candidate article flows through:

```text
Ingest → Dedup/Filter → Extract (LLM) → Enrich (NVD/KEV/EPSS) → Score → Persist → Distribute
```

These map to discrete, individually testable functions in `cyber_agent.py`
(`parse_article`, `pre_llm_skip_reason`, `generate_content`, `enrich_cve`,
`severity_from_cvss` / `build_score_str` / `inject_score`, the entity upserts,
and `process_article`), orchestrated by `run_agent()`. Each run emits a
`RunStats` summary (feeds scanned, articles seen, posted, and skip reasons).

Persistence is crash-safe: all JSON databases are written atomically
(temp file + `os.replace`), so an interrupted run can never corrupt
`database.json`, `vulnerabilities.json`, or `actors.json`.

### Risk prioritization score

`scoring.py` collapses the verified enrichment signals into a single 0-100
**priority score**, mirroring how vulnerability-management programs decide what
to patch first:

| Signal | Weight | Rationale |
|---|---|---|
| CVSS base score | 35 | technical severity |
| EPSS | 30 | probability of exploitation |
| CISA KEV | 25 | confirmed active exploitation |
| Recency | 10 | urgency decays over 30 days |

KEV (actively-exploited) items are floored at 85 so they always rank near the
top, and a missing CVSS is not penalized — its weight is redistributed across
the remaining signals. The score (and its band: critical / high / medium / low)
is persisted on each `vulnerabilities.json` entry and each `database.json`
feed record. The dashboard mirrors the identical formula in
`index.html` (`computeRiskScore`) so engine and UI always agree, and uses it
to rank the vulnerability tracker and headline the CVE dossier.

## Testing

Unit tests live in `tests/` and cover the deterministic, network-free parts of
the engine: deduplication, CVE validation, severity scoring, tweet composition,
atomic writes, and the entity-upsert lifecycle. The network-bound stages (Groq,
NVD, KEV, EPSS, X) are not exercised.

Run them locally:

```bash
pip install -r requirements.txt
pytest -q
```

CI runs the same suite on every push and pull request via
`.github/workflows/tests.yml`.

## REST API

`api.py` is a read-only [FastAPI](https://fastapi.tiangolo.com/) service that
exposes the same threat-intelligence data over HTTP. It is stateless — it reads
`database.json` / `vulnerabilities.json` / `actors.json` and reuses `scoring.py`,
so risk scores match the engine and dashboard exactly. No database required.

Run it locally:

```bash
pip install -r requirements-api.txt
uvicorn api:app --reload
```

Interactive OpenAPI docs are served at `http://127.0.0.1:8000/docs`.

### Endpoints

| Method & path | Description |
|---|---|
| `GET /health` | Service status + record counts |
| `GET /api/cves` | List CVEs; filters: `kev`, `min_risk`, `status`; `sort=risk\|recent`; `limit`/`offset` |
| `GET /api/cves/{cve_id}` | Single CVE dossier (case-insensitive; 404 if unknown) |
| `GET /api/actors` | List threat actors; `sort=campaigns\|recent`; pagination |
| `GET /api/actors/{name}` | Single actor by name or alias (404 if unknown) |
| `GET /api/feed` | Live feed, newest first; `kev` filter; pagination |
| `GET /api/search?q=` | Unified search across CVEs, actors, and feed |
| `GET /api/stats` | Summary analytics (totals, severity & risk-band breakdowns, top products/actors) |

Responses use typed Pydantic models, so the data is self-documenting in `/docs`.

### Security & operational guardrails

The API is built to behave like a real intelligence feed, not just an open dump:

- **Input validation & guardrails** — query params are constrained by Pydantic
  (types, ranges, max length), and free-text inputs pass through a
  sanitation layer (`guardrails.py`) that rejects prompt-injection, code/script,
  SQL-style, and path-traversal payloads with a `400` before they reach the
  engine. (Defense-in-depth: the API is read-only and doesn't feed input to the
  LLM today, but the path is screened in case it ever does.)
- **Rate limiting** — IP-based via `slowapi` (default `60/minute`, configurable),
  returning `429` on abuse. Health/meta routes are exempt.
- **Response caching** — an in-memory TTL cache (default 60s) serves popular
  queries (CVE lookups, search, stats) without recomputation. Swap for Redis if
  the service is ever scaled across multiple instances.
- **Optional API-key auth** — set `API_KEYS` to require an `X-API-Key` header on
  the `/api/*` routes (the `Authorize` button appears in `/docs`). Left unset,
  the API is open for the public demo. `/health` stays public either way.

Configuration (all optional, via environment variables):

| Variable | Default | Purpose |
|---|---|---|
| `API_KEYS` | _(unset → open)_ | Comma-separated valid API keys |
| `API_RATE_LIMIT` | `60/minute` | slowapi limit string |
| `API_CACHE_TTL` | `60` | Response cache TTL in seconds |
| `DATA_DIR` | repo root | Where the JSON data lives |

### Deploying the API (free)

`render.yaml` is a Render Blueprint. On [render.com](https://render.com): **New →
Blueprint →** connect this repo. Render runs
`uvicorn api:app --host 0.0.0.0 --port $PORT` and health-checks `/health`. No
environment variables are required. (The free tier sleeps when idle and
cold-starts on the next request.)

## GitHub Actions Deployment

The workflow in `.github/workflows/ingest.yml` runs once daily at 06:14 UTC:

```yaml
cron: '14 6 * * *'
```

It:

1. Checks out the repository.
2. Installs Python 3.10 and dependencies.
3. Runs `python cyber_agent.py` (ingest → enrich → score → persist).
4. Commits updates to `posted_urls.txt`, `database.json`, `vulnerabilities.json`, and `actors.json`.

Add these repository secrets before enabling the workflow:

```text
GROQ_API_KEY
DISCORD_WEBHOOK_URL
```

`DISCORD_WEBHOOK_URL` can be omitted if you do not want Discord crash
notifications. The workflow no longer sets the `X_*` secrets, since X
distribution is disabled by default (`POST_TO_X`). To re-enable posting from CI,
set `POST_TO_X: 'true'` and add the `X_API_KEY` / `X_API_SECRET` /
`X_ACCESS_TOKEN` / `X_ACCESS_TOKEN_SECRET` secrets back to the workflow's `env`
block.

## How the Agent Works

1. Checks the daily post count in `database.json`.
2. Stops if the daily cap has already been reached.
3. Shuffles the RSS feed list.
4. Skips articles already present in `posted_urls.txt`.
5. Skips articles older than the configured maximum age.
6. Performs layered deduplication against recent history: exact URL match, a fast title-keyword/entity overlap check (24h general, 7-day for CVEs and named entities), and a TF-IDF cosine similarity fallback (`semantic.py`) that catches reworded headlines across sources within the 7-day window.
7. Sends the article title and summary to Groq for structured JSON extraction, validated against a Pydantic schema with retries/backoff and a fallback model.
8. Rejects invalid CVE placeholders.
9. Performs an exact-CVE deduplication check against `vulnerabilities.json` to only proceed if the threat status has meaningfully escalated.
10. Looks up CVSS from NVD, KEV status from CISA, and EPSS scores from FIRST.org.
11. Upserts the extracted threat and actor into `vulnerabilities.json` and `actors.json`.
12. Saves the article URL and dashboard records (`database.json`).
13. _(Optional, only when `POST_TO_X=true`)_ Generates a threat-card image and posts the tweet and image to X.
14. Exits after one successfully processed article.

## Data Files

### `posted_urls.txt`

Stores one article URL per line. This prevents duplicate posts across scheduled runs.

### `database.json`

Stores dashboard records for the social feed. Current records use this shape:

```json
{
  "date": "2026-05-05 06:51 UTC",
  "content": "Tweet or threat text",
  "url": "https://example.com/article",
  "cve": "CVE-2026-1234",
  "kev": true,
  "epss": 0.03,
  "risk_score": 91,
  "risk_band": "critical"
}
```

### `vulnerabilities.json`

A relational database keyed by CVE ID tracking the lifecycle of specific vulnerabilities. Fields include `first_seen`, `cvss`, `kev`, `epss`, and a `status_timeline` tracking transitions from "disclosed" to "actively_exploited" to "patched".

### `actors.json`

A relational database keyed by threat actor/group name, tracking aliases and historical campaigns extracted from news sources.

## Security Notes

- Rotate any API keys that were ever committed to the repository.
- Do not commit real credentials.
- Keep local secrets in environment variables or an untracked `.env` file.
- Store production secrets in GitHub Actions repository secrets.
- Review generated LLM content before increasing automation scope or posting frequency.

## Troubleshooting

### The bot finds no articles

- Check that the RSS feeds are reachable.
- Confirm articles are newer than `ARTICLE_MAX_AGE_HOURS`.
- Check `posted_urls.txt`; the article may already have been posted.

### Groq fails

- Confirm `GROQ_API_KEY` is set.
- Check account quota and model availability.
- Inspect the workflow logs or terminal output for JSON parsing errors.

### X posting fails

- Confirm all X credentials are set.
- Confirm the app has write permissions.
- Check whether the generated tweet exceeds platform limits after CVSS injection.

### Dashboard shows no data

- Confirm `database.json` exists and contains a JSON array.
- If using `index.html`, serve the folder over HTTP instead of opening the file directly.
- If using Streamlit, run from the project root so `database.json` resolves correctly.
