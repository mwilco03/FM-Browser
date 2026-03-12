# FM-Browser — Forensic Browser History Search Engine

A forensic tool that ingests browser history from forensic acquisitions (7z/zip/tar.gz archives), extracts per-visit records from Safari, Chrome, Firefox, Edge, Brave, Vivaldi, and Arc databases, classifies visits with forensic tags, and serves a searchable web interface.

## Quick Start

```bash
# 1. Install dependencies
pip install flask
sudo apt-get install p7zip-full    # or: brew install p7zip (macOS)

# 2. Run with a forensic archive
python -m history_search.server /path/to/evidence.7z --port 8888

# 3. Open browser
open http://localhost:8888
```

That's it. The pipeline extracts archives (tries passwords `infected`, `dangerous`, then none), discovers browser history databases by schema probing, classifies every visit, and serves the UI.

### Already have extracted files?

```bash
# Point at a directory instead
python -m history_search.server /path/to/extracted/files/ --port 8888
```

### Just want the server (data already ingested)?

```bash
python -m history_search.server --port 8888
```

## What It Does

```
[Archive.7z] → Extract → Discover DBs → Extract Per-Visit Records → Classify → FTS5 Index → Web UI
```

**Stage 1 — Extract**: Recursively decompresses nested archives (7z inside zip inside tar.gz, etc.)

**Stage 2 — Ingest**: Queries the actual `visits` / `history_visits` / `moz_historyvisits` tables (not summary tables) for forensically accurate per-visit records

**Stage 3 — Classify**: Runs 15 forensic classifiers on every visit:

| Tag | What It Detects |
|-----|----------------|
| `cred_in_url` | Credentials in URL (`user:pass@host`) |
| `token_in_params` | API keys, tokens, secrets in query params |
| `oauth_redirect` | OAuth callback/authorize flows |
| `cloud_storage` | Google Drive, Dropbox, S3, OneDrive, etc. |
| `paste_site` | Pastebin, transfer.sh, file.io, etc. |
| `download_url` | Executable/archive downloads (.exe, .dmg, .ps1, etc.) |
| `internal_network` | RFC1918 addresses, localhost, .local, .corp |
| `suspicious_tld` | .tk, .ml, .xyz, .top, etc. |
| `search_query` | Google/Bing/DuckDuckGo search terms |
| `non_standard_port` | URLs with ports other than 80/443 |
| `file_scheme` | file://, data:, javascript:, chrome-extension:// |
| `ip_address_host` | IP address used as hostname |
| `jwt_token` | JWT tokens in URLs |
| `b64_payload` | Base64-encoded payloads in query params |
| `encoded_long_payload` | Query strings over 2000 chars |

**Stage 4 — Index**: Inserts into SQLite FTS5 with full-text search across URLs, titles, query strings, hosts, tags, and referrer URLs.

## Web Interface

Three views:

### Search (default)
- Full-text search with FTS5 syntax (`"quoted phrases"`, `AND`, `OR`, `NOT`, `title:keyword`, `dns_host:github`)
- Filter by host, browser, visit source, OS, transition type, tag
- Click any hostname to filter, click any tag to drill down
- Expandable row detail with full provenance chain

### Explore
- Progressive aggregation builder — choose a dimension (Hosts, Browsers, Users, Tags, Timeline, etc.)
- Bar charts rendered on demand, not pre-computed
- Click any bar to drill through to Search with that filter applied
- Heatmap view (day-of-week × hour-of-day)

### Ingest
- Enter a path to an archive or directory on the server filesystem
- Re-classify button to re-run taggers on existing data

## Supported Browsers

| Browser | Engine | macOS | Windows |
|---------|--------|-------|---------|
| Chrome | Chromium | ✓ | ✓ |
| Firefox | Gecko | ✓ | ✓ |
| Safari | WebKit | ✓ | — |
| Edge | Chromium | ✓ | ✓ |
| Brave | Chromium | ✓ | ✓ |
| Vivaldi | Chromium | ✓ | ✓ |
| Arc | Chromium | ✓ | — |

All Chromium derivatives share the same `History` database schema. The engine (not the browser name) determines which SQL query runs.

## Visit Source Detection

Critical for forensics — distinguishes whether a user was physically at the keyboard:

| Source | How Detected | Confidence |
|--------|-------------|------------|
| **Local** | Chrome: `visit_source` table = 0/4 | Confirmed |
| **Synced** | Chrome: `visit_source` table = 1 | Confirmed |
| **Synced** | Firefox: Sync metadata + no `from_visit` parent + negative frecency | Likely (heuristic) |
| **Synced** | Safari: `origin` column nonzero or tombstones table present | Likely (heuristic) |
| **Extension** | Chrome: `visit_source` table = 2 | Confirmed |

In the UI, confirmed sources show a solid badge; heuristic detections show a dashed border.

## API Reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/api/search?q=...&host=...&browser=...` | Full-text search with filters |
| `GET` | `/api/visit/<id>` | Single visit detail |
| `GET` | `/api/aggregate?group_by=dns_host&limit=20` | Dynamic aggregation |
| `GET` | `/api/filters` | Available filter values for dropdowns |
| `GET` | `/api/heatmap` | Activity heatmap data |
| `POST` | `/api/ingest` | `{"path": "/path/to/archive.7z"}` |
| `POST` | `/api/reingest` | Re-classify all existing visits |
| `POST` | `/api/rebuild-fts` | Rebuild FTS5 search index |

### Aggregate endpoint examples

```
# Top 20 hosts
/api/aggregate?group_by=dns_host&limit=20

# Visits per day
/api/aggregate?group_by=time_day&limit=365

# Tags breakdown filtered to Chrome only
/api/aggregate?group_by=tags&browser=chrome

# Visit source for a specific host
/api/aggregate?group_by=visit_source&host=github.com
```

## Adding a Custom Classifier

Write one function in `history_search/pipeline/classify.py`:

```python
@classifier("my_custom_tag")
def _cls_my_tag(r: VisitRecord) -> Optional[str]:
    if "suspicious-pattern" in r.full_url:
        return "my_custom_tag"
    return None
```

Then hit the **Re-classify** button in the Ingest tab (or `POST /api/reingest`) to tag existing data.

## Project Structure

```
FM-Browser/
├── history_search/              # Main package
│   ├── server.py                # Flask app + pipeline orchestration
│   ├── pipeline/
│   │   ├── extract.py           # Stage 1: Archive extraction
│   │   ├── ingest.py            # Stage 2: Browser DB extraction
│   │   ├── classify.py          # Stage 3: Classifiers
│   │   ├── index.py             # Stage 4: FTS5 indexing
│   │   ├── models.py            # Dataclasses
│   │   ├── enums.py             # Enums
│   │   └── constants.py         # Patterns & config
│   └── static/index.html        # React SPA
├── agents/                      # Claude agent definitions
├── scripts/                     # CLI helpers
├── tests/                       # Unit tests (37 tests)
├── server.py                    # Legacy monolithic server
└── fm-browser.html              # Legacy SPA
```

## CLI Options

```
python -m history_search.server [source] [options]

positional:
  source              Archive file or directory path (optional)

options:
  --port PORT         Server port (default: 8888)
  --host HOST         Bind address (default: 127.0.0.1)
  --db DB             Index database path (default: history_index.db)
  --verbose           Debug logging
```

## Requirements

- Python 3.8+
- Flask
- p7zip-full (system package for archive extraction)
- No JavaScript build step — the SPA uses React via CDN
