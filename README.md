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
- Three search modes: **FTS5** (default), **Contains** (substring), **Regex** (Python `re`)
- Filter by host, browser, visit source, OS, transition type, tag, date range
- Exclude specific domains from results
- Click any hostname to filter, click any tag to drill down
- Expandable row detail with full provenance chain, URL unfurling, and inline string decoder
- **Export CSV** — download all matching results as CSV with current filters applied
- Sort by any column (time, host, title, URL, URL length, browser, transition, file source)

### Explore
- Progressive aggregation builder — choose a dimension (Hosts, Browsers, Users, Tags, Titles, Timeline, etc.)
- Text search input to filter all aggregation charts and heatmaps via FTS
- Bar charts rendered on demand, not pre-computed
- Click any bar to drill through to Search with that filter applied
- Heatmap view (day-of-week × hour-of-day)

### Ingest
- Enter a path to an archive or directory on the server filesystem
- Built-in file picker for browsing the server filesystem
- **Source Manager** — view all ingested sources with browser, OS, user, profile, visit count, and ingest timestamp; select and remove individual sources without clearing everything
- Re-classify button to re-run taggers on existing data
- Clear All Data for starting fresh

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
| `GET` | `/api/export?q=...&host=...` | Export matching results as CSV |
| `GET` | `/api/visit/<id>` | Single visit detail |
| `GET` | `/api/aggregate?group_by=dns_host&limit=20` | Dynamic aggregation |
| `GET` | `/api/filters` | Available filter values for dropdowns |
| `GET` | `/api/heatmap` | Activity heatmap data |
| `GET` | `/api/sources` | List all ingested sources with visit counts |
| `GET` | `/api/browse?path=/` | Browse server filesystem |
| `POST` | `/api/sources/delete` | `{"ids": [1, 3]}` — remove selected sources |
| `POST` | `/api/ingest` | `{"path": "/path/to/archive.7z"}` |
| `POST` | `/api/reingest` | Re-classify all existing visits |
| `POST` | `/api/rebuild-fts` | Rebuild FTS5 search index |
| `POST` | `/api/clear` | Wipe all visit data and ingest log |

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

# Top page titles containing "login"
/api/aggregate?group_by=title&q=login

# Hosts breakdown filtered by text search
/api/aggregate?group_by=dns_host&q=google
```

### Export examples

```
# Export all visits as CSV
/api/export

# Export only Chrome visits matching "password"
/api/export?q=password&browser=chrome

# Export date range with regex filter
/api/export?mode=regex&q=\.tk$&start=2024-01-01T00:00:00Z&end=2024-12-31T23:59:59Z
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
├── tests/                       # End-to-end tests (53 tests)
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

## Acknowledgments

This tool exists because of the extraordinary work of people and communities who build things and share them freely. We stand on the shoulders of giants, and we are grateful.

**[SQLite](https://sqlite.org/)** and its [FTS5 extension](https://www.sqlite.org/fts5.html) — D. Richard Hipp and the SQLite team have given the world the most widely deployed database engine in history, and they did it as a gift to the public domain. The fact that a single-analyst forensic tool can do full-text search across millions of browser visits with zero infrastructure is because of their decades of careful, principled engineering. The FTS5 module is a masterpiece that makes this entire project's search capability possible. Thank you.

**[Flask](https://flask.palletsprojects.com/)** — Armin Ronacher and the Pallets team created a web framework that gets out of your way and lets you ship. Flask's philosophy of simplicity and extensibility means this entire server is one readable file. The ecosystem Armin built — Werkzeug, Jinja2, Click — represents some of the most thoughtfully designed Python code ever written. Thank you.

**[React](https://react.dev/)** — Jordan Walke created React at Facebook, and the React team at Meta has continued to evolve it into one of the most transformative UI libraries ever built. The component model changed how we all think about interfaces. The fact that we can ship a single HTML file with a CDN import and build a full forensic analysis SPA is a testament to how well React was designed from the start. Thank you.

**[Babel](https://babeljs.io/)** — Sebastian McKenzie started Babel as a teenager, and the team that grew around it made modern JavaScript accessible to everyone. Babel Standalone lets us write JSX directly in the browser without a build step, which is the reason this tool has zero frontend toolchain dependencies. That design choice keeps FM-Browser simple and portable. Thank you.

**[p7zip](https://p7zip.sourceforge.net/) and [7-Zip](https://www.7-zip.org/)** — Igor Pavlov built 7-Zip and released it under LGPL, and the p7zip team ported it to POSIX systems. Forensic acquisitions often arrive as password-protected 7z archives, and this tool's ability to recursively crack into nested archives is entirely thanks to their work. Thank you.

**[IBM Plex](https://www.ibm.com/plex/) and [DM Sans](https://fonts.google.com/specimen/DM+Sans)** — Mike Abbink and Bold Monday designed IBM Plex as IBM's corporate typeface and released it to the world as open source. Colophon Foundry designed DM Sans for DeepMind. These fonts make forensic data readable and the interface clean. Beautiful typography is an act of generosity. Thank you.

**[Google Fonts](https://fonts.google.com/)** — For hosting and serving open-source typefaces to the world for free, making good typography accessible to every project regardless of budget. Thank you.

**[Cloudflare](https://cdnjs.cloudflare.com/)** — For cdnjs, the free and open-source CDN that serves React, Babel, and countless other libraries to developers worldwide. Infrastructure is invisible when it works well, and cdnjs just works. Thank you.

**The browser forensics community** — The analysts, researchers, and DFIR practitioners who documented how Chrome, Firefox, Safari, and Edge store their history data. The schemas are undocumented and change between versions. Every blog post explaining `visit_source` values, Firefox frecency scores, Safari binary timestamps, and Chromium epoch offsets made this tool's accuracy possible. Thank you.

**The Python community** — For building a standard library so comprehensive that this entire four-stage forensic pipeline — archive extraction, binary parsing, timestamp conversion, URL decomposition, regex classification, CSV export, and a web server — runs on stdlib plus one package. That's not an accident; it's the result of thirty years of thoughtful contributions from thousands of people. Thank you.

---

*If you use this tool in your work and it saves you time, consider paying it forward. Contribute to the open-source projects listed above, write up your forensic findings, share your knowledge with the community. That's how we got here.*
