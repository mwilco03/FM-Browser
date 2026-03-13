# Code Map

A guide for contributors. Find the right file for what you want to change.

## "I want to..."

| I want to... | Look in | Key area |
|--------------|---------|----------|
| Add a new forensic classifier/tag | `pipeline/classify.py` | Add a `@classifier("tag_name")` function (~line 556) |
| Support a new browser | `pipeline/enums.py`, `pipeline/constants.py`, `pipeline/ingest.py` | Add enum, path patterns, extractor function |
| Support a new archive format | `pipeline/extract.py` | Add extractor function, call from `_extract_single()` |
| Add a new API endpoint | `server.py` | Add `@app.route` function after existing endpoints |
| Add a search filter | `server.py` (`FILTER_COLUMNS`), `static/index.html` (SearchView) | Add column mapping and UI control |
| Add a column to the visits table | `pipeline/models.py`, `pipeline/index.py`, `pipeline/ingest.py` | Add field, update schema DDL, update extractor |
| Change how URLs are parsed | `pipeline/classify.py` | Edit `decompose_url()` or `unfurl_url()` |
| Change timestamp conversion | `pipeline/ingest.py`, `pipeline/constants.py` | Edit `_chrome_time_to_utc()` etc., epoch constants |
| Add a chart to Explore | `static/index.html` | Add to `DIMENSIONS` array, create chart component |
| Change the search results table | `static/index.html` | Edit SearchView component (~line 634) |
| Change visit source detection | `pipeline/ingest.py` | Edit heuristics in `extract_gecko()` or `extract_webkit()` |
| Add patterns (cloud hosts, TLDs, etc.) | `pipeline/constants.py` | Edit the relevant regex/list |
| Change archive passwords | `pipeline/constants.py` | Edit `ARCHIVE_PASSWORDS` |
| Modify the FTS5 index | `pipeline/index.py` | Edit `FTS_COLUMNS` and `SCHEMA_DDL` |
| Add an Explore dimension | `static/index.html` | Add to `DIMENSIONS` array (~line 751) |
| Manage ingested sources | `server.py` (`api_sources`, `api_sources_delete`) | Endpoints for listing/removing sources |

## Architecture

```
[Archive] --> Stage 1: Extract --> Stage 2: Ingest --> Stage 3: Classify --> Stage 4: Index --> [Flask SPA]
               extract.py           ingest.py           classify.py           index.py         server.py
```

Four stages, each independently testable. Data flows through as `VisitRecord` dataclasses defined in `models.py`.

## File Reference

### `history_search/server.py`

Flask app, all API endpoints, and pipeline orchestration.

| Function | Line | What it does |
|----------|------|-------------|
| `run_pipeline()` | ~87 | Orchestrates extract, ingest, classify, index |
| `require_token()` | ~61 | Auth decorator for mutating endpoints |
| `_build_where()` | ~230 | Builds SQL WHERE from filter params |
| `_get_filters()` | ~288 | Extracts filter params from request |
| `api_search()` | ~319 | FTS5/contains/regex search with pagination |
| `api_export()` | ~408 | Streaming CSV export (same filters as search) |
| `api_aggregate()` | ~507 | Dynamic grouping by any dimension |
| `api_heatmap()` | ~616 | Day-of-week x hour activity matrix |
| `api_sources()` | ~682 | List ingested sources with live counts |
| `api_sources_delete()` | ~697 | Remove sources by ingest_log ID |
| `api_ingest()` | ~748 | Run full pipeline on archive/directory |
| `api_reingest()` | ~773 | Re-classify all visits |

### `history_search/pipeline/extract.py`

Stage 1. Recursive archive decompression with provenance tracking.

| Function | Line | What it does |
|----------|------|-------------|
| `extract_recursive()` | ~305 | Main entry: extracts nested archives up to 10 levels deep |
| `discover_files()` | ~361 | Walks extracted tree, yields ExtractedFile with provenance |
| `_extract_single()` | ~257 | Dispatch: tries Python libs first, falls back to CLI |
| `_check_path_traversal()` | ~124 | Blocks `..` path attacks in archive members |
| `_check_extraction_size()` | ~296 | Zip bomb protection (10 GB limit) |

Supports: `.7z`, `.zip`, `.tar`, `.tar.gz`, `.tar.bz2`, `.rar`

### `history_search/pipeline/ingest.py`

Stage 2. Reads browser-specific SQLite databases and produces `VisitRecord` objects.

| Function | Line | What it does |
|----------|------|-------------|
| `extract_chromium()` | ~206 | Chrome/Edge/Brave/Vivaldi/Arc visit extraction |
| `extract_gecko()` | ~291 | Firefox visit extraction with sync detection |
| `extract_webkit()` | ~395 | Safari visit extraction with redirect tracking |
| `extract_teams_json()` | ~495 | Microsoft Teams JSON log parsing |
| `_probe_engine()` | ~53 | Detects browser engine by schema probing |
| `detect_source_metadata()` | ~76 | Extracts browser, profile, username from DB path |
| `discover_databases()` | ~600 | Finds all history databases in a directory tree |
| `_chrome_time_to_utc()` | ~150 | Converts Chrome epoch (Jan 1, 1601 microseconds) |
| `_firefox_time_to_utc()` | ~168 | Converts Firefox epoch (Unix microseconds) |
| `_safari_time_to_utc()` | ~178 | Converts Safari epoch (Jan 1, 2001 seconds) |

**Adding a new browser:** Create an extractor function, add to `ENGINE_EXTRACTORS` dict (~line 470), add path patterns to constants.py.

### `history_search/pipeline/classify.py`

Stage 3. URL decomposition, forensic tagging, and URL unfurling.

| Function | Line | What it does |
|----------|------|-------------|
| `decompose_url()` | ~62 | Parse URL into host/path/query/scheme/port |
| `unfurl_url()` | ~120 | Extract artifacts: search terms, embedded URLs, timestamps, geo, protobuf |
| `classify_visit()` | ~748 | Main entry: decompose, unfurl, run all classifiers |
| `classify_batch()` | ~788 | Batch wrapper |

**Classifiers** (~lines 556-722): Each decorated with `@classifier("tag_name")`. Receives a `VisitRecord`, returns tag string or `None`.

| Tag | Line | Detects |
|-----|------|---------|
| `cred_in_url` | ~556 | `user:pass@host` credentials |
| `token_in_params` | ~568 | API keys, tokens, secrets in query params |
| `oauth_redirect` | ~581 | OAuth callback/authorize flows |
| `b64_payload` | ~597 | Base64-encoded payloads |
| `internal_network` | ~611 | RFC1918, localhost, .local, .corp |
| `non_standard_port` | ~623 | Ports other than 80/443 |
| `cloud_storage` | ~635 | Drive, Dropbox, S3, OneDrive |
| `file_scheme` | ~643 | file://, data:, javascript:, chrome-extension:// |
| `download_url` | ~655 | .exe, .dmg, .ps1, etc. |
| `paste_site` | ~663 | Pastebin, transfer.sh, file.io |
| `encoded_long_payload` | ~671 | Query strings over 2000 chars |
| `dns_over_https` | ~683 | DoH endpoints |
| `suspicious_tld` | ~692 | .tk, .ml, .xyz, .top |
| `search_query` | ~700 | Google/Bing/DDG search terms |
| `ip_address_host` | ~709 | IP address as hostname |
| `jwt_token` | ~717 | JWT tokens in URLs |

**Adding a classifier:** Write a function, decorate with `@classifier("your_tag")`, run Re-classify from the UI.

### `history_search/pipeline/index.py`

Stage 4. SQLite schema, FTS5 index, and batch insertion.

| Function | Line | What it does |
|----------|------|-------------|
| `init_schema()` | ~117 | Creates visits table, FTS5 virtual table, indices, triggers |
| `insert_visits()` | ~142 | Batch insert VisitRecords, log to ingest_log |
| `rebuild_fts()` | ~181 | Drop and rebuild FTS5 content |
| `is_already_ingested()` | ~169 | Dedup check against ingest_log |

**Schema:** 22-column visits table, FTS5 on 7 text columns, 8 B-tree indices, auto-sync triggers.

**Adding a column:** Add to `VisitRecord` (models.py), add to `SCHEMA_DDL` CREATE TABLE, add to `INSERT_VISIT_SQL`, update `_record_to_tuple()` ordering.

### `history_search/pipeline/models.py`

Dataclasses that flow through the pipeline.

- `ExtractedFile`: temp path + provenance chain from extraction
- `SourceMetadata`: OS, browser, profile, username derived from file paths
- `VisitRecord`: The main record (22 fields). Created in Stage 2, enriched in Stage 3, inserted in Stage 4.

### `history_search/pipeline/enums.py`

Enumerations: `Browser`, `BrowserEngine`, `TransitionType`, `VisitSource`, `VisitSourceConfidence`, `OSPlatform`, `TimeInterval`.

### `history_search/pipeline/constants.py`

All regex patterns, magic numbers, path templates, and thresholds. This is where you change:

- Archive passwords (`ARCHIVE_PASSWORDS`)
- Browser file path patterns (`MACOS_BROWSER_PATHS`, `WINDOWS_BROWSER_PATHS`)
- Timestamp epoch offsets (`CHROME_EPOCH_OFFSET_S`, `SAFARI_EPOCH_OFFSET_S`)
- Chrome transition bitmasks
- Search engine patterns, cloud storage hosts, paste sites, suspicious TLDs
- Download extensions, internal network patterns, sensitive param keys
- Search pagination limits

### `history_search/static/index.html`

Single-file React SPA. No build step. Uses React 18 + Babel Standalone via CDN.

| Component | Line | What it does |
|-----------|------|-------------|
| `api` object | ~224 | Fetch wrappers for all endpoints |
| `tryDecode()` | ~242 | Inline string decoder (base64, hex, URL, JWT) |
| `BarChart` | ~296 | Horizontal bar chart for aggregations |
| `TimelineChart` | ~308 | Canvas timeline for time-series data |
| `Heatmap` | ~330 | Day x hour activity grid |
| `FilePicker` | ~354 | Modal file/directory browser |
| `SearchView` | ~474 | Main search interface with filters and results |
| `ExploreView` | ~768 | Aggregation dashboard with drill-through |
| `SourceManager` | ~884 | Ingested source list with select/remove |
| `IngestView` | ~958 | Ingest controls, token input, maintenance |
| `App` | ~1086 | Root component, tab navigation |

**Adding an Explore dimension:** Add entry to `DIMENSIONS` array (~line 751).

**Adding a search filter:** Add UI control in SearchView (~line 598), add param to `doSearch()` query builder (~line 513).

## Tests

`tests/test_e2e_server.py` contains 53 end-to-end tests covering all API endpoints. Run with:

```bash
python tests/test_e2e_server.py
```

Tests create a temp SQLite database, seed sample data (including ingest_log entries), spin up a Flask test client, and verify every endpoint.
