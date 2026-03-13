# Web Interface Guide

FM-Browser has three views accessible via tabs at the top of the page: **Search**, **Explore**, and **Ingest**. Switching between tabs preserves your state (query, filters, scroll position).

## Search

The default view. Full-text search across all indexed browser history.

### Search Modes

Toggle between three modes using the buttons below the search bar:

- **FTS5** (default): SQLite full-text search. Supports `AND`, `OR`, `NOT`, `"quoted phrases"`, and column prefixes like `title:news` or `dns_host:github`.
- **Contains**: Case-insensitive substring match. Matches anywhere in URL, title, host, query string, or tags.
- **Regex**: Python regular expressions via `re.search`. Matches across all text fields.

### Filters

- **Host**: Type a hostname to filter (partial match)
- **Browser**: Chrome, Firefox, Safari, Edge, Brave, etc.
- **Visit Source**: Local, synced, extension, imported
- **OS**: macOS, Windows, Linux
- **Transition Type**: Typed, link, bookmark, reload, form_submit, redirect
- **Tag**: Click any tag pill in results to filter by it
- **Date Range**: From/To date pickers
- **Exclude Hosts**: Click the X next to any hostname in results to exclude that domain

### Sorting

Click any column header to sort. Click again to reverse direction. Sortable columns: Time, Source, Host, Title, URL, URL Length, Browser, Transition, File Source.

### Row Detail

Click any row to expand it and see:

- Full URL, path, decoded query string with parsed parameters
- Visit metadata (time, source, transition, duration, referrer)
- User, profile, platform, browser engine
- File source path and full provenance chain
- Tags and URL unfurl results (embedded URLs, search terms, geo coordinates, timestamps, protobuf data)
- Inline string decoder (paste any base64, hex, URL-encoded, or JWT string to decode)

### Export CSV

When results are showing, click **Export CSV** next to the result count. This exports ALL matching results (not just the loaded page) as a CSV file using the current search query and filters.

## Explore

Aggregation-based exploration of your dataset. Choose a dimension to see top values by count.

### Dimensions

**Column dimensions**: Hosts, Browsers, Platforms, Users, Profiles, Endpoints, Visit Source, Transitions, Tags, Titles

**Time dimensions**: Hourly, Daily, Weekly, Monthly

**Heatmap**: Day-of-week by hour-of-day activity grid

### Text Search

The search input at the top of the Explore tab filters all aggregation charts and heatmaps via FTS5. Type a keyword and all charts update to show only matching visits.

### Drill-through

Click any bar in a chart to jump to the Search tab with that filter applied (e.g., click a hostname bar to search with that host filtered).

### Filters

Browser, Visit Source, and OS dropdown filters narrow all aggregations.

## Ingest

Manage data ingestion and indexed sources.

### Ingesting Data

1. Enter a path to an archive (`.7z`, `.tar.gz`, `.zip`) or directory in the input field, or click **Browse...** to use the file picker
2. Optionally check "Clear existing data before ingest" to start fresh
3. Click **Ingest** to run the pipeline

The pipeline recursively extracts archives, probes for browser history databases, extracts per-visit records, classifies them, and builds the FTS5 index.

### Source Manager

Below the ingest controls, the **Ingested Sources** panel shows all sources currently in the index:

- Source file path, browser, OS, username, profile
- Visit count and ingest timestamp
- Checkboxes for selection (click row or checkbox)
- **Select All** checkbox for bulk operations
- **Remove** button to delete selected sources and all their visits

This lets you manage multi-host, multi-file cases without clearing everything. Remove one host's data while keeping another.

### Maintenance

- **Re-classify**: Re-run all forensic taggers on existing data (use after adding custom classifiers)
- **Clear All Data**: Wipe the entire index and start over

### API Token

Ingest, clear, reclassify, and source deletion operations require the API token printed at server startup. Paste it into the token field at the top of the Ingest tab.
