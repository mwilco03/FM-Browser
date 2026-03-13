# API Reference

All endpoints return JSON unless otherwise noted. POST endpoints that modify data require an API token (printed at server startup) via `X-API-Token` header or `?token=` query parameter.

## Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/api/search` | Full-text search with filters and pagination |
| `GET` | `/api/export` | Export matching results as streaming CSV |
| `GET` | `/api/visit/<id>` | Single visit detail |
| `GET` | `/api/aggregate` | Dynamic aggregation by any dimension |
| `GET` | `/api/filters` | Available filter values for dropdowns |
| `GET` | `/api/heatmap` | Day-of-week x hour activity heatmap |
| `GET` | `/api/sources` | List all ingested sources with visit counts |
| `GET` | `/api/browse` | Browse server filesystem for file picker |
| `POST` | `/api/sources/delete` | Remove selected sources and their visits |
| `POST` | `/api/ingest` | Run full pipeline on archive/directory |
| `POST` | `/api/reingest` | Re-classify all visits |
| `POST` | `/api/rebuild-fts` | Rebuild FTS5 search index |
| `POST` | `/api/clear` | Wipe all visit data and ingest log |

---

## GET /api/search

Full-text search with filters and pagination.

### Parameters

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `q` | string | | Search query |
| `mode` | string | `fts` | Search mode: `fts`, `contains`, or `regex` |
| `host` | string | | Filter by hostname |
| `browser` | string | | Filter by browser name |
| `visit_source` | string | | Filter by visit source (local, synced, extension) |
| `os_platform` | string | | Filter by OS (macos, windows, linux) |
| `transition_type` | string | | Filter by transition type (typed, link, bookmark, etc.) |
| `tag` | string | | Filter by forensic tag |
| `start` | string | | Start date (ISO-8601) |
| `end` | string | | End date (ISO-8601) |
| `exclude_host` | string | | Comma-separated hosts to exclude |
| `sort` | string | `time` | Sort by: time, host, title, browser, url, url_length, source, transition, duration, file_source |
| `sort_dir` | string | `desc` | Sort direction: `asc` or `desc` |
| `limit` | int | 100 | Results per page (max 500) |
| `offset` | int | 0 | Pagination offset |

### Search modes

- **fts** - FTS5 MATCH syntax. Supports `AND`, `OR`, `NOT`, `"quoted phrases"`, column prefixes (`title:news`, `dns_host:github`)
- **contains** - Case-insensitive substring match across URL, title, host, query string, tags
- **regex** - Python `re.search` across the same fields

### Response

```json
{
  "total": 1523,
  "limit": 100,
  "offset": 0,
  "results": [
    {
      "id": 42,
      "visit_time_utc": "2024-03-15T10:30:00Z",
      "full_url": "https://example.com/page",
      "title": "Example Page",
      "dns_host": "example.com",
      "url_path": "/page",
      "query_string_decoded": "",
      "visit_source": "local",
      "visit_source_confidence": "confirmed",
      "transition_type": "typed",
      "browser": "chrome",
      "os_platform": "macos",
      "tags": ["search_query"],
      "unfurl": [],
      "source_db_path": "/evidence/History",
      "provenance_chain": "evidence.7z > Users/john/Chrome/History"
    }
  ]
}
```

---

## GET /api/export

Export search results as CSV. Accepts the same parameters as `/api/search` (except `limit` and `offset` - exports all matching rows).

Returns `Content-Type: text/csv` with `Content-Disposition: attachment; filename=export.csv`.

### Examples

```
# Export everything
/api/export

# Export Chrome visits matching "password"
/api/export?q=password&browser=chrome

# Export with regex filter and date range
/api/export?mode=regex&q=\.tk$&start=2024-01-01T00:00:00Z&end=2024-12-31T23:59:59Z
```

---

## GET /api/visit/\<id\>

Returns full detail for a single visit by ID.

---

## GET /api/aggregate

Dynamic aggregation for building dashboards.

### Parameters

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `group_by` | string | `dns_host` | Dimension to group by |
| `metric` | string | `count` | Metric: `count`, `unique_urls`, `unique_users` |
| `q` | string | | Text search to filter aggregation (FTS5) |
| `limit` | int | 20 | Max groups (max 200) |
| `sort` | string | `desc` | Sort direction |

Plus all the same filter params as `/api/search` (host, browser, etc.).

### Available group_by values

**Column dimensions:** `dns_host`, `browser`, `os_platform`, `os_username`, `browser_profile`, `endpoint_name`, `visit_source`, `transition_type`, `browser_engine`, `title`

**Time dimensions:** `time_hour`, `time_day`, `time_week`, `time_month`

**Special:** `tags` (explodes JSON array, counts per-tag)

### Examples

```
# Top 20 hosts
/api/aggregate?group_by=dns_host&limit=20

# Visits per day
/api/aggregate?group_by=time_day&limit=365

# Tags breakdown filtered to Chrome
/api/aggregate?group_by=tags&browser=chrome

# Top page titles containing "login"
/api/aggregate?group_by=title&q=login
```

---

## GET /api/filters

Returns available filter values for populating dropdowns.

```json
{
  "total_visits": 15234,
  "browser": ["chrome", "firefox", "safari"],
  "os_platform": ["macos", "windows"],
  "visit_source": ["local", "synced"],
  "os_username": ["john", "jane"],
  "transition_type": ["typed", "link", "bookmark"],
  "tags": ["cloud_storage", "search_query", "suspicious_tld"],
  "time_range": {
    "earliest": "2023-01-15T08:00:00Z",
    "latest": "2024-06-20T22:15:00Z"
  }
}
```

---

## GET /api/heatmap

Returns day-of-week x hour-of-day activity counts. Accepts filter params and `q` for text search.

```json
{
  "cells": [
    {"dow": 0, "hour": 9, "count": 42},
    {"dow": 1, "hour": 14, "count": 87}
  ]
}
```

`dow`: 0=Sunday, 6=Saturday. `hour`: 0-23.

---

## GET /api/sources

List all ingested sources with live visit counts.

```json
{
  "sources": [
    {
      "id": 1,
      "source_db": "/tmp/extract/Users/john/Library/Safari/History.db",
      "browser": "safari",
      "os_platform": "macos",
      "os_username": "john",
      "browser_profile": "",
      "endpoint_name": "Johns-MacBook",
      "ingested_rows": 4521,
      "live_rows": 4521,
      "ingested_at": "2024-06-15 10:30:00"
    }
  ]
}
```

---

## POST /api/sources/delete

Remove selected sources and all their visits.

**Request:** `{"ids": [1, 3]}`

**Response:** `{"status": "ok", "deleted_visits": 8542, "deleted_sources": ["/path/to/History.db", "/path/to/places.sqlite"]}`

---

## GET /api/browse

Browse the server filesystem (restricted to allowed roots).

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | `/` | Directory to list |

---

## POST /api/ingest

Run the full pipeline on an archive or directory.

**Request:** `{"path": "/path/to/evidence.7z", "clear": false}`

Set `clear: true` to wipe existing data before ingesting.

---

## POST /api/reingest

Re-run classification (Stage 3) on all existing visits and rebuild the FTS index. Use after adding or modifying classifiers.

---

## POST /api/rebuild-fts

Rebuild the FTS5 search index from the visits table. Use if search results seem stale.

---

## POST /api/clear

Wipe all visit data and the ingest log. Schema is preserved.
