# FM-Browser: Forensic Browser History Search Engine

## Project Overview

A forensic tool that ingests browser history from forensic acquisitions (7z/tar.gz/zip archives),
extracts Safari/Chrome/Firefox/Edge/Brave history databases, classifies visits with forensic tags,
and serves a full-text search SPA.

## Architecture

Four-stage pipeline, each independently testable:

```
[Archive] → Stage 1: Extract → Stage 2: Ingest → Stage 3: Classify → Stage 4: Index → [Flask SPA]
```

### Key Directories

- `history_search/` — Main package
  - `server.py` — Flask app, API endpoints, pipeline orchestration
  - `pipeline/` — Pipeline stages
    - `extract.py` — Stage 1: Recursive archive decompression
    - `ingest.py` — Stage 2: Browser-specific SQLite extraction (per-visit granularity)
    - `classify.py` — Stage 3: URL decomposition, 15+ forensic classifiers, sync detection
    - `index.py` — Stage 4: FTS5 schema management and insertion
    - `models.py` — Dataclasses (ExtractedFile, SourceMetadata, VisitRecord)
    - `enums.py` — Browser, BrowserEngine, TransitionType, VisitSource enums
    - `constants.py` — All patterns, magic numbers, classifier config
  - `static/index.html` — React SPA (Search / Explore / Ingest views)
- `agents/` — Claude agent definitions for forensic analysis
- `scripts/` — CLI helpers and setup scripts
- `tests/` — Pipeline unit tests

### Legacy Files (kept for reference)

- `server.py` (root) — Original monolithic server
- `fm-browser.html` — Original SPA

## Running

```bash
# Install dependencies
pip install flask
apt-get install p7zip-full  # for archive extraction

# Run with source archive
python -m history_search.server /path/to/evidence.7z --port 8888

# Run server only (if already ingested)
python -m history_search.server --port 8888
```

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/search` | Full-text search with filters and pagination |
| GET | `/api/export` | Export matching results as streaming CSV (same params as search) |
| GET | `/api/visit/{id}` | Single visit detail |
| GET | `/api/aggregate` | Dynamic aggregation (group_by any dimension, supports q= text search) |
| GET | `/api/filters` | Available filter values for dropdowns |
| GET | `/api/heatmap` | Day-of-week x hour activity heatmap (supports q= text search) |
| GET | `/api/sources` | List all ingested sources with live visit counts |
| GET | `/api/browse` | Browse server filesystem for file picker |
| POST | `/api/sources/delete` | Remove selected sources and their visits by ingest_log IDs |
| POST | `/api/ingest` | Run full pipeline on archive/directory |
| POST | `/api/reingest` | Re-classify all visits |
| POST | `/api/rebuild-fts` | Rebuild FTS5 index |
| POST | `/api/clear` | Wipe all visit data and ingest log |

## Conventions

- Timestamps: ISO-8601 UTC strings (e.g., `2024-01-15T10:30:00Z`)
- Tags: JSON arrays stored as TEXT in SQLite
- Visit source confidence: "confirmed" | "likely" | "unknown"
- Browser engine determines extraction query, not browser name
- All classifiers are registered via `@classifier` decorator in `classify.py`

## Adding a New Classifier

1. Add a function in `history_search/pipeline/classify.py`
2. Decorate with `@classifier("tag_name")`
3. Function receives a `VisitRecord`, returns tag name string or None
4. Run `/api/reingest` to reclassify existing data
