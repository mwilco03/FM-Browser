# Architecture Notes

## Pipeline Stages
1. **Extract** (`extract.py`): Recursive 7z/zip/tar.gz extraction with password list
2. **Ingest** (`ingest.py`): Schema probing → engine detection → per-visit SQL extraction
3. **Classify** (`classify.py`): URL decomposition + 15 classifier functions (decorator-based registry)
4. **Index** (`index.py`): FTS5 content-sync with auto-triggers, ingest_log tracking

## Database Schema
- Main table: `visits` with 21 columns covering source, visit, URL, navigation, and classification
- FTS5 virtual table: `visits_fts` indexed on url, title, query_string, host, tags, from_visit_url
- Tracking: `ingest_log` prevents duplicate ingestion

## Frontend
- Three views: Search (default), Explore (progressive aggregation builder), Ingest
- Explore view uses `/api/aggregate?group_by=X` for on-demand dimension charts
- Drill-through: clicking any bar in Explore switches to Search with that filter applied
- Visit source badges with confidence indicator (solid = confirmed, dashed = heuristic)
