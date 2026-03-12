"""Stage 4: FTS5 index schema management and insertion."""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Dict, List, Optional

from .models import VisitRecord

LOG = logging.getLogger("history_search.index")

TABLE_VISITS = "visits"
TABLE_FTS = "visits_fts"

FTS_COLUMNS = ("full_url", "title", "query_string_decoded", "dns_host", "tags", "from_visit_url")

SCHEMA_DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_VISITS} (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Source identification
    provenance_chain        TEXT NOT NULL DEFAULT '',
    source_db_path          TEXT NOT NULL DEFAULT '',
    os_platform             TEXT NOT NULL DEFAULT '',
    browser                 TEXT NOT NULL DEFAULT '',
    browser_engine          TEXT NOT NULL DEFAULT '',
    browser_profile         TEXT NOT NULL DEFAULT '',
    os_username             TEXT NOT NULL DEFAULT '',
    endpoint_name           TEXT NOT NULL DEFAULT '',

    -- Visit data
    visit_time_utc          TEXT NOT NULL DEFAULT '',
    full_url                TEXT NOT NULL,
    title                   TEXT NOT NULL DEFAULT '',

    -- URL decomposition
    dns_host                TEXT NOT NULL DEFAULT '',
    url_path                TEXT NOT NULL DEFAULT '',
    query_string_decoded    TEXT NOT NULL DEFAULT '',

    -- Navigation metadata
    visit_source            TEXT NOT NULL DEFAULT 'unknown',
    visit_source_confidence TEXT NOT NULL DEFAULT 'unknown',
    transition_type         TEXT NOT NULL DEFAULT 'other',
    transition_qualifiers   TEXT NOT NULL DEFAULT '',
    from_visit_url          TEXT NOT NULL DEFAULT '',
    visit_duration_ms       INTEGER NOT NULL DEFAULT 0,

    -- Classification
    tags                    TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_visits_host       ON {TABLE_VISITS}(dns_host);
CREATE INDEX IF NOT EXISTS idx_visits_time       ON {TABLE_VISITS}(visit_time_utc);
CREATE INDEX IF NOT EXISTS idx_visits_browser    ON {TABLE_VISITS}(browser);
CREATE INDEX IF NOT EXISTS idx_visits_user       ON {TABLE_VISITS}(os_username);
CREATE INDEX IF NOT EXISTS idx_visits_platform   ON {TABLE_VISITS}(os_platform);
CREATE INDEX IF NOT EXISTS idx_visits_source     ON {TABLE_VISITS}(visit_source);
CREATE INDEX IF NOT EXISTS idx_visits_transition ON {TABLE_VISITS}(transition_type);
CREATE INDEX IF NOT EXISTS idx_visits_endpoint   ON {TABLE_VISITS}(endpoint_name);
CREATE INDEX IF NOT EXISTS idx_visits_engine     ON {TABLE_VISITS}(browser_engine);

CREATE VIRTUAL TABLE IF NOT EXISTS {TABLE_FTS} USING fts5(
    {', '.join(FTS_COLUMNS)},
    content={TABLE_VISITS},
    content_rowid=id,
    tokenize='unicode61 remove_diacritics 2'
);

-- Auto-sync triggers
CREATE TRIGGER IF NOT EXISTS trg_visits_ai AFTER INSERT ON {TABLE_VISITS} BEGIN
    INSERT INTO {TABLE_FTS}(rowid, {', '.join(FTS_COLUMNS)})
    VALUES(new.id, {', '.join('new.' + c for c in FTS_COLUMNS)});
END;

CREATE TRIGGER IF NOT EXISTS trg_visits_ad AFTER DELETE ON {TABLE_VISITS} BEGIN
    INSERT INTO {TABLE_FTS}({TABLE_FTS}, rowid, {', '.join(FTS_COLUMNS)})
    VALUES('delete', old.id, {', '.join('old.' + c for c in FTS_COLUMNS)});
END;

CREATE TRIGGER IF NOT EXISTS trg_visits_au AFTER UPDATE ON {TABLE_VISITS} BEGIN
    INSERT INTO {TABLE_FTS}({TABLE_FTS}, rowid, {', '.join(FTS_COLUMNS)})
    VALUES('delete', old.id, {', '.join('old.' + c for c in FTS_COLUMNS)});
    INSERT INTO {TABLE_FTS}(rowid, {', '.join(FTS_COLUMNS)})
    VALUES(new.id, {', '.join('new.' + c for c in FTS_COLUMNS)});
END;

-- Ingestion tracking
CREATE TABLE IF NOT EXISTS ingest_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_db   TEXT NOT NULL,
    browser     TEXT NOT NULL,
    os_platform TEXT NOT NULL DEFAULT '',
    os_username TEXT NOT NULL DEFAULT '',
    browser_profile TEXT NOT NULL DEFAULT '',
    endpoint_name TEXT NOT NULL DEFAULT '',
    row_count   INTEGER NOT NULL DEFAULT 0,
    ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

INSERT_VISIT_SQL = f"""
INSERT INTO {TABLE_VISITS} (
    provenance_chain, source_db_path, os_platform, browser, browser_engine,
    browser_profile, os_username, endpoint_name, visit_time_utc, full_url,
    title, dns_host, url_path, query_string_decoded, visit_source,
    visit_source_confidence, transition_type, transition_qualifiers,
    from_visit_url, visit_duration_ms, tags
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


def init_schema(db_path: str) -> None:
    """Initialize the index database schema."""
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA_DDL)
    LOG.info("Schema initialized: %s", db_path)


def _record_to_tuple(r: VisitRecord) -> tuple:
    """Convert a VisitRecord to an insert tuple."""
    return (
        r.provenance_chain, r.source_db_path, r.os_platform, r.browser,
        r.browser_engine, r.browser_profile, r.os_username, r.endpoint_name,
        r.visit_time_utc, r.full_url, r.title, r.dns_host, r.url_path,
        r.query_string_decoded, r.visit_source, r.visit_source_confidence,
        r.transition_type, r.transition_qualifiers, r.from_visit_url,
        r.visit_duration_ms, json.dumps(r.tags),
    )


def insert_visits(db_path: str, records: List[VisitRecord], source_db: str = "",
                  meta_browser: str = "", meta_platform: str = "",
                  meta_username: str = "", meta_profile: str = "",
                  meta_endpoint: str = "") -> int:
    """Insert classified visit records into the index database.

    Returns the number of records inserted.
    """
    if not records:
        return 0

    batch = [_record_to_tuple(r) for r in records]

    with sqlite3.connect(db_path) as conn:
        conn.executemany(INSERT_VISIT_SQL, batch)
        conn.execute(
            "INSERT INTO ingest_log (source_db, browser, os_platform, os_username, "
            "browser_profile, endpoint_name, row_count) VALUES (?,?,?,?,?,?,?)",
            (source_db, meta_browser, meta_platform, meta_username, meta_profile,
             meta_endpoint, len(batch))
        )
        conn.commit()

    LOG.info("Indexed %d visits from %s", len(batch), source_db or "unknown")
    return len(batch)


def is_already_ingested(db_path: str, source_db: str) -> bool:
    """Check if a source database has already been ingested."""
    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM ingest_log WHERE source_db = ?", (source_db,)
            ).fetchone()
            return row is not None
    except sqlite3.Error:
        return False


def rebuild_fts(db_path: str) -> None:
    """Rebuild the FTS5 index from scratch."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(f"INSERT INTO {TABLE_FTS}({TABLE_FTS}) VALUES('rebuild')")
        conn.commit()
    LOG.info("FTS index rebuilt")


def get_visit_count(db_path: str) -> int:
    """Get total visit count."""
    try:
        with sqlite3.connect(db_path) as conn:
            return conn.execute(f"SELECT COUNT(*) FROM {TABLE_VISITS}").fetchone()[0]
    except sqlite3.Error:
        return 0
