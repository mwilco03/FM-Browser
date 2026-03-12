#!/usr/bin/env python3
"""
Forensic Browser History Search Server

Modular pipeline architecture:
  Stage 1: Extract  — recursive archive decompression
  Stage 2: Ingest   — browser-specific SQLite extraction
  Stage 3: Classify — URL decomposition, tagging, sync detection
  Stage 4: Index    — FTS5 insertion and schema management

Usage:
    python -m history_search.server /path/to/archive.7z --port 8888
    python -m history_search.server /path/to/extracted/dir --port 8888
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, g, jsonify, request, send_from_directory

from .pipeline.classify import classify_batch
from .pipeline.constants import DEFAULT_SEARCH_LIMIT, INTERVAL_STRFTIME, MAX_SEARCH_LIMIT
from .pipeline.extract import discover_files, extract_recursive
from .pipeline.index import (
    TABLE_FTS, TABLE_VISITS, init_schema, insert_visits,
    is_already_ingested, rebuild_fts, get_visit_count,
)
from .pipeline.ingest import discover_databases, ingest_database

LOG = logging.getLogger("history_search")

app = Flask(__name__, static_folder="static")

# ---------------------------------------------------------------------------
# Full pipeline orchestration
# ---------------------------------------------------------------------------

def run_pipeline(index_db: str, source_path: Path,
                 on_progress: Optional[callable] = None) -> Dict[str, Any]:
    """Run the full 4-stage pipeline on an archive or directory.

    Returns ingestion statistics.
    """
    stats: Dict[str, Any] = {"databases_found": 0, "ingested": [], "total_new_rows": 0}

    # Stage 1: Extract if archive
    work_dir = source_path
    tmp_dir = None
    if source_path.is_file():
        tmp_dir = Path(tempfile.mkdtemp(prefix="hist_"))
        if on_progress:
            on_progress("Extracting archives...")
        extract_recursive(source_path, tmp_dir, on_progress=on_progress)
        work_dir = tmp_dir

    try:
        # Stage 2: Discover and ingest
        if on_progress:
            on_progress("Discovering databases...")
        db_list = discover_databases(work_dir)
        stats["databases_found"] = len(db_list)

        for db_path, engine, meta in db_list:
            src_key = str(db_path)

            if is_already_ingested(index_db, src_key):
                stats["ingested"].append({
                    "path": src_key, "browser": meta.browser,
                    "os_platform": meta.os_platform, "rows": 0, "status": "skipped"
                })
                continue

            if on_progress:
                on_progress(f"Ingesting: {db_path.name} [{meta.browser}]")

            provenance = meta.endpoint_name or source_path.name
            records = ingest_database(db_path, engine, meta, provenance)

            if not records:
                stats["ingested"].append({
                    "path": src_key, "browser": meta.browser,
                    "os_platform": meta.os_platform, "rows": 0, "status": "empty"
                })
                continue

            # Stage 3: Classify
            if on_progress:
                on_progress(f"Classifying {len(records)} visits...")
            records = classify_batch(records)

            # Stage 4: Index
            if on_progress:
                on_progress(f"Indexing {len(records)} visits...")
            count = insert_visits(
                index_db, records, source_db=src_key,
                meta_browser=meta.browser, meta_platform=meta.os_platform,
                meta_username=meta.os_username, meta_profile=meta.browser_profile,
                meta_endpoint=meta.endpoint_name,
            )

            stats["total_new_rows"] += count
            stats["ingested"].append({
                "path": src_key, "browser": meta.browser,
                "os_platform": meta.os_platform, "user": meta.os_username,
                "profile": meta.browser_profile, "rows": count, "status": "ingested"
            })

    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return stats


# ---------------------------------------------------------------------------
# Flask helpers
# ---------------------------------------------------------------------------

def _get_db():
    if "db" not in g:
        g.db = sqlite3.connect(g.db_path)
        g.db.row_factory = sqlite3.Row
    return g.db


FILTER_COLUMNS = {
    "host": "v.dns_host",
    "browser": "v.browser",
    "browser_engine": "v.browser_engine",
    "os_platform": "v.os_platform",
    "os_username": "v.os_username",
    "visit_source": "v.visit_source",
    "transition_type": "v.transition_type",
    "browser_profile": "v.browser_profile",
    "endpoint_name": "v.endpoint_name",
}


def _build_where(filters: Dict[str, Optional[str]], fts_q: str = ""):
    """Build WHERE clause from filters and optional FTS query."""
    clauses, params = [], []

    if fts_q:
        clauses.append(f"{TABLE_FTS} MATCH ?")
        params.append(fts_q)

    for param_name, col_expr in FILTER_COLUMNS.items():
        v = filters.get(param_name)
        if v:
            clauses.append(f"{col_expr} = ?")
            params.append(v)

    # Tag filter (JSON array contains)
    tag = filters.get("tag")
    if tag:
        clauses.append("v.tags LIKE ?")
        params.append(f'%"{tag}"%')

    # Date range
    start = filters.get("start")
    if start:
        clauses.append("v.visit_time_utc >= ?")
        params.append(start)
    end = filters.get("end")
    if end:
        clauses.append("v.visit_time_utc <= ?")
        params.append(end)

    return (" AND ".join(clauses) or "1=1"), params


def _get_filters() -> Dict[str, Optional[str]]:
    """Extract filter parameters from request args."""
    keys = list(FILTER_COLUMNS.keys()) + ["tag", "start", "end"]
    return {k: request.args.get(k) for k in keys}


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.teardown_appcontext
def _teardown(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/search")
def api_search():
    """Full-text search with filters and pagination."""
    db = _get_db()
    q = request.args.get("q", "").strip()
    limit = min(int(request.args.get("limit", DEFAULT_SEARCH_LIMIT)), MAX_SEARCH_LIMIT)
    offset = int(request.args.get("offset", 0))
    sort = request.args.get("sort", "rank" if q else "time")
    f = _get_filters()

    if q:
        w, p = _build_where(f, fts_q=q)
        order = "rank" if sort == "rank" else "v.visit_time_utc DESC"
        sql = (f"SELECT v.* FROM {TABLE_FTS} fts "
               f"JOIN {TABLE_VISITS} v ON v.id = fts.rowid "
               f"WHERE {w} ORDER BY {order} LIMIT ? OFFSET ?")
        csql = (f"SELECT COUNT(*) FROM {TABLE_FTS} fts "
                f"JOIN {TABLE_VISITS} v ON v.id = fts.rowid WHERE {w}")
    else:
        w, p = _build_where(f)
        sql = (f"SELECT v.* FROM {TABLE_VISITS} v "
               f"WHERE {w} ORDER BY v.visit_time_utc DESC LIMIT ? OFFSET ?")
        csql = f"SELECT COUNT(*) FROM {TABLE_VISITS} v WHERE {w}"

    total = db.execute(csql, p).fetchone()[0]
    rows = []
    for r in db.execute(sql, p + [limit, offset]).fetchall():
        row = {k: r[k] for k in r.keys()}
        # Parse tags JSON for frontend
        try:
            row["tags"] = json.loads(row.get("tags", "[]"))
        except (json.JSONDecodeError, TypeError):
            row["tags"] = []
        rows.append(row)

    return jsonify({"total": total, "limit": limit, "offset": offset, "results": rows})


@app.route("/api/visit/<int:visit_id>")
def api_visit(visit_id: int):
    """Single visit detail."""
    db = _get_db()
    row = db.execute(f"SELECT * FROM {TABLE_VISITS} WHERE id = ?", (visit_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    result = {k: row[k] for k in row.keys()}
    try:
        result["tags"] = json.loads(result.get("tags", "[]"))
    except (json.JSONDecodeError, TypeError):
        result["tags"] = []
    return jsonify(result)


@app.route("/api/aggregate")
def api_aggregate():
    """Dynamic aggregation endpoint for progressive dashboards."""
    db = _get_db()
    group_by = request.args.get("group_by", "dns_host")
    metric = request.args.get("metric", "count")
    limit = min(int(request.args.get("limit", 20)), 200)
    sort = request.args.get("sort", "desc")
    f = _get_filters()
    w, p = _build_where(f)

    sort_dir = "DESC" if sort == "desc" else "ASC"

    # Time-based grouping
    time_groups = {
        "time_hour": "%Y-%m-%dT%H:00:00Z",
        "time_day": "%Y-%m-%d",
        "time_week": "%Y-W%W",
        "time_month": "%Y-%m",
    }

    if group_by == "tags":
        # Explode JSON array using json_each
        if metric == "unique_urls":
            select = "j.value AS label, COUNT(DISTINCT v.full_url) AS count"
        elif metric == "unique_users":
            select = "j.value AS label, COUNT(DISTINCT v.os_username) AS count"
        else:
            select = "j.value AS label, COUNT(*) AS count"

        sql = (f"SELECT {select} FROM {TABLE_VISITS} v, json_each(v.tags) AS j "
               f"WHERE {w} GROUP BY j.value ORDER BY count {sort_dir} LIMIT ?")
    elif group_by in time_groups:
        pat = time_groups[group_by]
        if metric == "unique_urls":
            select = f"strftime('{pat}', v.visit_time_utc) AS label, COUNT(DISTINCT v.full_url) AS count"
        elif metric == "unique_users":
            select = f"strftime('{pat}', v.visit_time_utc) AS label, COUNT(DISTINCT v.os_username) AS count"
        else:
            select = f"strftime('{pat}', v.visit_time_utc) AS label, COUNT(*) AS count"

        sql = (f"SELECT {select} FROM {TABLE_VISITS} v "
               f"WHERE {w} AND v.visit_time_utc != '' "
               f"GROUP BY label ORDER BY label ASC LIMIT ?")
    else:
        # Standard column grouping
        col = f"v.{group_by}" if group_by in (
            "dns_host", "browser", "os_platform", "os_username",
            "browser_profile", "endpoint_name", "visit_source",
            "transition_type", "browser_engine",
        ) else "v.dns_host"

        if metric == "unique_urls":
            select = f"{col} AS label, COUNT(DISTINCT v.full_url) AS count"
        elif metric == "unique_users":
            select = f"{col} AS label, COUNT(DISTINCT v.os_username) AS count"
        else:
            select = f"{col} AS label, COUNT(*) AS count"

        sql = (f"SELECT {select} FROM {TABLE_VISITS} v "
               f"WHERE {w} GROUP BY label ORDER BY count {sort_dir} LIMIT ?")

    rows = [{"label": r["label"], "count": r["count"]}
            for r in db.execute(sql, p + [limit]).fetchall()]

    return jsonify({"group_by": group_by, "metric": metric, "results": rows})


@app.route("/api/filters")
def api_filters():
    """Return available filter values for dropdowns."""
    db = _get_db()
    t = TABLE_VISITS
    result = {}
    for col in ("browser", "os_platform", "os_username", "visit_source",
                "transition_type", "browser_profile", "endpoint_name", "browser_engine"):
        rows = db.execute(
            f"SELECT DISTINCT {col} FROM {t} WHERE {col} != '' ORDER BY {col}"
        ).fetchall()
        result[col] = [r[0] for r in rows]

    # Tags (from JSON arrays)
    tag_rows = db.execute(
        f"SELECT DISTINCT j.value FROM {t}, json_each({t}.tags) AS j ORDER BY j.value"
    ).fetchall()
    result["tags"] = [r[0] for r in tag_rows]

    # Time range
    tr = db.execute(f"SELECT MIN(visit_time_utc), MAX(visit_time_utc) FROM {t}").fetchone()
    result["time_range"] = {"earliest": tr[0], "latest": tr[1]}

    # Total count
    result["total_visits"] = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]

    return jsonify(result)


@app.route("/api/heatmap")
def api_heatmap():
    """Day-of-week × hour-of-day activity heatmap."""
    db = _get_db()
    f = _get_filters()
    w, p = _build_where(f)
    rows = db.execute(
        f"SELECT CAST(strftime('%w', visit_time_utc) AS INT) AS dow, "
        f"CAST(strftime('%H', visit_time_utc) AS INT) AS hour, "
        f"COUNT(*) AS count FROM {TABLE_VISITS} v "
        f"WHERE {w} AND visit_time_utc != '' GROUP BY dow, hour", p
    ).fetchall()
    return jsonify({"cells": [dict(r) for r in rows]})


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Accept archive/directory path and run the full pipeline."""
    body = request.get_json(silent=True) or {}
    path_str = body.get("path", "")
    if not path_str:
        return jsonify({"error": "path required"}), 400

    target = Path(path_str).resolve()
    if not target.exists():
        return jsonify({"error": f"not found: {target}"}), 400

    stats = run_pipeline(g.db_path, target)
    return jsonify(stats)


@app.route("/api/reingest", methods=["POST"])
def api_reingest():
    """Re-run classification (Stage 3) and rebuild FTS index."""
    db = _get_db()
    # Re-classify all visits
    rows = db.execute(f"SELECT id, full_url, title, dns_host FROM {TABLE_VISITS}").fetchall()
    from .pipeline.classify import decompose_url, classify_visit
    from .pipeline.models import VisitRecord

    count = 0
    for row in rows:
        record = VisitRecord(full_url=row["full_url"], title=row["title"] or "")
        record = classify_visit(record)
        db.execute(
            f"UPDATE {TABLE_VISITS} SET dns_host=?, url_path=?, query_string_decoded=?, "
            f"tags=? WHERE id=?",
            (record.dns_host, record.url_path, record.query_string_decoded,
             json.dumps(record.tags), row["id"])
        )
        count += 1

    db.commit()
    rebuild_fts(g.db_path)
    return jsonify({"reclassified": count})


@app.route("/api/rebuild-fts", methods=["POST"])
def api_rebuild_fts():
    """Rebuild the FTS5 index."""
    rebuild_fts(g.db_path)
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Forensic Browser History Search")
    p.add_argument("source", nargs="?", help="Archive (.7z/.zip/.tar.gz) or directory")
    p.add_argument("--port", type=int, default=8888)
    p.add_argument("--db", default="history_index.db")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--host", default="127.0.0.1")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s | %(name)s | %(message)s"
    )
    db_path = os.path.abspath(args.db)

    # Initialize schema
    init_schema(db_path)
    LOG.info("Index: %s", db_path)

    # Run pipeline on source if provided
    if args.source:
        src = Path(args.source).resolve()
        if not src.exists():
            LOG.error("Not found: %s", src)
            return
        stats = run_pipeline(db_path, src)
        LOG.info("Done: %d DB(s), %d new rows",
                 stats["databases_found"], stats["total_new_rows"])

    @app.before_request
    def _inject_db_path():
        g.db_path = db_path

    LOG.info("http://%s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.verbose)


if __name__ == "__main__":
    main()
