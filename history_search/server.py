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
import csv
import hashlib
import io
import json
import logging
import os
import pkgutil
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from flask import Flask, Response, g, jsonify, request, send_file, send_from_directory

from .pipeline.carve import carve_deleted_records
from .pipeline.classify import classify_batch, classifier_version
from .pipeline.constants import DEFAULT_SEARCH_LIMIT, INTERVAL_STRFTIME, MAX_SEARCH_LIMIT
from .pipeline.extract import discover_files, extract_recursive
from .pipeline.index import (
    TABLE_FTS, TABLE_VISITS, FTS_COLUMNS, init_schema, insert_visits,
    is_already_ingested, rebuild_fts, get_visit_count, fts_row_count, log_action,
)
from .pipeline.ingest import discover_databases, ingest_database

LOG = logging.getLogger("history_search")

TOOL_VERSION = "1.0.0"  # keep in sync with pyproject.toml

app = Flask(__name__, static_folder="static")

# ---------------------------------------------------------------------------
# Security: loopback-by-default + same-origin CSRF defense
# ---------------------------------------------------------------------------
#
# Forensic tools run on the analyst's workstation. We don't need a token-paste
# dance: bind to 127.0.0.1, trust loopback, and reject cross-origin POSTs by
# checking Origin/Referer against Host. For non-loopback binds the operator
# must pass --allow-remote and is expected to put a real reverse proxy with
# auth in front of the server.

ALLOW_REMOTE: bool = False  # Set in main()

# Restrict /api/browse to these root paths (set via --browse-root)
BROWSE_ROOTS: List[Path] = []  # Empty = restricted to CWD by default


_LOOPBACK_PREFIXES = ("127.", "::1", "::ffff:127.")


def _is_loopback_request() -> bool:
    """True if the request originated on the local loopback interface."""
    addr = (request.remote_addr or "").strip()
    if not addr:
        return False
    if addr in ("127.0.0.1", "::1", "localhost"):
        return True
    return any(addr.startswith(p) for p in _LOOPBACK_PREFIXES)


def _is_same_origin() -> bool:
    """CSRF defense: Origin (or Referer) host must match the request Host.

    Browsers send Origin on POST/PUT/DELETE; same-origin XHRs from our SPA
    will always include it. Cross-site form submissions land here too but
    their Origin reflects the attacker's site, not ours.
    """
    origin = request.headers.get("Origin") or request.headers.get("Referer", "")
    if not origin:
        return False
    try:
        parsed = urlparse(origin)
    except ValueError:
        return False
    if not parsed.netloc:
        return False
    return parsed.netloc.lower() == request.host.lower()


def require_local(fn):
    """Decorator for mutating endpoints.

    - Reject non-loopback requests unless --allow-remote was passed.
    - Reject any request whose Origin/Referer is not same-origin (CSRF).
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _is_loopback_request() and not ALLOW_REMOTE:
            return jsonify({
                "error": "remote requests disabled. Bind with --allow-remote "
                         "and put a reverse proxy with auth in front of the server."
            }), 403
        if not _is_same_origin():
            return jsonify({
                "error": "cross-origin request rejected (CSRF defense). "
                         "Open the SPA from the server's own URL."
            }), 403
        return fn(*args, **kwargs)
    return wrapper


def _is_within_browse_roots(target: Path) -> bool:
    """Check if target is within any allowed browse root.

    BROWSE_ROOTS is always populated (CWD by default). Default-deny when
    somehow empty.
    """
    if not BROWSE_ROOTS:
        return False
    resolved = target.resolve()
    return any(resolved == root or str(resolved).startswith(str(root) + os.sep)
               for root in BROWSE_ROOTS)


# ---------------------------------------------------------------------------
# Full pipeline orchestration
# ---------------------------------------------------------------------------

def _sha256_file(path: Path):
    """Return (sha256_hex, size_bytes) for chain of custody (B-3)."""
    h = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest(), size
    except OSError:
        return "", 0


def run_pipeline(index_db: str, source_path: Path,
                 on_progress: Optional[callable] = None,
                 passwords: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run the full 4-stage pipeline on an archive or directory.

    Returns ingestion statistics, including any extraction failures (e.g.
    password-protected archives the supplied passwords didn't open).
    """
    stats: Dict[str, Any] = {
        "databases_found": 0,
        "ingested": [],
        "total_new_rows": 0,
        "extraction_failures": [],
    }

    # Stage 1: Extract if archive
    work_dir = source_path
    tmp_dir = None
    if source_path.is_file():
        tmp_dir = Path(tempfile.mkdtemp(prefix="hist_"))
        if on_progress:
            on_progress("Extracting archives...")
        ext_result = extract_recursive(source_path, tmp_dir,
                                       on_progress=on_progress,
                                       passwords=passwords)
        stats["extraction_failures"] = list(ext_result.failures)
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
            try:
                records = ingest_database(db_path, engine, meta, provenance)
            except Exception as e:
                # Extraction FAILED — surface it instead of reporting "empty"
                # and silently dropping evidence (UA-26).
                LOG.error("Ingest error for %s: %s", src_key, e)
                stats["ingested"].append({
                    "path": src_key, "browser": meta.browser,
                    "os_platform": meta.os_platform, "rows": 0,
                    "status": "error", "error": str(e),
                })
                stats["extraction_failures"].append({
                    "archive": src_key, "reason": "ingest_error", "detail": str(e),
                })
                continue

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
            src_hash, src_size = _sha256_file(db_path)
            count = insert_visits(
                index_db, records, source_db=src_key,
                meta_browser=meta.browser, meta_platform=meta.os_platform,
                meta_username=meta.os_username, meta_profile=meta.browser_profile,
                meta_endpoint=meta.endpoint_name,
                source_sha256=src_hash, source_size_bytes=src_size,
                tool_version=TOOL_VERSION, classifier_version=classifier_version(),
            )

            stats["total_new_rows"] += count
            stats["ingested"].append({
                "path": src_key, "browser": meta.browser,
                "os_platform": meta.os_platform, "user": meta.os_username,
                "profile": meta.browser_profile, "rows": count, "status": "ingested"
            })

            # Stage 5: Carve deleted records from WAL/freelist/slack
            if engine not in ("teams_json",):
                if on_progress:
                    on_progress(f"Carving deleted records: {db_path.name}...")
                active_urls = {r.full_url for r in records}
                carved = carve_deleted_records(db_path, meta, provenance, active_urls)
                if carved:
                    carved = classify_batch(carved)
                    # Ensure carved records keep their recovery tag
                    for cr in carved:
                        if "recovered_deleted" not in cr.tags:
                            cr.tags.append("recovered_deleted")
                            cr.tags = sorted(set(cr.tags))
                    carved_count = insert_visits(
                        index_db, carved, source_db=src_key + " [carved]",
                        meta_browser=meta.browser, meta_platform=meta.os_platform,
                        meta_username=meta.os_username, meta_profile=meta.browser_profile,
                        meta_endpoint=meta.endpoint_name,
                        source_sha256=src_hash, source_size_bytes=src_size,
                        tool_version=TOOL_VERSION, classifier_version=classifier_version(),
                    )
                    stats["total_new_rows"] += carved_count
                    stats["ingested"].append({
                        "path": src_key + " [carved]", "browser": meta.browser,
                        "os_platform": meta.os_platform, "user": meta.os_username,
                        "profile": meta.browser_profile, "rows": carved_count,
                        "status": "carved"
                    })

    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return stats


# ---------------------------------------------------------------------------
# Flask helpers
# ---------------------------------------------------------------------------

def _regexp(pattern, value):
    """SQLite REGEXP function implementation."""
    if value is None:
        return False
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return False


def _get_db():
    if "db" not in g:
        g.db = sqlite3.connect(g.db_path)
        g.db.row_factory = sqlite3.Row
        g.db.create_function("REGEXP", 2, _regexp)
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
    "from_visit_url": "v.from_visit_url",
}


# Columns used by the non-FTS search paths (contains / regex / LIKE fallback).
# Derived from the FTS5 index column list so the two can never drift.
SEARCH_COLS = tuple(f"v.{c}" for c in FTS_COLUMNS)

SEARCH_MODES = ("smart", "fts", "contains", "regex")
DEFAULT_SEARCH_MODE = "smart"

# Whitelists for user-supplied query parameters. Every value that reaches an
# ORDER BY / GROUP BY / metric position in raw SQL must be a member of one of
# these sets — never interpolated from free request input.
SORT_KEYS = ("time", "host", "title", "browser", "url", "url_length",
             "source", "transition", "duration", "file_source")
AGG_GROUP_BY = ("dns_host", "browser", "os_platform", "os_username",
                "browser_profile", "endpoint_name", "visit_source",
                "transition_type", "browser_engine", "title",
                "tags", "time_hour", "time_day", "time_week", "time_month")
AGG_METRICS = ("count", "unique_urls", "unique_users")
MAX_AGG_LIMIT = 5000  # was a hard 200 cap that hid the long tail (UA-25)

# FTS5 reserved keywords (case-insensitive). Tokens matching these are
# dropped during smart-mode sanitization to avoid syntax errors.
_FTS5_KEYWORDS = {"and", "or", "not", "near"}

# Anything not alphanumeric becomes a token boundary in smart mode.
_FTS5_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+")

LIKE_ESCAPE_CHAR = "\\"


def _like_escape(value: str) -> str:
    """Escape SQL LIKE wildcards so user input is treated literally."""
    return (
        value.replace(LIKE_ESCAPE_CHAR, LIKE_ESCAPE_CHAR * 2)
        .replace("%", LIKE_ESCAPE_CHAR + "%")
        .replace("_", LIKE_ESCAPE_CHAR + "_")
    )


def _smart_to_fts5(q: str) -> str:
    """Translate a free-form user query into a safe FTS5 expression.

    Splits on non-alphanumeric characters, drops single-char and FTS5-keyword
    tokens, AND-joins the survivors with prefix matching. Returns "" if no
    usable tokens remain — caller should fall back to LIKE in that case.
    """
    parts = _FTS5_TOKEN_SPLIT.split(q.lower())
    tokens = [t for t in parts if len(t) >= 2 and t not in _FTS5_KEYWORDS]
    if not tokens:
        return ""
    return " AND ".join(f"{t}*" for t in tokens)


def _build_where(filters: Dict[str, Optional[str]], fts_q: str = "",
                 search_mode: str = DEFAULT_SEARCH_MODE):
    """Build WHERE clause from filters and optional search query.

    search_mode:
      "smart"    — sanitized FTS5 with prefix matching (default).
      "fts"      — raw FTS5 MATCH for power users who want the full grammar.
      "contains" — LIKE substring match across all search columns.
      "regex"    — Python regex via the REGEXP function.

    Returns (where_sql, params, used_fts) where used_fts indicates whether
    the FTS5 shadow table is needed in the FROM clause.
    """
    clauses, params = [], []
    used_fts = False

    if fts_q:
        if search_mode == "regex":
            subs = []
            for col in SEARCH_COLS:
                subs.append(f"{col} REGEXP ?")
                params.append(fts_q)
            clauses.append("(" + " OR ".join(subs) + ")")
        elif search_mode == "contains":
            esc = _like_escape(fts_q)
            subs = []
            for col in SEARCH_COLS:
                subs.append(f"{col} LIKE ? ESCAPE '{LIKE_ESCAPE_CHAR}'")
                params.append(f"%{esc}%")
            clauses.append("(" + " OR ".join(subs) + ")")
        elif search_mode == "fts":
            clauses.append(f"{TABLE_FTS} MATCH ?")
            params.append(fts_q)
            used_fts = True
        else:  # "smart"
            sanitized = _smart_to_fts5(fts_q)
            if sanitized:
                clauses.append(f"{TABLE_FTS} MATCH ?")
                params.append(sanitized)
                used_fts = True
            else:
                # Pure-punctuation query, fall back to literal LIKE.
                esc = _like_escape(fts_q)
                subs = []
                for col in SEARCH_COLS:
                    subs.append(f"{col} LIKE ? ESCAPE '{LIKE_ESCAPE_CHAR}'")
                    params.append(f"%{esc}%")
                clauses.append("(" + " OR ".join(subs) + ")")

    for param_name, col_expr in FILTER_COLUMNS.items():
        if param_name == "host":
            continue  # subdomain-aware handling below (UA-23)
        v = filters.get(param_name)
        if v:
            clauses.append(f"{col_expr} = ?")
            params.append(v)

    # Host filter: match the domain AND its subdomains — the IOC pivot analysts
    # actually want. Use host_exact for a strict single-host match.
    host = filters.get("host")
    if host:
        clauses.append(f"(v.dns_host = ? OR v.dns_host LIKE ? ESCAPE '{LIKE_ESCAPE_CHAR}')")
        params.append(host)
        params.append(f"%.{_like_escape(host)}")
    host_exact = filters.get("host_exact")
    if host_exact:
        clauses.append("v.dns_host = ?")
        params.append(host_exact)

    # Exclude visit_source values (comma-separated), e.g. keep carved off timelines.
    exclude_source = filters.get("exclude_source")
    if exclude_source:
        srcs = [s.strip() for s in exclude_source.split(",") if s.strip()]
        if srcs:
            clauses.append("v.visit_source NOT IN (" + ",".join("?" * len(srcs)) + ")")
            params.extend(srcs)

    # Minimum source confidence: confirmed > likely > possible.
    min_conf = filters.get("min_confidence")
    if min_conf:
        ladder = {"confirmed": ("confirmed",),
                  "likely": ("confirmed", "likely"),
                  "possible": ("confirmed", "likely", "possible")}
        allowed = ladder.get(min_conf)
        if allowed:
            clauses.append("v.visit_source_confidence IN (" + ",".join("?" * len(allowed)) + ")")
            params.extend(allowed)

    # Tag filter (JSON array contains; LIKE-escape the tag value)
    tag = filters.get("tag")
    if tag:
        clauses.append(f"v.tags LIKE ? ESCAPE '{LIKE_ESCAPE_CHAR}'")
        params.append(f'%"{_like_escape(tag)}"%')

    # Multi-tag boolean filter: tags=a,b,c with tags_mode=and|or (default and).
    tags_raw = filters.get("tags")
    if tags_raw:
        tlist = [t.strip() for t in tags_raw.split(",") if t.strip()]
        if tlist:
            subs = []
            for t in tlist:
                subs.append(f"v.tags LIKE ? ESCAPE '{LIKE_ESCAPE_CHAR}'")
                params.append(f'%"{_like_escape(t)}"%')
            joiner = " OR " if (filters.get("tags_mode") or "and").lower() == "or" else " AND "
            clauses.append("(" + joiner.join(subs) + ")")

    # Domain exclusion filter (comma-separated list)
    exclude_host = filters.get("exclude_host")
    if exclude_host:
        hosts = [h.strip() for h in exclude_host.split(",") if h.strip()]
        if hosts:
            clauses.append("v.dns_host NOT IN (" + ",".join("?" * len(hosts)) + ")")
            params.extend(hosts)

    # Date range
    start = filters.get("start")
    if start:
        clauses.append("v.visit_time_utc >= ?")
        params.append(start)
    end = filters.get("end")
    if end:
        clauses.append("v.visit_time_utc <= ?")
        params.append(end)

    return (" AND ".join(clauses) or "1=1"), params, used_fts


def _safe_int(value, default: int) -> Optional[int]:
    """Parse an int from request input. Returns None on failure (caller 400s)."""
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_search_args():
    """Pull q/mode/sort/sort_dir from request.args with defaults applied."""
    q = request.args.get("q", "").strip()
    mode = request.args.get("mode", DEFAULT_SEARCH_MODE)
    if mode not in SEARCH_MODES:
        mode = DEFAULT_SEARCH_MODE
    # Sort defaults to FTS rank when an FTS-capable mode produced a query.
    is_fts_mode = mode in ("smart", "fts")
    sort = request.args.get("sort", "rank" if q and is_fts_mode else "time")
    sort_dir = request.args.get("sort_dir", "desc").upper()
    if sort_dir not in ("ASC", "DESC"):
        sort_dir = "DESC"
    return q, mode, sort, sort_dir


def _sort_map(sort_dir: str) -> Dict[str, str]:
    return {
        "time": f"v.visit_time_utc {sort_dir}",
        "host": f"v.dns_host {sort_dir}",
        "title": f"v.title {sort_dir}",
        "browser": f"v.browser {sort_dir}",
        "url": f"v.full_url {sort_dir}",
        "url_length": f"LENGTH(v.full_url) {sort_dir}",
        "source": f"v.visit_source {sort_dir}",
        "transition": f"v.transition_type {sort_dir}",
        "duration": f"v.visit_duration_ms {sort_dir}",
        "file_source": f"v.source_db_path {sort_dir}",
    }


def _build_search_sql(filters, q: str, mode: str, sort: str, sort_dir: str):
    """Build (sql, count_sql, params) for a search query.

    Caller decides whether to add LIMIT/OFFSET.
    """
    where, params, used_fts = _build_where(filters, fts_q=q, search_mode=mode)
    sort_map = _sort_map(sort_dir)
    if used_fts:
        order = sort_map.get(sort, "rank" if sort == "rank" else f"v.visit_time_utc {sort_dir}")
        sql = (f"SELECT v.* FROM {TABLE_FTS} fts "
               f"JOIN {TABLE_VISITS} v ON v.id = fts.rowid "
               f"WHERE {where} ORDER BY {order}")
        csql = (f"SELECT COUNT(*) FROM {TABLE_FTS} fts "
                f"JOIN {TABLE_VISITS} v ON v.id = fts.rowid WHERE {where}")
    else:
        order = sort_map.get(sort, f"v.visit_time_utc {sort_dir}")
        sql = f"SELECT v.* FROM {TABLE_VISITS} v WHERE {where} ORDER BY {order}"
        csql = f"SELECT COUNT(*) FROM {TABLE_VISITS} v WHERE {where}"
    return sql, csql, params


def _get_filters() -> Dict[str, Optional[str]]:
    """Extract filter parameters from request args."""
    keys = list(FILTER_COLUMNS.keys()) + ["tag", "start", "end", "exclude_host",
                                          "host_exact", "exclude_source", "min_confidence",
                                          "tags", "tags_mode"]
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
    # send_from_directory fails inside a .pyz zipapp because the static
    # folder path points into the zip archive.  Fall back to pkgutil which
    # reads from zip-importable packages.
    if app.static_folder and os.path.isdir(app.static_folder):
        return send_from_directory(app.static_folder, "index.html")
    data = pkgutil.get_data("history_search", "static/index.html")
    if data is None:
        return "index.html not found", 404
    return send_file(io.BytesIO(data), mimetype="text/html")


@app.route("/api/search")
def api_search():
    """Full-text search with filters and pagination.

    Search modes (?mode=):
      smart    — Default. Sanitizes user input into a safe FTS5 query with
                 prefix matching. Falls back to LIKE on pure-punctuation
                 queries.
      fts      — Raw FTS5 MATCH. Power-user grammar (boolean ops, columns).
      contains — Substring match (LIKE %term%). Matches anywhere.
      regex    — Python regex (re.search) across URL, title, host, query, tags.
    """
    db = _get_db()
    q, mode, sort, sort_dir = _normalize_search_args()

    limit = _safe_int(request.args.get("limit"), DEFAULT_SEARCH_LIMIT)
    offset = _safe_int(request.args.get("offset"), 0)
    if limit is None or offset is None:
        return jsonify({"error": "limit and offset must be integers"}), 400
    limit = max(1, min(limit, MAX_SEARCH_LIMIT))
    offset = max(0, offset)
    f = _get_filters()

    # Validate regex before running query
    if mode == "regex" and q:
        try:
            re.compile(q)
        except re.error as exc:
            return jsonify({"error": f"Invalid regex: {exc}",
                            "total": 0, "limit": limit, "offset": 0,
                            "results": []}), 400

    sql, csql, p = _build_search_sql(f, q, mode, sort, sort_dir)
    paged_sql = f"{sql} LIMIT ? OFFSET ?"

    try:
        total = db.execute(csql, p).fetchone()[0]
        cursor = db.execute(paged_sql, p + [limit, offset]).fetchall()
    except sqlite3.OperationalError as exc:
        return jsonify({
            "error": f"search failed: {exc}",
            "hint": "Try removing punctuation or switch to Contains mode for "
                    "literal substring search.",
            "total": 0, "limit": limit, "offset": offset, "results": [],
        }), 400

    rows = []
    for r in cursor:
        row = {k: r[k] for k in r.keys()}
        try:
            row["tags"] = json.loads(row.get("tags", "[]"))
        except (json.JSONDecodeError, TypeError):
            row["tags"] = []
        try:
            row["unfurl"] = json.loads(row.get("unfurl", "[]"))
        except (json.JSONDecodeError, TypeError):
            row["unfurl"] = []
        rows.append(row)

    return jsonify({"total": total, "limit": limit, "offset": offset, "results": rows})


CSV_COLUMNS = [
    "id", "visit_time_utc", "full_url", "title", "dns_host", "url_path",
    "query_string_decoded", "visit_source", "visit_source_confidence",
    "transition_type", "transition_qualifiers", "from_visit_url",
    "visit_duration_ms", "browser", "browser_engine", "browser_profile",
    "os_platform", "os_username", "endpoint_name", "source_db_path",
    "provenance_chain", "tags", "unfurl",
    "raw_transition", "raw_from_visit", "raw_visit_id",
]


@app.route("/api/export")
def api_export():
    """Export search results as CSV. Accepts same params as /api/search."""
    q, mode, sort, sort_dir = _normalize_search_args()
    f = _get_filters()

    if mode == "regex" and q:
        try:
            re.compile(q)
        except re.error as exc:
            return jsonify({"error": f"Invalid regex: {exc}"}), 400

    sql, _csql, p = _build_search_sql(f, q, mode, sort, sort_dir)

    # Use a dedicated connection for streaming (app context may close before
    # the generator finishes)
    db_path = g.db_path
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    filestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    active_filters = {k: v for k, v in f.items() if v}

    def generate():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            buf = io.StringIO()
            writer = csv.writer(buf)
            # Reproducibility header (commented) so an export can be attributed.
            writer.writerow(["# fm-browser export"])
            writer.writerow(["# tool_version", TOOL_VERSION])
            writer.writerow(["# exported_utc", stamp])
            writer.writerow(["# query", q, "mode", mode])
            writer.writerow(["# filters", json.dumps(active_filters)])
            writer.writerow(CSV_COLUMNS)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

            for row in conn.execute(sql, p):
                vals = []
                for c in CSV_COLUMNS:
                    v = row[c] if c in row.keys() else ""
                    if c == "tags":
                        try:
                            v = "; ".join(json.loads(v or "[]"))
                        except (json.JSONDecodeError, TypeError):
                            v = v or ""
                    elif c == "unfurl":
                        # Flatten decoded artifacts to readable "type=value" pairs
                        # instead of dumping raw JSON (UA-27).
                        try:
                            v = " | ".join(
                                f"{a.get('type')}={a.get('value', '')}"
                                for a in json.loads(v or "[]")
                            )
                        except (json.JSONDecodeError, TypeError):
                            v = v or ""
                    vals.append(v if v is not None else "")
                writer.writerow(vals)
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)
        finally:
            conn.close()

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=fmbrowser_export_{filestamp}.csv"},
    )


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
    try:
        result["unfurl"] = json.loads(result.get("unfurl", "[]"))
    except (json.JSONDecodeError, TypeError):
        result["unfurl"] = []
    return jsonify(result)


@app.route("/api/aggregate")
def api_aggregate():
    """Dynamic aggregation endpoint for progressive dashboards."""
    db = _get_db()
    group_by = request.args.get("group_by", "dns_host")
    metric = request.args.get("metric", "count")
    if group_by not in AGG_GROUP_BY:
        return jsonify({"error": f"unknown group_by: {group_by}",
                        "group_by": group_by, "metric": metric, "results": []}), 400
    if metric not in AGG_METRICS:
        return jsonify({"error": f"unknown metric: {metric}",
                        "group_by": group_by, "metric": metric, "results": []}), 400
    limit = _safe_int(request.args.get("limit"), 20)
    if limit is None:
        return jsonify({"error": "limit must be an integer"}), 400
    limit = max(1, min(limit, MAX_AGG_LIMIT))
    sort = request.args.get("sort", "desc")
    f = _get_filters()
    # Carved records carry fabricated timestamps (UA-19); keep them off time
    # views by default unless the caller opts in with include_carved=1.
    if (group_by in ("time_hour", "time_day", "time_week", "time_month")
            and not f.get("exclude_source")
            and request.args.get("include_carved") not in ("1", "true", "yes")):
        f["exclude_source"] = "carved"
    q = request.args.get("q", "").strip()
    search_mode = request.args.get("mode", DEFAULT_SEARCH_MODE)
    if search_mode not in SEARCH_MODES:
        search_mode = DEFAULT_SEARCH_MODE
    w, p, used_fts = _build_where(f, fts_q=q, search_mode=search_mode)

    # FTS search requires joining the FTS table
    fts_join = (f"{TABLE_FTS} fts JOIN {TABLE_VISITS} v ON v.id = fts.rowid"
                if used_fts else f"{TABLE_VISITS} v")

    sort_dir = "DESC" if sort == "desc" else "ASC"

    # First/last-seen per group enables frequency-stacking / least-frequency
    # hunting (UA-25). The COUNT includes every visit, but the time window must
    # reflect REAL visits — carved rows carry fabricated timestamps (UA-19), so
    # exclude them from the bounds (a carved-only group yields empty bounds).
    _real_ts = "CASE WHEN v.visit_source='carved' THEN '' ELSE v.visit_time_utc END"
    bounds = (f", MIN(NULLIF({_real_ts},'')) AS first_seen"
              f", MAX(NULLIF({_real_ts},'')) AS last_seen")

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
        select += bounds

        sql = (f"SELECT {select} FROM {fts_join}, json_each(v.tags) AS j "
               f"WHERE {w} GROUP BY j.value ORDER BY count {sort_dir} LIMIT ?")
    elif group_by in time_groups:
        pat = time_groups[group_by]
        if metric == "unique_urls":
            select = f"strftime('{pat}', v.visit_time_utc) AS label, COUNT(DISTINCT v.full_url) AS count"
        elif metric == "unique_users":
            select = f"strftime('{pat}', v.visit_time_utc) AS label, COUNT(DISTINCT v.os_username) AS count"
        else:
            select = f"strftime('{pat}', v.visit_time_utc) AS label, COUNT(*) AS count"

        sql = (f"SELECT {select} FROM {fts_join} "
               f"WHERE {w} AND v.visit_time_utc != '' "
               f"GROUP BY label ORDER BY label ASC LIMIT ?")
    else:
        # Standard column grouping. group_by is already validated against
        # AGG_GROUP_BY above, and the tags/time_* members are handled in the
        # branches above, so anything reaching here is a plain visits column.
        col = f"v.{group_by}"

        if metric == "unique_urls":
            select = f"{col} AS label, COUNT(DISTINCT v.full_url) AS count"
        elif metric == "unique_users":
            select = f"{col} AS label, COUNT(DISTINCT v.os_username) AS count"
        else:
            select = f"{col} AS label, COUNT(*) AS count"
        select += bounds

        sql = (f"SELECT {select} FROM {fts_join} "
               f"WHERE {w} GROUP BY label ORDER BY count {sort_dir} LIMIT ?")

    try:
        rows = []
        for r in db.execute(sql, p + [limit]).fetchall():
            d = {"label": r["label"], "count": r["count"]}
            if "first_seen" in r.keys():
                d["first_seen"] = r["first_seen"]
                d["last_seen"] = r["last_seen"]
            rows.append(d)
    except sqlite3.OperationalError as exc:
        return jsonify({"error": f"aggregate failed: {exc}",
                        "group_by": group_by, "metric": metric,
                        "results": []}), 400

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
    # Carved rows carry fabricated timestamps (UA-19); exclude from the activity
    # heatmap by default unless include_carved=1.
    if (not f.get("exclude_source")
            and request.args.get("include_carved") not in ("1", "true", "yes")):
        f["exclude_source"] = "carved"
    q = request.args.get("q", "").strip()
    # Render the heatmap in the analyst's chosen local offset (signed minutes) so
    # "active at 2am local" reasoning works without off-tool math (UA-11).
    tz_min = _safe_int(request.args.get("tz_offset"), 0) or 0
    tzmod = f"{tz_min:+d} minutes"
    w, p, used_fts = _build_where(f, fts_q=q, search_mode=DEFAULT_SEARCH_MODE)
    fts_join = (f"{TABLE_FTS} fts JOIN {TABLE_VISITS} v ON v.id = fts.rowid"
                if used_fts else f"{TABLE_VISITS} v")
    try:
        rows = db.execute(
            f"SELECT CAST(strftime('%w', v.visit_time_utc, ?) AS INT) AS dow, "
            f"CAST(strftime('%H', v.visit_time_utc, ?) AS INT) AS hour, "
            f"COUNT(*) AS count FROM {fts_join} "
            f"WHERE {w} AND v.visit_time_utc != '' GROUP BY dow, hour", [tzmod, tzmod] + p
        ).fetchall()
    except sqlite3.OperationalError as exc:
        return jsonify({"error": f"heatmap failed: {exc}", "cells": []}), 400
    return jsonify({"cells": [dict(r) for r in rows]})


@app.route("/api/browse")
def api_browse():
    """Browse server filesystem for file picker."""
    target = request.args.get("path", "/")
    target = Path(target).resolve()
    if not _is_within_browse_roots(target):
        return jsonify({"error": "path outside allowed roots", "path": str(target),
                        "allowed_roots": [str(r) for r in BROWSE_ROOTS]}), 403
    if not target.exists():
        return jsonify({"error": "path not found", "path": str(target)}), 404
    if not target.is_dir():
        # If it's a file, return parent listing with this file highlighted
        target = target.parent

    entries = []
    try:
        for entry in sorted(target.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
            try:
                stat = entry.stat()
                entries.append({
                    "name": entry.name,
                    "path": str(entry),
                    "is_dir": entry.is_dir(),
                    "size": stat.st_size if not entry.is_dir() else None,
                    "mtime": stat.st_mtime,
                    "ingestable": (
                        entry.is_dir()
                        or entry.suffix.lower() in (".7z", ".zip", ".tar", ".gz", ".tgz")
                        or entry.name.endswith(".tar.gz")
                    ),
                })
            except (PermissionError, OSError):
                continue
    except PermissionError:
        return jsonify({"error": "permission denied", "path": str(target)}), 403

    return jsonify({
        "path": str(target),
        "parent": str(target.parent) if target != target.parent else None,
        "entries": entries,
        "cwd": os.getcwd(),
    })


@app.route("/api/sources")
def api_sources():
    """List all ingested sources with per-source visit counts."""
    db = _get_db()
    rows = db.execute(
        f"SELECT il.id, il.source_db, il.browser, il.os_platform, il.os_username, "
        f"il.browser_profile, il.endpoint_name, il.row_count AS ingested_rows, il.ingested_at, "
        f"il.source_sha256, il.source_size_bytes, il.tool_version, il.classifier_version, "
        f"COUNT(v.id) AS live_rows "
        f"FROM ingest_log il "
        f"LEFT JOIN {TABLE_VISITS} v ON v.source_db_path = il.source_db "
        f"GROUP BY il.id ORDER BY il.ingested_at DESC"
    ).fetchall()
    return jsonify({"sources": [dict(r) for r in rows]})


@app.route("/api/sources/delete", methods=["POST"])
@require_local
def api_sources_delete():
    """Delete visits from selected sources by ingest_log IDs."""
    body = request.get_json(silent=True) or {}
    ids = body.get("ids", [])
    if not ids or not isinstance(ids, list):
        return jsonify({"error": "ids array required"}), 400

    db = _get_db()
    # Look up source_db keys for the given ingest_log IDs
    placeholders = ",".join("?" * len(ids))
    source_rows = db.execute(
        f"SELECT id, source_db FROM ingest_log WHERE id IN ({placeholders})",
        ids
    ).fetchall()
    if not source_rows:
        return jsonify({"error": "no matching sources found"}), 404

    deleted_visits = 0
    deleted_sources = []
    for row in source_rows:
        src_id, src_db = row["id"], row["source_db"]
        cur = db.execute(
            f"DELETE FROM {TABLE_VISITS} WHERE source_db_path = ?", (src_db,)
        )
        deleted_visits += cur.rowcount
        db.execute("DELETE FROM ingest_log WHERE id = ?", (src_id,))
        deleted_sources.append(src_db)

    db.commit()
    rebuild_fts(g.db_path)
    log_action(g.db_path, "delete_source", target=", ".join(deleted_sources),
               after=deleted_visits, detail=f"{len(deleted_sources)} source(s)")
    return jsonify({
        "status": "ok",
        "deleted_visits": deleted_visits,
        "deleted_sources": deleted_sources,
    })


@app.route("/api/clear", methods=["POST"])
@require_local
def api_clear():
    """Wipe all visit data and ingest log, keeping schema intact."""
    db = _get_db()
    before = db.execute(f"SELECT COUNT(*) FROM {TABLE_VISITS}").fetchone()[0]
    db.execute(f"DELETE FROM {TABLE_VISITS}")
    db.execute("DELETE FROM ingest_log")
    db.commit()
    rebuild_fts(g.db_path)
    log_action(g.db_path, "clear", before=before, after=0)
    return jsonify({"status": "ok", "message": "All data cleared"})


@app.route("/api/ingest", methods=["POST"])
@require_local
def api_ingest():
    """Accept archive/directory path and run the full pipeline."""
    body = request.get_json(silent=True) or {}
    path_str = body.get("path", "")
    clear_first = body.get("clear", False)
    raw_passwords = body.get("passwords") or []
    if not isinstance(raw_passwords, list):
        return jsonify({"error": "passwords must be a JSON array"}), 400
    passwords = [str(p) for p in raw_passwords if isinstance(p, (str, int))]

    if not path_str:
        return jsonify({"error": "path required"}), 400

    target = Path(path_str).resolve()
    if not target.exists():
        return jsonify({"error": f"not found: {target}"}), 400

    if clear_first:
        db = _get_db()
        db.execute(f"DELETE FROM {TABLE_VISITS}")
        db.execute("DELETE FROM ingest_log")
        db.commit()
        rebuild_fts(g.db_path)

    stats = run_pipeline(g.db_path, target, passwords=passwords)
    # Guarantee a consistent, searchable FTS index after a bulk ingest. Inserts
    # go through the auto-sync triggers, but an explicit rebuild removes the
    # "search silently returns nothing" failure class (e.g. carve path, or a
    # pre-existing visits table restored without its FTS shadow).
    rebuild_fts(g.db_path)
    stats["fts_rows"] = fts_row_count(g.db_path)
    log_action(g.db_path, "ingest", target=str(target),
               after=stats.get("total_new_rows", 0),
               detail=f"{stats.get('databases_found', 0)} db(s)")
    return jsonify(stats)


@app.route("/api/reingest", methods=["POST"])
@require_local
def api_reingest():
    """Re-run classification (Stage 3) and rebuild FTS index."""
    db = _get_db()
    rows = db.execute(f"SELECT * FROM {TABLE_VISITS}").fetchall()
    from .pipeline.classify import classify_visit
    from .pipeline.ingest import decode_chrome_transition
    from .pipeline.models import VisitRecord

    count = 0
    for row in rows:
        rec = classify_visit(VisitRecord(full_url=row["full_url"], title=row["title"] or ""))
        cols = "dns_host=?, url_path=?, query_string_decoded=?, tags=?, unfurl=?"
        params = [rec.dns_host, rec.url_path, rec.query_string_decoded,
                  json.dumps(rec.tags), json.dumps(rec.unfurl)]
        # Re-derive transition from the persisted raw bitmask (B-9) so a bad
        # decode can be corrected without a full re-ingest (UA-9). Chromium only.
        raw_t = row["raw_transition"] if "raw_transition" in row.keys() else 0
        if row["browser_engine"] == "chromium" and raw_t:
            tt, tq = decode_chrome_transition(raw_t)
            cols += ", transition_type=?, transition_qualifiers=?"
            params += [tt, tq]
        params.append(row["id"])
        db.execute(f"UPDATE {TABLE_VISITS} SET {cols} WHERE id=?", params)
        count += 1

    db.commit()
    rebuild_fts(g.db_path)
    log_action(g.db_path, "reingest", after=count, detail=f"classifier {classifier_version()}")
    return jsonify({"reclassified": count, "classifier_version": classifier_version()})


@app.route("/api/rebuild-fts", methods=["POST"])
@require_local
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
    p.add_argument("--allow-remote", action="store_true",
                   help="Allow non-loopback requests to mutating endpoints. "
                        "Only use behind a reverse proxy that adds auth.")
    p.add_argument("--browse-root", action="append", default=[],
                   help="Restrict /api/browse to these directories (repeatable). "
                        "Defaults to the current working directory.")
    p.add_argument("--archive-password", action="append", default=[],
                   dest="archive_passwords",
                   help="Password to try when extracting encrypted archives. "
                        "Repeat for multiple passwords; tried in order.")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s | %(name)s | %(message)s"
    )

    # Security setup
    global ALLOW_REMOTE, BROWSE_ROOTS
    ALLOW_REMOTE = bool(args.allow_remote)

    if args.browse_root:
        BROWSE_ROOTS = [Path(r).resolve() for r in args.browse_root]
        LOG.info("Browse restricted to: %s", [str(r) for r in BROWSE_ROOTS])
    else:
        BROWSE_ROOTS = [Path.cwd().resolve()]
        LOG.info("Browse restricted to CWD: %s (override with --browse-root)",
                 BROWSE_ROOTS[0])

    is_loopback_host = args.host in ("127.0.0.1", "::1", "localhost")
    if not is_loopback_host:
        if ALLOW_REMOTE:
            LOG.warning("Binding to %s with --allow-remote. Put a reverse "
                        "proxy with auth in front of this server.", args.host)
        else:
            LOG.warning("Binding to %s but mutating endpoints reject non-loopback "
                        "requests. Pass --allow-remote to override.", args.host)

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
        stats = run_pipeline(db_path, src, passwords=args.archive_passwords)
        LOG.info("Done: %d DB(s), %d new rows",
                 stats["databases_found"], stats["total_new_rows"])
        for fail in stats.get("extraction_failures", []):
            LOG.warning("Extraction failed [%s]: %s — %s",
                        fail["reason"], fail["archive"], fail["detail"])

    @app.before_request
    def _inject_db_path():
        g.db_path = db_path

    LOG.info("http://%s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.verbose)


if __name__ == "__main__":
    main()
