"""Stage 2: Browser-specific SQLite extraction with per-visit granularity."""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import (
    CHROME_EPOCH_OFFSET_S, CHROME_TRANSITION_CORE, CHROME_TRANSITION_QUALIFIERS,
    CHROME_VISIT_SOURCE, FIREFOX_VISIT_TYPE, MACOS_BROWSER_PATHS,
    OS_PATH_INDICATORS, SAFARI_EPOCH_OFFSET_S, SCHEMA_PROBES,
    TEAMS_LEVELDB_PATHS, TEAMS_LOG_PATHS,
    TICK_DIVISOR, WINDOWS_BROWSER_PATHS,
)
from .enums import Browser, BrowserEngine, BROWSER_ENGINE_MAP, OSPlatform
from .models import SourceMetadata, VisitRecord

LOG = logging.getLogger("history_search.ingest")


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

def _has_sqlite_header(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(16).startswith(b"SQLite format 3")
    except Exception:
        return False


def _has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    try:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        return column in cols
    except sqlite3.Error:
        return False


def _has_table(conn: sqlite3.Connection, table: str) -> bool:
    try:
        conn.execute(f"SELECT 1 FROM {table} LIMIT 1")
        return True
    except sqlite3.Error:
        return False


def _probe_engine(conn: sqlite3.Connection) -> Optional[str]:
    """Probe which browser engine schema this database uses."""
    for engine, sql in SCHEMA_PROBES.items():
        try:
            conn.execute(sql)
            return engine
        except sqlite3.Error:
            continue
    return None


# ---------------------------------------------------------------------------
# Path-based metadata extraction
# ---------------------------------------------------------------------------

def detect_os_platform(path: Path) -> str:
    s = str(path)
    for os_name, patterns in OS_PATH_INDICATORS.items():
        if any(p.search(s) for p in patterns):
            return os_name
    return "unknown"


def detect_source_metadata(db_path: Path, engine: str) -> SourceMetadata:
    """Extract browser, profile, user, and OS from the database file path."""
    path_str = str(db_path).replace("\\", "/")
    meta = SourceMetadata()
    meta.os_platform = detect_os_platform(db_path)

    # Try macOS patterns
    for pattern, browser_name in MACOS_BROWSER_PATHS:
        m = pattern.search(path_str)
        if m:
            meta.browser = browser_name
            meta.os_platform = "macos"
            meta.os_username = m.group(1)
            if m.lastindex and m.lastindex >= 2:
                meta.browser_profile = m.group(2)
            elif browser_name == "safari":
                meta.browser_profile = "Default"
            break

    # Try Windows patterns
    if meta.browser == "unknown":
        for pattern, browser_name in WINDOWS_BROWSER_PATHS:
            m = pattern.search(path_str)
            if m:
                meta.browser = browser_name
                meta.os_platform = "windows"
                meta.os_username = m.group(1)
                if m.lastindex and m.lastindex >= 2:
                    meta.browser_profile = m.group(2)
                break

    # Fallback: infer browser from engine if path didn't match
    if meta.browser == "unknown":
        if engine == "chromium":
            meta.browser = "chrome"
        elif engine == "gecko":
            meta.browser = "firefox"
        elif engine == "webkit":
            meta.browser = "safari"

    # Set engine
    try:
        browser_enum = Browser(meta.browser)
        engine_enum = BROWSER_ENGINE_MAP.get(browser_enum)
        if engine_enum:
            meta.browser_engine = engine_enum.value
        else:
            meta.browser_engine = engine
    except ValueError:
        meta.browser_engine = engine

    # Fallback username extraction
    if not meta.os_username:
        meta.os_username = _extract_username_fallback(db_path)

    return meta


def _extract_username_fallback(path: Path) -> str:
    """Extract username from path segments as a fallback."""
    parts = list(path.parts)
    lower = [p.lower() for p in parts]
    for idx, seg in enumerate(lower):
        if seg in ("users", "documents and settings", "home") and idx + 1 < len(parts):
            cand = parts[idx + 1]
            if cand.lower() not in ("default", "public", "all users", "default user"):
                return cand
    return ""


# ---------------------------------------------------------------------------
# Timestamp conversion
# ---------------------------------------------------------------------------

def _chrome_time_to_utc(chrome_time: int) -> str:
    """Convert Chrome/Chromium timestamp (microseconds since 1601-01-01) to ISO-8601."""
    if not chrome_time or chrome_time <= 0:
        return ""
    try:
        unix_ts = (chrome_time / TICK_DIVISOR) - CHROME_EPOCH_OFFSET_S
        if unix_ts < 0 or unix_ts > 4102444800:  # sanity: before 2100
            return ""
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OSError, OverflowError):
        return ""


def _firefox_time_to_utc(ff_time: int) -> str:
    """Convert Firefox timestamp (microseconds since Unix epoch) to ISO-8601."""
    if not ff_time or ff_time <= 0:
        return ""
    try:
        unix_ts = ff_time / TICK_DIVISOR
        if unix_ts < 0 or unix_ts > 4102444800:
            return ""
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OSError, OverflowError):
        return ""


def _safari_time_to_utc(safari_time: float) -> str:
    """Convert Safari timestamp (seconds since 2001-01-01) to ISO-8601."""
    if safari_time is None:
        return ""
    try:
        unix_ts = safari_time + SAFARI_EPOCH_OFFSET_S
        if unix_ts < 0 or unix_ts > 4102444800:
            return ""
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OSError, OverflowError):
        return ""


# ---------------------------------------------------------------------------
# Chrome transition decoding
# ---------------------------------------------------------------------------

def decode_chrome_transition(raw: int) -> Tuple[str, str]:
    """Decode Chrome transition bitmask into (core_type, qualifier_string)."""
    if not raw:
        return ("other", "")
    core = CHROME_TRANSITION_CORE.get(raw & 0xFF, f"unknown_{raw & 0xFF}")
    quals = [name for bit, name in CHROME_TRANSITION_QUALIFIERS.items() if raw & bit]
    return (core, ",".join(quals))


# ---------------------------------------------------------------------------
# Browser extractors — per-visit rows
# ---------------------------------------------------------------------------

def extract_chromium(conn: sqlite3.Connection, meta: SourceMetadata, provenance: str) -> List[VisitRecord]:
    """Extract per-visit records from a Chromium-engine database."""
    has_visit_source_table = _has_table(conn, "visit_source")
    has_duration = _has_column(conn, "visits", "visit_duration")
    has_transition = _has_column(conn, "visits", "transition")
    has_from_visit = _has_column(conn, "visits", "from_visit")

    # Build the query per the design doc
    cols = [
        "urls.url",
        "urls.title",
        "visits.visit_time",
        "visits.id AS visit_id",
    ]
    if has_from_visit:
        cols.append("visits.from_visit")
    else:
        cols.append("0 AS from_visit")
    if has_transition:
        cols.append("visits.transition")
    else:
        cols.append("0 AS transition")
    if has_duration:
        cols.append("visits.visit_duration")
    else:
        cols.append("0 AS visit_duration")

    join_source = ""
    if has_visit_source_table:
        cols.append("COALESCE(visit_source.source, 0) AS vsource")
        join_source = "LEFT JOIN visit_source ON visit_source.id = visits.id"
    else:
        cols.append("0 AS vsource")

    sql = (
        f"SELECT {', '.join(cols)} FROM visits "
        f"JOIN urls ON urls.id = visits.url "
        f"{join_source} "
        f"ORDER BY visits.visit_time DESC"
    )

    records = []
    try:
        for row in conn.execute(sql).fetchall():
            url, title, visit_time, visit_id, from_visit, transition, duration, vsource = row

            # Timestamp
            ts = _chrome_time_to_utc(visit_time or 0)

            # Visit source
            source_val = CHROME_VISIT_SOURCE.get(vsource, "unknown")

            # Transition
            trans_core, trans_quals = decode_chrome_transition(transition or 0)

            # Duration in ms
            dur_ms = int((duration or 0) / 1000) if duration else 0  # microseconds to ms

            records.append(VisitRecord(
                provenance_chain=provenance,
                source_db_path=str(meta.browser_profile),
                os_platform=meta.os_platform,
                browser=meta.browser,
                browser_engine=meta.browser_engine,
                browser_profile=meta.browser_profile,
                os_username=meta.os_username,
                endpoint_name=meta.endpoint_name,
                visit_time_utc=ts,
                full_url=url or "",
                title=title or "",
                visit_source=source_val,
                visit_source_confidence="confirmed" if has_visit_source_table else "unknown",
                transition_type=trans_core,
                transition_qualifiers=trans_quals,
                visit_duration_ms=dur_ms,
                raw_transition=transition or 0,
                raw_from_visit=from_visit or 0,
                raw_visit_id=visit_id or 0,
            ))
    except sqlite3.Error as e:
        LOG.warning("Chromium extraction error: %s", e)

    return records


def extract_gecko(conn: sqlite3.Connection, meta: SourceMetadata, provenance: str) -> List[VisitRecord]:
    """Extract per-visit records from a Firefox/Gecko database."""
    has_visit_type = _has_column(conn, "moz_historyvisits", "visit_type")
    has_from_visit = _has_column(conn, "moz_historyvisits", "from_visit")

    # Check for Sync metadata
    sync_enabled = False
    try:
        row = conn.execute("SELECT 1 FROM moz_meta WHERE key LIKE '%sync%' LIMIT 1").fetchone()
        if row:
            sync_enabled = True
    except sqlite3.Error:
        pass

    # Also check for storage-sync-v2 indicator
    if not sync_enabled:
        try:
            row = conn.execute("SELECT 1 FROM moz_meta WHERE key = 'sync/deviceID' LIMIT 1").fetchone()
            if row:
                sync_enabled = True
        except sqlite3.Error:
            pass

    vt_col = "v.visit_type" if has_visit_type else "0 AS visit_type"
    fv_col = "v.from_visit" if has_from_visit else "0 AS from_visit"

    sql = (
        f"SELECT p.url, COALESCE(p.title, ''), v.visit_date, v.id AS visit_id, "
        f"{vt_col}, {fv_col}, p.frecency "
        f"FROM moz_historyvisits v "
        f"JOIN moz_places p ON p.id = v.place_id "
        f"WHERE p.url IS NOT NULL "
        f"ORDER BY v.visit_date DESC"
    )

    records = []
    try:
        for row in conn.execute(sql).fetchall():
            url, title, visit_date, visit_id, visit_type, from_visit, frecency = row

            ts = _firefox_time_to_utc(visit_date or 0)

            # Transition type mapping
            trans = FIREFOX_VISIT_TYPE.get(visit_type, "other")

            # Sync detection heuristic
            if not sync_enabled:
                source = "local"
                confidence = "confirmed"
            elif from_visit and from_visit > 0:
                source = "local"
                confidence = "confirmed"
            elif frecency is not None and frecency < 0:
                source = "synced"
                confidence = "likely"
            else:
                source = "unknown"
                confidence = "unknown"

            records.append(VisitRecord(
                provenance_chain=provenance,
                source_db_path=str(meta.browser_profile),
                os_platform=meta.os_platform,
                browser=meta.browser,
                browser_engine=meta.browser_engine,
                browser_profile=meta.browser_profile,
                os_username=meta.os_username,
                endpoint_name=meta.endpoint_name,
                visit_time_utc=ts,
                full_url=url or "",
                title=title or "",
                visit_source=source,
                visit_source_confidence=confidence,
                transition_type=trans,
                raw_from_visit=from_visit or 0,
                raw_visit_id=visit_id or 0,
            ))
    except sqlite3.Error as e:
        LOG.warning("Gecko extraction error: %s", e)
        # Fallback to moz_places summary
        try:
            for row in conn.execute(
                "SELECT url, COALESCE(title,''), last_visit_date "
                "FROM moz_places WHERE last_visit_date IS NOT NULL AND url IS NOT NULL "
                "ORDER BY last_visit_date DESC"
            ).fetchall():
                url, title, lvd = row
                records.append(VisitRecord(
                    provenance_chain=provenance,
                    os_platform=meta.os_platform,
                    browser=meta.browser,
                    browser_engine=meta.browser_engine,
                    browser_profile=meta.browser_profile,
                    os_username=meta.os_username,
                    visit_time_utc=_firefox_time_to_utc(lvd or 0),
                    full_url=url or "",
                    title=title or "",
                ))
        except sqlite3.Error:
            pass

    return records


def extract_webkit(conn: sqlite3.Connection, meta: SourceMetadata, provenance: str) -> List[VisitRecord]:
    """Extract per-visit records from a Safari/WebKit database."""
    has_origin = _has_column(conn, "history_visits", "origin")
    has_redirect_src = _has_column(conn, "history_visits", "redirect_source")
    has_redirect_dst = _has_column(conn, "history_visits", "redirect_destination")
    has_score = _has_column(conn, "history_visits", "score")
    has_tombstones = _has_table(conn, "history_tombstones")

    cols = [
        "history_items.url",
        "COALESCE(history_items.title, '')",
        "history_visits.visit_time",
        "history_visits.id AS visit_id",
    ]
    if has_redirect_src:
        cols.append("history_visits.redirect_source")
    else:
        cols.append("NULL AS redirect_source")
    if has_redirect_dst:
        cols.append("history_visits.redirect_destination")
    else:
        cols.append("NULL AS redirect_destination")
    if has_origin:
        cols.append("history_visits.origin")
    else:
        cols.append("0 AS origin")

    sql = (
        f"SELECT {', '.join(cols)} "
        f"FROM history_visits "
        f"JOIN history_items ON history_items.id = history_visits.history_item "
        f"ORDER BY history_visits.visit_time DESC"
    )

    records = []
    try:
        for row in conn.execute(sql).fetchall():
            url, title, visit_time, visit_id, redirect_src, redirect_dst, origin_val = row

            ts = _safari_time_to_utc(visit_time or 0)

            # Sync detection heuristic
            if has_origin and origin_val and int(origin_val) != 0:
                source = "synced"
                confidence = "likely"
            elif has_tombstones:
                source = "unknown"
                confidence = "unknown"
            else:
                source = "local"
                confidence = "confirmed"

            records.append(VisitRecord(
                provenance_chain=provenance,
                source_db_path=str(meta.browser_profile),
                os_platform=meta.os_platform,
                browser=meta.browser,
                browser_engine=meta.browser_engine,
                browser_profile=meta.browser_profile,
                os_username=meta.os_username,
                endpoint_name=meta.endpoint_name,
                visit_time_utc=ts,
                full_url=url or "",
                title=title or "",
                visit_source=source,
                visit_source_confidence=confidence,
                raw_visit_id=visit_id or 0,
            ))
    except sqlite3.Error as e:
        LOG.warning("WebKit extraction error: %s", e)

    return records


# Engine-to-extractor mapping
ENGINE_EXTRACTORS = {
    "chromium": extract_chromium,
    "gecko": extract_gecko,
    "webkit": extract_webkit,
}


# ---------------------------------------------------------------------------
# Database discovery and ingestion orchestration
# ---------------------------------------------------------------------------

def _is_teams_json(path: Path) -> bool:
    """Check if a file looks like a Teams JSON log with URL data."""
    if path.suffix.lower() != ".json":
        return False
    path_str = str(path)
    return any(p.search(path_str) for p in TEAMS_LOG_PATHS)


def _is_teams_leveldb(path: Path) -> bool:
    """Check if a path is inside a Teams LevelDB directory."""
    path_str = str(path)
    return any(p.search(path_str) for p in TEAMS_LEVELDB_PATHS)


def extract_teams_json(json_path: Path, meta: SourceMetadata, provenance: str) -> List[VisitRecord]:
    """Extract URL visits from Microsoft Teams JSON log files.

    Teams stores activity in JSON files that can contain URLs visited
    within the app (meeting links, shared links, tab URLs, etc.).
    """
    records = []
    try:
        with open(json_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        LOG.debug("Teams JSON parse error %s: %s", json_path, e)
        return records

    # Teams JSON can be a list of events or a dict with events
    events = []
    if isinstance(data, list):
        events = data
    elif isinstance(data, dict):
        # Look for common Teams JSON keys
        for key in ("events", "messages", "activities", "history", "items"):
            if key in data and isinstance(data[key], list):
                events = data[key]
                break
        if not events:
            # Single-level dict might be one event
            events = [data]

    for event in events:
        if not isinstance(event, dict):
            continue

        # Extract URLs from various Teams JSON formats
        url = (event.get("url") or event.get("href") or
               event.get("targetUrl") or event.get("link") or
               event.get("contentUrl") or event.get("meetingUrl") or "")

        if not url or not url.startswith(("http://", "https://")):
            # Try to find URLs in message content
            content = event.get("content") or event.get("body") or event.get("text") or ""
            if isinstance(content, dict):
                content = content.get("content", "")
            urls_in_content = re.findall(r'https?://[^\s<>"\']+', str(content))
            if urls_in_content:
                url = urls_in_content[0]
            else:
                continue

        # Timestamp
        ts = ""
        for ts_key in ("timestamp", "time", "createdDateTime", "composetime",
                        "originalarrivaltime", "arrivalTime", "date"):
            raw_ts = event.get(ts_key)
            if raw_ts:
                ts = _parse_teams_timestamp(raw_ts)
                if ts:
                    break

        title = (event.get("title") or event.get("subject") or
                 event.get("displayName") or event.get("name") or "")

        records.append(VisitRecord(
            provenance_chain=provenance,
            source_db_path=str(json_path),
            os_platform=meta.os_platform,
            browser="teams",
            browser_engine="chromium",
            browser_profile=meta.browser_profile or "Teams",
            os_username=meta.os_username,
            endpoint_name=meta.endpoint_name,
            visit_time_utc=ts,
            full_url=url,
            title=str(title),
            visit_source="local",
            visit_source_confidence="confirmed",
            transition_type="link",
        ))

    if records:
        LOG.info("Extracted %d URLs from Teams JSON: %s", len(records), json_path.name)
    return records


def _parse_teams_timestamp(raw: Any) -> str:
    """Parse various Teams timestamp formats to ISO-8601 UTC."""
    if not raw:
        return ""
    s = str(raw)
    # Already ISO-8601
    if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", s):
        if not s.endswith("Z") and "+" not in s:
            s += "Z"
        return s
    # Unix epoch (seconds or ms)
    try:
        ts_num = float(s)
        if ts_num > 1e12:  # milliseconds
            ts_num /= 1000
        if 0 < ts_num < 4102444800:
            return datetime.fromtimestamp(ts_num, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        pass
    return ""


def discover_databases(root: Path) -> List[Tuple[Path, str, SourceMetadata]]:
    """Walk a directory tree and find all browser history SQLite databases.

    Returns list of (db_path, engine_name, source_metadata).
    Also discovers Teams JSON logs as (json_path, 'teams_json', metadata).
    """
    results = []
    seen_inodes: Set[int] = set()

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # Skip WAL/SHM/journal files
        if any(path.name.endswith(s) for s in ("-wal", "-shm", "-journal")):
            continue
        try:
            ino = path.stat().st_ino
            if ino in seen_inodes:
                continue
            seen_inodes.add(ino)
        except OSError:
            continue

        # Check for Teams JSON files
        if _is_teams_json(path):
            meta = detect_source_metadata(path, "chromium")
            meta.browser = "teams"
            meta.browser_engine = "chromium"
            results.append((path, "teams_json", meta))
            continue

        if not _has_sqlite_header(path):
            continue

        try:
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
                engine = _probe_engine(conn)
                if engine:
                    meta = detect_source_metadata(path, engine)
                    results.append((path, engine, meta))
        except sqlite3.Error:
            continue

    LOG.info("Discovered %d history database(s)", len(results))
    return results


def ingest_database(db_path: Path, engine: str, meta: SourceMetadata, provenance: str = "") -> List[VisitRecord]:
    """Extract all visit records from a single browser history database."""
    prov = provenance or str(db_path)

    # Handle Teams JSON files
    if engine == "teams_json":
        return extract_teams_json(db_path, meta, prov)

    extractor = ENGINE_EXTRACTORS.get(engine)
    if not extractor:
        LOG.warning("No extractor for engine: %s", engine)
        return []

    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
            records = extractor(conn, meta, prov)
            LOG.info("Extracted %d visits from %s [%s/%s/%s]",
                     len(records), db_path.name, meta.browser, meta.os_platform, meta.os_username or "?")
            return records
    except sqlite3.Error as e:
        LOG.error("Failed to ingest %s: %s", db_path, e)
        return []
