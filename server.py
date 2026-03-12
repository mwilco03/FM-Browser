#!/usr/bin/env python3
"""
Forensic Browser History Search Server

Ingests browser history from forensic archives (7z/tar.gz/zip) or directories.
Extracts Safari / Chrome / Firefox history SQLite DBs with schema probing,
detects synced-vs-local visits, and indexes everything into FTS5.

Usage:
    python server.py /path/to/archive.7z --port 8888
    python server.py /path/to/extracted/dir --port 8888
"""
from __future__ import annotations

import argparse
import base64
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from collections import OrderedDict
from datetime import datetime, timezone
from enum import Enum, unique
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote_plus, urlparse

from flask import Flask, g, jsonify, request, send_from_directory

LOG = logging.getLogger("history_search")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

@unique
class Browser(Enum):
    CHROME = "chrome"; SAFARI = "safari"; FIREFOX = "firefox"; UNKNOWN = "unknown"

@unique
class VisitOrigin(Enum):
    LOCAL = "local"; SYNCED = "synced"; UNKNOWN = "unknown"

@unique
class HostOS(Enum):
    MACOS = "macos"; WINDOWS = "windows"; LINUX = "linux"; UNKNOWN = "unknown"

@unique
class TimeInterval(Enum):
    HOUR = "hour"; DAY = "day"; WEEK = "week"; MONTH = "month"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ARCHIVE_PASSWORD = "infected"

CHROME_EPOCH_OFFSET_S = 11644473600
SAFARI_EPOCH_OFFSET_S = 978307200
TICK_DIVISOR = 1_000_000

CHROME_TRANSITION_CORE = {
    0:"link",1:"typed",2:"auto_bookmark",3:"auto_subframe",4:"manual_subframe",
    5:"generated",6:"start_page",7:"form_submit",8:"reload",9:"keyword",10:"keyword_generated",
}
CHROME_TRANSITION_QUALIFIERS = {
    0x00800000:"blocked",0x01000000:"forward_back",0x02000000:"from_address_bar",
    0x04000000:"home_page",0x08000000:"from_api",0x10000000:"chain_start",
    0x20000000:"chain_end",0x40000000:"client_redirect",0x80000000:"server_redirect",
}
FIREFOX_VISIT_TYPE = {
    1:"link",2:"typed",3:"bookmark",4:"embed",5:"redirect_permanent",
    6:"redirect_temporary",7:"download",8:"framed_link",9:"reload",
}

SCHEMA_PROBES: Dict[Browser, str] = {
    Browser.CHROME:  "SELECT 1 FROM urls LIMIT 1",
    Browser.SAFARI:  "SELECT 1 FROM history_items LIMIT 1",
    Browser.FIREFOX: "SELECT 1 FROM moz_places LIMIT 1",
}

OS_PATH_INDICATORS: Dict[HostOS, List[re.Pattern]] = {
    HostOS.WINDOWS: [
        re.compile(r"(Users|Documents and Settings)[\\/].*AppData", re.I),
        re.compile(r"[A-Z]:[\\/]", re.I),
    ],
    HostOS.MACOS: [
        re.compile(r"Library[\\/](Application Support|Safari)", re.I),
        re.compile(r"/Users/[^/]+/Library", re.I),
    ],
    HostOS.LINUX: [
        re.compile(r"/home/[^/]+/\.(mozilla|config/(google-chrome|chromium))", re.I),
    ],
}

INTERESTING_PATTERNS = {
    "base64_payload":  re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    "jwt_token":       re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
    "ip_address_host": re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}"),
    "uncommon_port":   re.compile(r":(\d{4,5})(/|$)"),
    "data_uri":        re.compile(r"^data:[^;]+;base64,"),
    "long_hex":        re.compile(r"[0-9a-f]{32,}", re.I),
    "oauth_code":      re.compile(r"(code|token|access_token|id_token)=[A-Za-z0-9._-]{20,}"),
    "protobuf_url":    re.compile(r"![\d]+[a-z]"),
    "file_download":   re.compile(r"\.(exe|msi|dmg|pkg|bat|ps1|sh|cmd|scr|dll|jar|apk|ipa)\b", re.I),
    "suspicious_tld":  re.compile(r"\.(tk|ml|ga|cf|gq|top|xyz|work|click|loan|racing|win|bid|stream)\b", re.I),
}

_B64_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r")

DEFAULT_SEARCH_LIMIT = 50
MAX_SEARCH_LIMIT = 500

TABLE_VISITS = "visits"
TABLE_FTS = "visits_fts"
FTS_COLUMNS = ("full_url", "title", "query_string", "dns_host")

INTERVAL_STRFTIME = {
    TimeInterval.HOUR:"%Y-%m-%dT%H:00:00Z", TimeInterval.DAY:"%Y-%m-%d",
    TimeInterval.WEEK:"%Y-W%W", TimeInterval.MONTH:"%Y-%m",
}

TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f")

# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

SCHEMA_DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_VISITS} (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user            TEXT NOT NULL DEFAULT '',
    browser         TEXT NOT NULL DEFAULT '',
    host_os         TEXT NOT NULL DEFAULT '',
    profile_name    TEXT NOT NULL DEFAULT '',
    visit_time_utc  TEXT NOT NULL DEFAULT '',
    dns_host        TEXT NOT NULL DEFAULT '',
    full_url        TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    query_string    TEXT NOT NULL DEFAULT '',
    url_path        TEXT NOT NULL DEFAULT '',
    url_scheme      TEXT NOT NULL DEFAULT '',
    url_port        INTEGER,
    visit_origin    TEXT NOT NULL DEFAULT 'unknown',
    transition_type TEXT NOT NULL DEFAULT '',
    visit_duration_s REAL NOT NULL DEFAULT 0,
    source_db       TEXT NOT NULL DEFAULT '',
    interesting     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_v_host    ON {TABLE_VISITS}(dns_host);
CREATE INDEX IF NOT EXISTS idx_v_time    ON {TABLE_VISITS}(visit_time_utc);
CREATE INDEX IF NOT EXISTS idx_v_browser ON {TABLE_VISITS}(browser);
CREATE INDEX IF NOT EXISTS idx_v_user    ON {TABLE_VISITS}(user);
CREATE INDEX IF NOT EXISTS idx_v_origin  ON {TABLE_VISITS}(visit_origin);
CREATE INDEX IF NOT EXISTS idx_v_os      ON {TABLE_VISITS}(host_os);

CREATE VIRTUAL TABLE IF NOT EXISTS {TABLE_FTS} USING fts5(
    {', '.join(FTS_COLUMNS)}, content={TABLE_VISITS}, content_rowid=id
);

CREATE TRIGGER IF NOT EXISTS trg_ai AFTER INSERT ON {TABLE_VISITS} BEGIN
    INSERT INTO {TABLE_FTS}(rowid,{','.join(FTS_COLUMNS)})
    VALUES(new.id,{','.join('new.'+c for c in FTS_COLUMNS)});
END;
CREATE TRIGGER IF NOT EXISTS trg_ad AFTER DELETE ON {TABLE_VISITS} BEGIN
    INSERT INTO {TABLE_FTS}({TABLE_FTS},rowid,{','.join(FTS_COLUMNS)})
    VALUES('delete',old.id,{','.join('old.'+c for c in FTS_COLUMNS)});
END;
CREATE TRIGGER IF NOT EXISTS trg_au AFTER UPDATE ON {TABLE_VISITS} BEGIN
    INSERT INTO {TABLE_FTS}({TABLE_FTS},rowid,{','.join(FTS_COLUMNS)})
    VALUES('delete',old.id,{','.join('old.'+c for c in FTS_COLUMNS)});
    INSERT INTO {TABLE_FTS}(rowid,{','.join(FTS_COLUMNS)})
    VALUES(new.id,{','.join('new.'+c for c in FTS_COLUMNS)});
END;

CREATE TABLE IF NOT EXISTS ingest_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_db TEXT NOT NULL, browser TEXT NOT NULL,
    host_os TEXT NOT NULL DEFAULT '', user TEXT NOT NULL DEFAULT '',
    row_count INTEGER NOT NULL DEFAULT 0,
    ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------

def extract_archive(archive_path: Path, dest: Path) -> Path:
    archive_path = archive_path.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    suffix = archive_path.suffix.lower()
    suffixes = "".join(s.lower() for s in archive_path.suffixes)

    LOG.info("Extracting: %s", archive_path.name)

    if suffix == ".7z":
        subprocess.run(
            ["7z","x",f"-p{ARCHIVE_PASSWORD}",f"-o{dest}","-y",str(archive_path)],
            check=True, capture_output=True)
    elif suffix == ".zip":
        # Try with password, then without
        r = subprocess.run(["unzip","-o","-P",ARCHIVE_PASSWORD,str(archive_path),"-d",str(dest)],
                           capture_output=True)
        if r.returncode != 0:
            subprocess.run(["unzip","-o",str(archive_path),"-d",str(dest)],
                           check=True, capture_output=True)
    elif ".tar" in suffixes or suffix in (".tgz",".gz"):
        subprocess.run(["tar","xf",str(archive_path),"-C",str(dest)],
                       check=True, capture_output=True)
    else:
        LOG.warning("Unknown archive format: %s", suffix)
        return archive_path

    # Recurse into nested archives
    nested_exts = {".7z",".zip",".tgz",".tar"}
    for child in list(dest.rglob("*")):
        if not child.is_file():
            continue
        child_sfx = "".join(s.lower() for s in child.suffixes)
        if child.suffix.lower() in nested_exts or child_sfx.endswith(".tar.gz"):
            nested_dest = child.parent / (child.stem + "_extracted")
            try:
                extract_archive(child, nested_dest)
                LOG.info("  nested: %s", child.name)
            except Exception as e:
                LOG.warning("  nested extract failed %s: %s", child.name, e)
    return dest

# ---------------------------------------------------------------------------
# DB discovery (schema probing)
# ---------------------------------------------------------------------------

def _has_sqlite_header(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(16).startswith(b"SQLite format 3")
    except Exception:
        return False

def _probe_browser(conn: sqlite3.Connection) -> Browser:
    for browser, sql in SCHEMA_PROBES.items():
        try:
            conn.execute(sql)
            return browser
        except sqlite3.Error:
            continue
    return Browser.UNKNOWN

def _has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    try:
        return column in [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    except sqlite3.Error:
        return False

def discover_databases(root: Path) -> List[Tuple[Path, Browser]]:
    results = []
    seen: Set[int] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(path.name.endswith(s) for s in ("-wal","-shm","-journal")):
            continue
        try:
            ino = path.stat().st_ino
            if ino in seen: continue
            seen.add(ino)
        except OSError:
            continue
        if not _has_sqlite_header(path):
            continue
        try:
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
                browser = _probe_browser(conn)
                if browser != Browser.UNKNOWN:
                    results.append((path, browser))
        except sqlite3.Error:
            continue
    LOG.info("Discovered %d history database(s)", len(results))
    return results

# ---------------------------------------------------------------------------
# Path metadata
# ---------------------------------------------------------------------------

def detect_host_os(path: Path) -> HostOS:
    s = str(path)
    for hos, patterns in OS_PATH_INDICATORS.items():
        if any(p.search(s) for p in patterns):
            return hos
    return HostOS.UNKNOWN

def extract_username(path: Path) -> str:
    parts = list(path.parts)
    lower = [p.lower() for p in parts]
    for idx, seg in enumerate(lower):
        if seg in ("users","documents and settings","home") and idx+1 < len(parts):
            cand = parts[idx+1]
            if cand.lower() not in ("default","public","all users","default user"):
                return cand
    for idx, seg in enumerate(lower):
        if seg in ("library","appdata") and idx >= 1:
            return parts[idx-1]
    return ""

def extract_profile(path: Path, browser: Browser) -> str:
    parts = list(path.parts)
    lower = [p.lower() for p in parts]
    if browser == Browser.CHROME:
        for idx, seg in enumerate(lower):
            if seg == "user data" and idx+1 < len(parts):
                return parts[idx+1]
    if browser == Browser.FIREFOX:
        for idx, seg in enumerate(lower):
            if seg == "profiles" and idx+1 < len(parts):
                return parts[idx+1]
    return "Default" if browser == Browser.SAFARI else ""

# ---------------------------------------------------------------------------
# URL parsing & interesting detection
# ---------------------------------------------------------------------------

def _looks_b64(s: str) -> bool:
    if not s or len(s) < 8: return False
    raw = s.strip()
    try: b = raw.encode("utf-8")
    except: return False
    if any(ch not in _B64_CHARS for ch in b): return False
    if len(raw.replace("\n","").replace("\r","")) % 4 != 0: return False
    try:
        base64.b64decode(raw, validate=True).decode("utf-8")
        return True
    except: return False

def _maybe_b64(v: str) -> str:
    if _looks_b64(v):
        try: return base64.b64decode(v).decode("utf-8")
        except: pass
    return v

def parse_url_full(url: str) -> Dict[str, Any]:
    try: parsed = urlparse(url)
    except: return {"host":"","query_string":"","path":"","scheme":"","port":None}
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    ordered: OrderedDict[str,List[str]] = OrderedDict()
    for k,v in pairs:
        ordered.setdefault(unquote_plus(k),[]).append(_maybe_b64(unquote_plus(v)))
    flat = [f"{k}={v}" for k,vs in ordered.items() for v in vs]
    return {
        "host": parsed.hostname or "", "query_string": "&".join(flat),
        "path": parsed.path or "", "scheme": parsed.scheme or "", "port": parsed.port,
    }

def detect_interesting(url: str, qs: str, title: str) -> str:
    combined = f"{url} {qs} {title}"
    tags = [name for name, pat in INTERESTING_PATTERNS.items() if pat.search(combined)]
    try:
        scheme = urlparse(url).scheme.lower()
        normal_schemes = {"http","https","ftp","file","chrome","about","safari",
                          "blob","data","javascript","mailto","chrome-extension","moz-extension"}
        if scheme and scheme not in normal_schemes:
            tags.append(f"scheme:{scheme}")
    except: pass
    return ",".join(sorted(set(tags)))

def normalize_ts(s: str) -> str:
    if not s: return ""
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).isoformat().replace("+00:00","Z")
        except ValueError: continue
    return s

def decode_chrome_transition(raw: int) -> str:
    if not raw: return ""
    core = CHROME_TRANSITION_CORE.get(raw & 0xFF, f"unk_{raw & 0xFF}")
    quals = [n for bit,n in CHROME_TRANSITION_QUALIFIERS.items() if raw & bit]
    return "|".join([core] + quals)

# ---------------------------------------------------------------------------
# Browser extractors
# ---------------------------------------------------------------------------

def extract_chrome(conn: sqlite3.Connection) -> List[Dict[str,Any]]:
    has_originator = _has_column(conn, "visits", "originator_cache_guid")
    has_sync = _has_column(conn, "visits", "is_known_to_sync")
    has_dur = _has_column(conn, "visits", "visit_duration")
    has_trans = _has_column(conn, "visits", "transition")

    cols = [
        "u.url", "u.title",
        f"datetime(v.visit_time/{TICK_DIVISOR}-{CHROME_EPOCH_OFFSET_S},'unixepoch') AS vt",
        "v.transition" if has_trans else "0 AS transition",
        f"CAST(v.visit_duration AS REAL)/{TICK_DIVISOR}" if has_dur else "0.0",
        "v.originator_cache_guid" if has_originator else "'' AS originator_cache_guid",
        "v.is_known_to_sync" if has_sync else "0 AS is_known_to_sync",
    ]
    sql = f"SELECT {','.join(cols)} FROM visits v JOIN urls u ON u.id=v.url WHERE u.url IS NOT NULL ORDER BY v.visit_time DESC"

    rows = []
    for url,title,vt,trans,dur,orig_guid,sync_flag in conn.execute(sql).fetchall():
        if orig_guid and orig_guid.strip():
            origin = VisitOrigin.SYNCED
        elif sync_flag:
            origin = VisitOrigin.SYNCED
        else:
            origin = VisitOrigin.LOCAL
        rows.append({"url":url or "","title":title or "","visit_time_utc":vt or "",
                      "transition":decode_chrome_transition(trans),"duration_s":dur or 0.0,
                      "visit_origin":origin.value})
    return rows

def extract_safari(conn: sqlite3.Connection) -> List[Dict[str,Any]]:
    has_origin = _has_column(conn, "history_visits", "origin")
    origin_col = "hv.origin" if has_origin else "0 AS origin"

    sqls = [
        f"""SELECT hi.url, COALESCE(hi.title,''), datetime(hv.visit_time+{SAFARI_EPOCH_OFFSET_S},'unixepoch'),
            {origin_col} FROM history_visits hv JOIN history_items hi ON hi.id=hv.history_item ORDER BY hv.visit_time DESC""",
    ]
    for sql in sqls:
        try:
            rows = []
            for url,title,vt,orig_val in conn.execute(sql).fetchall():
                origin = VisitOrigin.SYNCED if (has_origin and orig_val and int(orig_val)!=0) else VisitOrigin.LOCAL
                rows.append({"url":url or "","title":title or "","visit_time_utc":vt or "",
                              "transition":"","duration_s":0.0,"visit_origin":origin.value})
            return rows
        except sqlite3.Error:
            continue
    return []

def extract_firefox(conn: sqlite3.Connection) -> List[Dict[str,Any]]:
    has_vtype = _has_column(conn, "moz_historyvisits", "visit_type")
    has_fc = _has_column(conn, "moz_places", "foreign_count")

    # Check for Sync metadata
    has_sync_meta = False
    try:
        conn.execute("SELECT 1 FROM moz_meta WHERE key LIKE 'sync%' LIMIT 1").fetchone()
        has_sync_meta = True
    except sqlite3.Error: pass

    vt_col = "v.visit_type" if has_vtype else "0"
    sql = f"""SELECT p.url, COALESCE(p.title,''),
              datetime(v.visit_date/{TICK_DIVISOR},'unixepoch'), {vt_col}, p.frecency
              FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id
              WHERE p.url IS NOT NULL ORDER BY v.visit_date DESC"""
    try:
        rows = []
        for url,title,vt,visit_type,frec in conn.execute(sql).fetchall():
            trans = FIREFOX_VISIT_TYPE.get(visit_type, f"type_{visit_type}")
            origin = VisitOrigin.SYNCED if (has_sync_meta and frec is not None and frec < 0) else VisitOrigin.LOCAL
            rows.append({"url":url or "","title":title or "","visit_time_utc":vt or "",
                          "transition":trans,"duration_s":0.0,"visit_origin":origin.value})
        return rows
    except sqlite3.Error:
        # Fallback: moz_places only
        rows = []
        for url,title,vt in conn.execute(
            f"SELECT url,COALESCE(title,''),datetime(last_visit_date/{TICK_DIVISOR},'unixepoch') FROM moz_places WHERE last_visit_date IS NOT NULL AND url IS NOT NULL ORDER BY last_visit_date DESC"
        ).fetchall():
            rows.append({"url":url or "","title":title or "","visit_time_utc":vt or "",
                          "transition":"","duration_s":0.0,"visit_origin":VisitOrigin.UNKNOWN.value})
        return rows

EXTRACTORS = {Browser.CHROME: extract_chrome, Browser.SAFARI: extract_safari, Browser.FIREFOX: extract_firefox}

# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def ingest_into_index(index_db: str, source_root: Path) -> Dict[str, Any]:
    db_list = discover_databases(source_root)
    stats: Dict[str,Any] = {"databases_found": len(db_list), "ingested": []}

    with sqlite3.connect(index_db) as conn:
        conn.executescript(SCHEMA_DDL)
        for db_path, browser in db_list:
            src = str(db_path)
            if conn.execute("SELECT 1 FROM ingest_log WHERE source_db=?",(src,)).fetchone():
                stats["ingested"].append({"path":src,"browser":browser.value,"rows":0,"status":"skipped"})
                continue

            hos = detect_host_os(db_path)
            user = extract_username(db_path)
            profile = extract_profile(db_path, browser)
            extractor = EXTRACTORS.get(browser)
            if not extractor: continue

            try:
                with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as src_conn:
                    raw = extractor(src_conn)
            except sqlite3.Error as e:
                stats["ingested"].append({"path":src,"browser":browser.value,"rows":0,"status":f"error:{e}"})
                continue
            if not raw: continue

            batch = []
            for r in raw:
                p = parse_url_full(r["url"])
                ts = normalize_ts(r["visit_time_utc"])
                intrstg = detect_interesting(r["url"], p["query_string"], r["title"])
                batch.append((
                    user, browser.value, hos.value, profile, ts,
                    p["host"], r["url"], r["title"], p["query_string"], p["path"],
                    p["scheme"], p["port"], r["visit_origin"], r["transition"],
                    r["duration_s"], src, intrstg,
                ))

            conn.executemany(f"""INSERT INTO {TABLE_VISITS}
                (user,browser,host_os,profile_name,visit_time_utc,dns_host,full_url,title,
                 query_string,url_path,url_scheme,url_port,visit_origin,transition_type,
                 visit_duration_s,source_db,interesting) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", batch)
            conn.execute("INSERT INTO ingest_log(source_db,browser,host_os,user,row_count) VALUES(?,?,?,?,?)",
                         (src,browser.value,hos.value,user,len(batch)))
            conn.commit()
            LOG.info("Ingested %d rows: %s [%s/%s/%s]", len(batch), db_path.name, browser.value, hos.value, user or "?")
            stats["ingested"].append({"path":src,"browser":browser.value,"host_os":hos.value,
                                      "user":user,"profile":profile,"rows":len(batch),"status":"ingested"})
    return stats

# ---------------------------------------------------------------------------
# Flask helpers
# ---------------------------------------------------------------------------

def _get_db():
    if "db" not in g:
        g.db = sqlite3.connect(g.db_path)
        g.db.row_factory = sqlite3.Row
    return g.db

def _build_where(filters, fts_q=None):
    clauses, params = [], []
    if fts_q:
        clauses.append(f"{TABLE_FTS} MATCH ?"); params.append(fts_q)
    col_map = {"dns_host":"v.dns_host=?","browser":"v.browser=?","user":"v.user=?",
               "host_os":"v.host_os=?","origin":"v.visit_origin=?"}
    for k,sql_c in col_map.items():
        v = filters.get(k)
        if v: clauses.append(sql_c); params.append(v)
    if filters.get("start"): clauses.append("v.visit_time_utc>=?"); params.append(filters["start"])
    if filters.get("end"):   clauses.append("v.visit_time_utc<=?"); params.append(filters["end"])
    return (" AND ".join(clauses) or "1=1"), params

def _filters():
    return {k: request.args.get(v) for k,v in
            {"dns_host":"host","browser":"browser","user":"user","host_os":"os",
             "origin":"origin","start":"start","end":"end"}.items()}

# ---------------------------------------------------------------------------
# Flask app + API
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder="static")

@app.teardown_appcontext
def _teardown(exc=None):
    db = g.pop("db", None)
    if db: db.close()

@app.route("/")
def index(): return send_from_directory(app.static_folder, "index.html")

@app.route("/api/search")
def api_search():
    db = _get_db(); q = request.args.get("q","").strip()
    limit = min(int(request.args.get("limit",DEFAULT_SEARCH_LIMIT)), MAX_SEARCH_LIMIT)
    offset = int(request.args.get("offset",0)); f = _filters()
    if q:
        w,p = _build_where(f, fts_q=q)
        sql = f"SELECT v.* FROM {TABLE_FTS} fts JOIN {TABLE_VISITS} v ON v.id=fts.rowid WHERE {w} ORDER BY rank LIMIT ? OFFSET ?"
        csql = f"SELECT COUNT(*) FROM {TABLE_FTS} fts JOIN {TABLE_VISITS} v ON v.id=fts.rowid WHERE {w}"
    else:
        w,p = _build_where(f)
        sql = f"SELECT v.* FROM {TABLE_VISITS} v WHERE {w} ORDER BY v.visit_time_utc DESC LIMIT ? OFFSET ?"
        csql = f"SELECT COUNT(*) FROM {TABLE_VISITS} v WHERE {w}"
    total = db.execute(csql,p).fetchone()[0]
    rows = [{k:r[k] for k in r.keys()} for r in db.execute(sql,p+[limit,offset]).fetchall()]
    return jsonify({"total":total,"limit":limit,"offset":offset,"results":rows})

@app.route("/api/stats")
def api_stats():
    db = _get_db(); t = TABLE_VISITS
    total = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    hosts = db.execute(f"SELECT COUNT(DISTINCT dns_host) FROM {t}").fetchone()[0]
    users = db.execute(f"SELECT COUNT(DISTINCT user) FROM {t} WHERE user!=''").fetchone()[0]
    browsers = [dict(r) for r in db.execute(f"SELECT browser,COUNT(*)as count FROM {t} GROUP BY browser ORDER BY count DESC").fetchall()]
    os_b = [dict(r) for r in db.execute(f"SELECT host_os,COUNT(*)as count FROM {t} WHERE host_os!='' GROUP BY host_os ORDER BY count DESC").fetchall()]
    origin_b = [dict(r) for r in db.execute(f"SELECT visit_origin,COUNT(*)as count FROM {t} GROUP BY visit_origin ORDER BY count DESC").fetchall()]
    tr = db.execute(f"SELECT MIN(visit_time_utc),MAX(visit_time_utc) FROM {t}").fetchone()
    ingest = [dict(r) for r in db.execute("SELECT * FROM ingest_log ORDER BY ingested_at DESC").fetchall()]
    return jsonify({"total_visits":total,"unique_hosts":hosts,"unique_users":users,"browsers":browsers,
                     "os_breakdown":os_b,"origin_breakdown":origin_b,"earliest":tr[0],"latest":tr[1],"ingest_log":ingest})

@app.route("/api/hosts")
def api_hosts():
    db = _get_db(); limit = int(request.args.get("limit",30)); q = request.args.get("q","").strip(); f = _filters()
    w,p = _build_where(f)
    if q: w += " AND v.dns_host LIKE ?"; p.append(f"%{q}%")
    rows = db.execute(f"SELECT dns_host,COUNT(*)as count FROM {TABLE_VISITS} v WHERE {w} GROUP BY dns_host ORDER BY count DESC LIMIT ?",p+[limit]).fetchall()
    return jsonify({"hosts":[dict(r) for r in rows]})

@app.route("/api/timeline")
def api_timeline():
    db = _get_db()
    try: iv = TimeInterval(request.args.get("interval","day"))
    except ValueError: iv = TimeInterval.DAY
    f = _filters(); w,p = _build_where(f); pat = INTERVAL_STRFTIME[iv]
    rows = db.execute(f"SELECT strftime('{pat}',visit_time_utc) as bucket,COUNT(*)as count FROM {TABLE_VISITS} v WHERE {w} AND visit_time_utc!='' GROUP BY bucket ORDER BY bucket",p).fetchall()
    return jsonify({"interval":iv.value,"buckets":[dict(r) for r in rows]})

@app.route("/api/heatmap")
def api_heatmap():
    db = _get_db(); f = _filters(); w,p = _build_where(f)
    rows = db.execute(f"SELECT CAST(strftime('%w',visit_time_utc)AS INT)as dow,CAST(strftime('%H',visit_time_utc)AS INT)as hour,COUNT(*)as count FROM {TABLE_VISITS} v WHERE {w} AND visit_time_utc!='' GROUP BY dow,hour",p).fetchall()
    return jsonify({"cells":[dict(r) for r in rows]})

@app.route("/api/interesting")
def api_interesting():
    db = _get_db(); limit = min(int(request.args.get("limit",100)),500); tag = request.args.get("tag","").strip()
    if tag:
        rows = db.execute(f"SELECT * FROM {TABLE_VISITS} WHERE interesting LIKE ? ORDER BY visit_time_utc DESC LIMIT ?",(f"%{tag}%",limit)).fetchall()
    else:
        rows = db.execute(f"SELECT * FROM {TABLE_VISITS} WHERE interesting!='' ORDER BY visit_time_utc DESC LIMIT ?",(limit,)).fetchall()
    tag_counts: Dict[str,int] = {}
    for r in db.execute(f"SELECT interesting FROM {TABLE_VISITS} WHERE interesting!=''").fetchall():
        for t in r["interesting"].split(","):
            t = t.strip()
            if t: tag_counts[t] = tag_counts.get(t,0)+1
    return jsonify({"results":[{k:r[k] for k in r.keys()} for r in rows],
                     "tag_summary":sorted([{"tag":t,"count":c} for t,c in tag_counts.items()], key=lambda x:-x["count"])})

@app.route("/api/users")
def api_users():
    db = _get_db()
    return jsonify({"users":[dict(r) for r in db.execute(
        f"SELECT user,host_os,browser,COUNT(*)as count FROM {TABLE_VISITS} WHERE user!='' GROUP BY user,host_os,browser ORDER BY count DESC").fetchall()]})

@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    body = request.get_json(silent=True) or {}
    path_str = body.get("path","")
    if not path_str: return jsonify({"error":"path required"}), 400
    target = Path(path_str).resolve()
    if target.is_file():
        d = Path(tempfile.mkdtemp(prefix="hist_"))
        try:
            extract_archive(target, d)
            stats = ingest_into_index(g.db_path, d)
        finally:
            shutil.rmtree(d, ignore_errors=True)
    elif target.is_dir():
        stats = ingest_into_index(g.db_path, target)
    else:
        return jsonify({"error":f"not found: {target}"}), 400
    return jsonify(stats)

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

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s | %(message)s")
    db_path = os.path.abspath(args.db)

    with sqlite3.connect(db_path) as c: c.executescript(SCHEMA_DDL)
    LOG.info("Index: %s", db_path)

    if args.source:
        src = Path(args.source).resolve()
        if src.is_file():
            d = Path(tempfile.mkdtemp(prefix="hist_"))
            try:
                extract_archive(src, d)
                stats = ingest_into_index(db_path, d)
            finally:
                shutil.rmtree(d, ignore_errors=True)
        elif src.is_dir():
            stats = ingest_into_index(db_path, src)
        else:
            LOG.error("Not found: %s", src); return
        new = sum(e["rows"] for e in stats["ingested"] if e["status"]=="ingested")
        LOG.info("Done: %d DB(s), %d new rows", stats["databases_found"], new)

    @app.before_request
    def _inj(): g.db_path = db_path

    LOG.info("http://%s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.verbose)

if __name__ == "__main__":
    main()
