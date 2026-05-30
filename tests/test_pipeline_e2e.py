#!/usr/bin/env python3
"""True end-to-end pipeline tests.

Creates synthetic browser history SQLite databases (Chromium, Gecko, WebKit),
runs them through the full pipeline (discover → ingest → classify → index),
then queries the results via the Flask API.

This tests the real pipeline — no manual DB seeding.
"""
import json
import os
import sqlite3
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from history_search.server import app, run_pipeline
from history_search.pipeline.index import init_schema, TABLE_VISITS, get_visit_count, rebuild_fts


# ---------------------------------------------------------------------------
# Helpers: create synthetic browser history databases
# ---------------------------------------------------------------------------

def _create_chromium_db(db_path: Path, visits: list[dict]) -> None:
    """Create a minimal Chromium-style history database with visits."""
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 1,
            typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER DEFAULT 0
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER NOT NULL REFERENCES urls(id),
            visit_time INTEGER NOT NULL,
            from_visit INTEGER DEFAULT 0,
            transition INTEGER DEFAULT 0,
            visit_duration INTEGER DEFAULT 0
        );
        CREATE TABLE visit_source (
            id INTEGER PRIMARY KEY,
            source INTEGER NOT NULL
        );
    """)
    for i, v in enumerate(visits, 1):
        conn.execute(
            "INSERT INTO urls (id, url, title) VALUES (?, ?, ?)",
            (i, v["url"], v.get("title", "")),
        )
        # Chrome timestamps: microseconds since 1601-01-01
        # 2024-06-15T12:00:00Z = Unix 1718452800 → Chrome (1718452800 + 11644473600) * 1e6
        chrome_ts = int((v.get("unix_ts", 1718452800) + 11644473600) * 1_000_000)
        transition = v.get("transition", 1)  # typed
        conn.execute(
            "INSERT INTO visits (id, url, visit_time, from_visit, transition, visit_duration) "
            "VALUES (?, ?, ?, 0, ?, ?)",
            (i, i, chrome_ts, transition, v.get("duration_us", 5_000_000)),
        )
        conn.execute(
            "INSERT INTO visit_source (id, source) VALUES (?, ?)",
            (i, v.get("source", 0)),
        )
    conn.commit()
    conn.close()


def _create_firefox_db(db_path: Path, visits: list[dict]) -> None:
    """Create a minimal Firefox/Gecko-style history database."""
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 1,
            frecency INTEGER DEFAULT 100,
            last_visit_date INTEGER DEFAULT 0
        );
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY,
            place_id INTEGER NOT NULL REFERENCES moz_places(id),
            visit_date INTEGER NOT NULL,
            visit_type INTEGER DEFAULT 1,
            from_visit INTEGER DEFAULT 0
        );
    """)
    for i, v in enumerate(visits, 1):
        # Firefox timestamps: microseconds since Unix epoch
        ff_ts = int(v.get("unix_ts", 1718452800) * 1_000_000)
        conn.execute(
            "INSERT INTO moz_places (id, url, title, frecency) VALUES (?, ?, ?, ?)",
            (i, v["url"], v.get("title", ""), v.get("frecency", 100)),
        )
        conn.execute(
            "INSERT INTO moz_historyvisits (id, place_id, visit_date, visit_type, from_visit) "
            "VALUES (?, ?, ?, ?, 0)",
            (i, i, ff_ts, v.get("visit_type", 1)),
        )
    conn.commit()
    conn.close()


def _create_safari_db(db_path: Path, visits: list[dict]) -> None:
    """Create a minimal Safari/WebKit-style history database."""
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE history_items (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 1
        );
        CREATE TABLE history_visits (
            id INTEGER PRIMARY KEY,
            history_item INTEGER NOT NULL REFERENCES history_items(id),
            visit_time REAL NOT NULL,
            origin INTEGER DEFAULT 0
        );
    """)
    for i, v in enumerate(visits, 1):
        # Safari timestamps: seconds since 2001-01-01
        # 2024-06-15T12:00:00Z = Unix 1718452800 → Safari 1718452800 - 978307200
        safari_ts = v.get("unix_ts", 1718452800) - 978307200
        conn.execute(
            "INSERT INTO history_items (id, url, title) VALUES (?, ?, ?)",
            (i, v["url"], v.get("title", "")),
        )
        conn.execute(
            "INSERT INTO history_visits (id, history_item, visit_time, origin) VALUES (?, ?, ?, ?)",
            (i, i, safari_ts, v.get("origin", 0)),
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

CHROME_VISITS = [
    {
        "url": "https://www.google.com/search?q=forensic+browser+analysis",
        "title": "forensic browser analysis - Google Search",
        "unix_ts": 1718452800,
        "transition": 0x02000001,  # typed + from_address_bar
    },
    {
        "url": "https://drive.google.com/drive/my-drive",
        "title": "My Drive - Google Drive",
        "unix_ts": 1718456400,
        "transition": 0,  # link
        "source": 1,  # synced
    },
    {
        "url": "https://192.168.1.100:8080/admin/panel",
        "title": "Admin Panel",
        "unix_ts": 1718460000,
        "transition": 1,  # typed
    },
]

FIREFOX_VISITS = [
    {
        "url": "https://pastebin.com/raw/abc123",
        "title": "Pastebin Raw Content",
        "unix_ts": 1718463600,
        "visit_type": 2,  # typed
    },
    {
        "url": "https://example.com/download/tool.exe",
        "title": "Download Tool",
        "unix_ts": 1718467200,
        "visit_type": 1,  # link
    },
]

SAFARI_VISITS = [
    {
        "url": "https://docs.google.com/document/d/abc123/edit",
        "title": "Test Document - Google Docs",
        "unix_ts": 1718470800,
    },
    {
        "url": "https://mail.google.com/mail/u/0/#inbox",
        "title": "Gmail - Inbox",
        "unix_ts": 1718474400,
    },
]


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def run_tests():
    passed = 0
    failed = 0

    def check(label, condition, detail=""):
        nonlocal passed, failed
        if condition:
            print(f"[PASS] {label}")
            passed += 1
        else:
            print(f"[FAIL] {label}{' — ' + detail if detail else ''}")
            failed += 1

    # Create temp directories
    work_dir = Path(tempfile.mkdtemp(prefix="e2e_pipeline_"))
    index_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    index_db_path = index_db.name
    index_db.close()

    try:
        # --- Set up fake forensic directory structure ---
        # Chromium DB at a realistic path
        chrome_dir = work_dir / "Users" / "bob" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
        chrome_dir.mkdir(parents=True)
        _create_chromium_db(chrome_dir / "History", CHROME_VISITS)

        # Firefox DB at a realistic path
        ff_dir = work_dir / "Users" / "bob" / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abc123.default"
        ff_dir.mkdir(parents=True)
        _create_firefox_db(ff_dir / "places.sqlite", FIREFOX_VISITS)

        # Safari DB at a realistic path
        safari_dir = work_dir / "Users" / "alice" / "Library" / "Safari"
        safari_dir.mkdir(parents=True)
        _create_safari_db(safari_dir / "History.db", SAFARI_VISITS)

        # ---------------------------------------------------------------
        # TEST: Pipeline discovers all 3 databases
        # ---------------------------------------------------------------
        from history_search.pipeline.ingest import discover_databases
        db_list = discover_databases(work_dir)
        check(
            "discover_databases finds 3 browser DBs",
            len(db_list) == 3,
            f"found {len(db_list)}: {[str(p) for p, _, _ in db_list]}"
        )

        # Check engines detected correctly
        engines = {engine for _, engine, _ in db_list}
        check(
            "correct engines detected (chromium, gecko, webkit)",
            engines == {"chromium", "gecko", "webkit"},
            f"got {engines}"
        )

        # Check metadata extraction
        for db_path, engine, meta in db_list:
            if engine == "chromium":
                check(
                    "Chrome metadata: browser detected",
                    meta.browser == "chrome",
                    f"got browser={meta.browser}"
                )
                check(
                    "Chrome metadata: OS detected as windows",
                    meta.os_platform == "windows",
                    f"got os_platform={meta.os_platform}"
                )
                check(
                    "Chrome metadata: username extracted",
                    meta.os_username == "bob",
                    f"got os_username={meta.os_username}"
                )
            elif engine == "gecko":
                check(
                    "Firefox metadata: browser detected",
                    meta.browser == "firefox",
                    f"got browser={meta.browser}"
                )
            elif engine == "webkit":
                check(
                    "Safari metadata: browser detected",
                    meta.browser == "safari",
                    f"got browser={meta.browser}"
                )
                check(
                    "Safari metadata: username extracted",
                    meta.os_username == "alice",
                    f"got os_username={meta.os_username}"
                )

        # ---------------------------------------------------------------
        # TEST: Full pipeline run (ingest + classify + index)
        # ---------------------------------------------------------------
        init_schema(index_db_path)
        stats = run_pipeline(index_db_path, work_dir)

        check(
            "run_pipeline found 3 databases",
            stats["databases_found"] == 3,
            f"got {stats['databases_found']}"
        )

        total_rows = stats["total_new_rows"]
        expected_rows = len(CHROME_VISITS) + len(FIREFOX_VISITS) + len(SAFARI_VISITS)
        check(
            f"run_pipeline indexed {expected_rows} visits (may include carved)",
            total_rows >= expected_rows,
            f"got {total_rows}"
        )

        # ---------------------------------------------------------------
        # TEST: Verify data in index DB directly
        # ---------------------------------------------------------------
        count = get_visit_count(index_db_path)
        check(
            f"index DB has >= {expected_rows} visits",
            count >= expected_rows,
            f"got {count}"
        )

        # Check classification tags were applied
        with sqlite3.connect(index_db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f"SELECT * FROM {TABLE_VISITS}").fetchall()

            # Find the Google search visit → should have "search_query" tag
            google_search = [r for r in rows if "google.com/search" in r["full_url"]]
            check(
                "Google search visit exists in index",
                len(google_search) >= 1,
                f"found {len(google_search)}"
            )
            if google_search:
                tags = json.loads(google_search[0]["tags"])
                check(
                    "Google search visit has 'search_query' tag",
                    "search_query" in tags,
                    f"tags={tags}"
                )

            # Find drive.google.com → should have "cloud_storage" tag
            drive_visit = [r for r in rows if "drive.google.com" in r["full_url"]]
            check(
                "Google Drive visit exists",
                len(drive_visit) >= 1,
            )
            if drive_visit:
                tags = json.loads(drive_visit[0]["tags"])
                check(
                    "Google Drive visit has 'cloud_storage' tag",
                    "cloud_storage" in tags,
                    f"tags={tags}"
                )

            # Find 192.168.x visit → should have "internal_network" tag
            internal_visit = [r for r in rows if "192.168" in r["full_url"]]
            check(
                "Internal network visit exists",
                len(internal_visit) >= 1,
            )
            if internal_visit:
                tags = json.loads(internal_visit[0]["tags"])
                check(
                    "Internal visit has 'internal_network' tag",
                    "internal_network" in tags,
                    f"tags={tags}"
                )
                check(
                    "Internal visit has 'non_standard_port' tag",
                    "non_standard_port" in tags,
                    f"tags={tags}"
                )

            # Pastebin → should have "paste_site" tag
            paste_visit = [r for r in rows if "pastebin.com" in r["full_url"]]
            check(
                "Pastebin visit exists",
                len(paste_visit) >= 1,
            )
            if paste_visit:
                tags = json.loads(paste_visit[0]["tags"])
                check(
                    "Pastebin visit has 'paste_site' tag",
                    "paste_site" in tags,
                    f"tags={tags}"
                )

            # .exe download → should have "download_url" tag
            dl_visit = [r for r in rows if "tool.exe" in r["full_url"]]
            check(
                "Download visit exists",
                len(dl_visit) >= 1,
            )
            if dl_visit:
                tags = json.loads(dl_visit[0]["tags"])
                check(
                    "Download visit has 'download_url' tag",
                    "download_url" in tags,
                    f"tags={tags}"
                )

            # URL decomposition: dns_host populated
            all_hosts = [r["dns_host"] for r in rows if r["dns_host"]]
            check(
                "All visits have dns_host populated",
                len(all_hosts) >= expected_rows,
                f"got {len(all_hosts)} of {expected_rows}"
            )

            # Unfurl: Google search should have search_terms unfurl
            if google_search:
                unfurl = json.loads(google_search[0]["unfurl"])
                search_unfurls = [u for u in unfurl if u.get("type") == "search_terms"]
                check(
                    "Google search has search_terms unfurl",
                    len(search_unfurls) >= 1,
                    f"unfurl={unfurl}"
                )

        # ---------------------------------------------------------------
        # TEST: Flask API queries work on pipeline-indexed data
        # ---------------------------------------------------------------
        app.config["TESTING"] = True
        client = app.test_client()

        @app.before_request
        def _set_db():
            from flask import g
            g.db_path = index_db_path

        # Search — no query (returns all)
        r = client.get("/api/search")
        data = r.get_json()
        check(
            "API /api/search returns all pipeline-indexed visits",
            r.status_code == 200 and data["total"] >= expected_rows,
            f"status={r.status_code}, total={data.get('total')}"
        )

        # FTS search for "forensic"
        r = client.get("/api/search?q=forensic")
        data = r.get_json()
        check(
            "API FTS search for 'forensic' finds Google search visit",
            r.status_code == 200 and data["total"] >= 1,
            f"total={data.get('total')}"
        )

        # Filter by browser=chrome
        r = client.get("/api/search?browser=chrome")
        data = r.get_json()
        chrome_count = len(CHROME_VISITS)
        check(
            f"API filter browser=chrome returns {chrome_count} visits",
            r.status_code == 200 and data["total"] >= chrome_count,
            f"total={data.get('total')}"
        )

        # Filter by browser=safari
        r = client.get("/api/search?browser=safari")
        data = r.get_json()
        safari_count = len(SAFARI_VISITS)
        check(
            f"API filter browser=safari returns {safari_count} visits",
            r.status_code == 200 and data["total"] >= safari_count,
            f"total={data.get('total')}"
        )

        # Filter by tag
        r = client.get("/api/search?tag=search_query")
        data = r.get_json()
        check(
            "API filter tag=search_query returns results",
            r.status_code == 200 and data["total"] >= 1,
            f"total={data.get('total')}"
        )

        # Aggregate by browser
        r = client.get("/api/aggregate?group_by=browser")
        data = r.get_json()
        browsers = {row["label"] for row in data.get("results", [])}
        check(
            "API aggregate group_by=browser has all 3 browsers",
            {"chrome", "firefox", "safari"}.issubset(browsers),
            f"got browsers={browsers}"
        )

        # Aggregate by tags
        r = client.get("/api/aggregate?group_by=tags")
        data = r.get_json()
        tag_labels = {row["label"] for row in data.get("results", [])}
        check(
            "API aggregate group_by=tags includes expected tags",
            "search_query" in tag_labels and "cloud_storage" in tag_labels,
            f"got tags={tag_labels}"
        )

        # Filters endpoint
        r = client.get("/api/filters")
        data = r.get_json()
        check(
            "API /api/filters has all browsers",
            "chrome" in data.get("browser", []) and "safari" in data.get("browser", []),
            f"browsers={data.get('browser')}"
        )
        check(
            "API /api/filters total_visits correct",
            data.get("total_visits", 0) >= expected_rows,
            f"total_visits={data.get('total_visits')}"
        )
        check(
            "API /api/filters time_range populated",
            data.get("time_range", {}).get("earliest") is not None,
            f"time_range={data.get('time_range')}"
        )

        # Heatmap
        r = client.get("/api/heatmap")
        data = r.get_json()
        check(
            "API /api/heatmap returns cells",
            r.status_code == 200 and len(data.get("cells", [])) >= 1,
            f"cells count={len(data.get('cells', []))}"
        )

        # Visit detail
        r = client.get("/api/visit/1")
        data = r.get_json()
        check(
            "API /api/visit/1 returns a visit",
            r.status_code == 200 and "full_url" in data,
            f"status={r.status_code}"
        )

        # Reingest (reclassify)
        r = client.post("/api/reingest")
        data = r.get_json()
        check(
            "API /api/reingest reclassifies all visits",
            r.status_code == 200 and data.get("reclassified", 0) >= expected_rows,
            f"reclassified={data.get('reclassified')}"
        )

        # Verify FTS still works after reingest
        r = client.get("/api/search?q=pastebin")
        data = r.get_json()
        check(
            "FTS works after reingest",
            r.status_code == 200 and data["total"] >= 1,
            f"total={data.get('total')}"
        )

        # ---------------------------------------------------------------
        # TEST: Duplicate ingestion protection
        # ---------------------------------------------------------------
        stats2 = run_pipeline(index_db_path, work_dir)
        check(
            "Re-running pipeline skips already-ingested DBs",
            stats2["total_new_rows"] == 0,
            f"got {stats2['total_new_rows']} new rows"
        )

        # ---------------------------------------------------------------
        # TEST: Contains search mode
        # ---------------------------------------------------------------
        r = client.get("/api/search?q=pastebin&mode=contains")
        data = r.get_json()
        check(
            "API contains search mode works",
            r.status_code == 200 and data["total"] >= 1,
            f"total={data.get('total')}"
        )

        # ---------------------------------------------------------------
        # TEST: Regex search mode
        # ---------------------------------------------------------------
        r = client.get("/api/search?q=192\\.168&mode=regex")
        data = r.get_json()
        check(
            "API regex search mode works",
            r.status_code == 200 and data["total"] >= 1,
            f"total={data.get('total')}"
        )

        # ---------------------------------------------------------------
        # TEST: Date range filtering
        # ---------------------------------------------------------------
        r = client.get("/api/search?start=2024-06-15T14:00:00Z")
        data = r.get_json()
        check(
            "API date range start filter works",
            r.status_code == 200 and data["total"] >= 1 and data["total"] < count,
            f"total={data.get('total')}"
        )

        # ---------------------------------------------------------------
        # TEST: Sort options
        # ---------------------------------------------------------------
        r = client.get("/api/search?sort=host&sort_dir=asc")
        data = r.get_json()
        if r.status_code == 200 and len(data["results"]) >= 2:
            hosts = [row["dns_host"] for row in data["results"]]
            check(
                "API sort by host ascending",
                hosts == sorted(hosts),
                f"hosts={hosts}"
            )
        else:
            check("API sort by host ascending", False, f"status={r.status_code}")

        # ---------------------------------------------------------------
        # TEST: Clear and verify
        # ---------------------------------------------------------------
        r = client.post("/api/clear")
        data = r.get_json()
        check(
            "API /api/clear succeeds",
            r.status_code == 200 and data.get("status") == "ok",
        )

        r = client.get("/api/filters")
        data = r.get_json()
        check(
            "After clear, 0 visits remain",
            data.get("total_visits") == 0,
            f"total_visits={data.get('total_visits')}"
        )

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        try:
            os.unlink(index_db_path)
        except OSError:
            pass

    print(f"\n=== {passed} passed, {failed} failed ===")
    return failed == 0


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
