#!/usr/bin/env python3
"""End-to-end tests for all API endpoints.

Runs against the Flask test client — no real server needed.
Seeds the DB with sample visit data and verifies every route.
"""
import json
import os
import sqlite3
import tempfile
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from history_search.server import app
from history_search.pipeline.index import init_schema, TABLE_VISITS

SAMPLE_VISITS = [
    {
        "provenance_chain": "test.7z > Users/alice/Library/Safari/History.db",
        "source_db_path": "/tmp/test/History.db",
        "os_platform": "macos",
        "browser": "safari",
        "browser_engine": "webkit",
        "browser_profile": "Default",
        "os_username": "alice",
        "endpoint_name": "test.7z",
        "visit_time_utc": "2024-06-15T10:30:00Z",
        "full_url": "https://www.google.com/search?q=forensic+tools",
        "title": "forensic tools - Google Search",
        "dns_host": "www.google.com",
        "url_path": "/search",
        "query_string_decoded": "q=forensic tools",
        "visit_source": "local",
        "visit_source_confidence": "confirmed",
        "transition_type": "typed",
        "transition_qualifiers": "from_address_bar",
        "from_visit_url": "",
        "visit_duration_ms": 5000,
        "tags": '["search_query"]',
        "unfurl": '[{"type":"search_terms","key":"q","value":"forensic tools"}]',
    },
    {
        "provenance_chain": "test.7z > Users/bob/AppData/Local/Google/Chrome/Default/History",
        "source_db_path": "/tmp/test/Chrome/History",
        "os_platform": "windows",
        "browser": "chrome",
        "browser_engine": "chromium",
        "browser_profile": "Default",
        "os_username": "bob",
        "endpoint_name": "test.7z",
        "visit_time_utc": "2024-06-15T14:00:00Z",
        "full_url": "https://drive.google.com/drive/my-drive",
        "title": "My Drive - Google Drive",
        "dns_host": "drive.google.com",
        "url_path": "/drive/my-drive",
        "query_string_decoded": "",
        "visit_source": "synced",
        "visit_source_confidence": "confirmed",
        "transition_type": "link",
        "transition_qualifiers": "",
        "from_visit_url": "https://mail.google.com/",
        "visit_duration_ms": 12000,
        "tags": '["cloud_storage"]',
        "unfurl": '[]',
    },
    {
        "provenance_chain": "test.7z > Users/alice/Library/Safari/History.db",
        "source_db_path": "/tmp/test/History.db",
        "os_platform": "macos",
        "browser": "safari",
        "browser_engine": "webkit",
        "browser_profile": "Default",
        "os_username": "alice",
        "endpoint_name": "test.7z",
        "visit_time_utc": "2024-06-16T08:00:00Z",
        "full_url": "https://pastebin.com/raw/abc123",
        "title": "Pastebin Raw",
        "dns_host": "pastebin.com",
        "url_path": "/raw/abc123",
        "query_string_decoded": "",
        "visit_source": "local",
        "visit_source_confidence": "confirmed",
        "transition_type": "link",
        "transition_qualifiers": "",
        "from_visit_url": "https://www.google.com/",
        "visit_duration_ms": 3000,
        "tags": '["paste_site"]',
        "unfurl": '[]',
    },
]

COLS = [
    "provenance_chain", "source_db_path", "os_platform", "browser",
    "browser_engine", "browser_profile", "os_username", "endpoint_name",
    "visit_time_utc", "full_url", "title", "dns_host", "url_path",
    "query_string_decoded", "visit_source", "visit_source_confidence",
    "transition_type", "transition_qualifiers", "from_visit_url",
    "visit_duration_ms", "tags", "unfurl",
]


def seed_db(db_path):
    """Insert sample visits into the test database."""
    init_schema(db_path)
    placeholders = ", ".join(["?"] * len(COLS))
    col_names = ", ".join(COLS)
    with sqlite3.connect(db_path) as conn:
        for visit in SAMPLE_VISITS:
            values = [visit[c] for c in COLS]
            conn.execute(
                f"INSERT INTO {TABLE_VISITS} ({col_names}) VALUES ({placeholders})",
                values,
            )
        conn.commit()


def run_tests():
    passed = 0
    failed = 0

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path = tmp.name
    tmp.close()

    try:
        seed_db(db_path)

        app.config["TESTING"] = True
        client = app.test_client()

        # Inject db_path for every request
        @app.before_request
        def _set_db():
            from flask import g
            g.db_path = db_path

        # ---------------------------------------------------------------
        # GET / — index page
        # ---------------------------------------------------------------
        r = client.get("/")
        if r.status_code == 200 and b"<html" in r.data.lower():
            print("[PASS] GET / — serves index.html")
            passed += 1
        else:
            print(f"[FAIL] GET / — status={r.status_code}, len={len(r.data)}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/search — no query (returns all, sorted by time)
        # ---------------------------------------------------------------
        r = client.get("/api/search")
        data = r.get_json()
        if r.status_code == 200 and data["total"] == 3 and len(data["results"]) == 3:
            print("[PASS] GET /api/search — returns all 3 visits")
            passed += 1
        else:
            print(f"[FAIL] GET /api/search — {data}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/search?q=forensic — FTS query
        # ---------------------------------------------------------------
        r = client.get("/api/search?q=forensic")
        data = r.get_json()
        if r.status_code == 200 and data["total"] >= 1:
            urls = [row["full_url"] for row in data["results"]]
            if any("google.com/search" in u for u in urls):
                print("[PASS] GET /api/search?q=forensic — FTS match found")
                passed += 1
            else:
                print(f"[FAIL] GET /api/search?q=forensic — no expected match in {urls}")
                failed += 1
        else:
            print(f"[FAIL] GET /api/search?q=forensic — status={r.status_code}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/search with filters
        # ---------------------------------------------------------------
        r = client.get("/api/search?browser=chrome")
        data = r.get_json()
        if r.status_code == 200 and data["total"] == 1 and data["results"][0]["browser"] == "chrome":
            print("[PASS] GET /api/search?browser=chrome — filter works")
            passed += 1
        else:
            print(f"[FAIL] GET /api/search?browser=chrome — {data}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/search with date range
        # ---------------------------------------------------------------
        r = client.get("/api/search?start=2024-06-16T00:00:00Z")
        data = r.get_json()
        if r.status_code == 200 and data["total"] == 1:
            print("[PASS] GET /api/search?start=... — date range filter")
            passed += 1
        else:
            print(f"[FAIL] GET /api/search?start=... — total={data.get('total')}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/search with tag filter
        # ---------------------------------------------------------------
        r = client.get("/api/search?tag=cloud_storage")
        data = r.get_json()
        if r.status_code == 200 and data["total"] == 1:
            print("[PASS] GET /api/search?tag=cloud_storage — tag filter")
            passed += 1
        else:
            print(f"[FAIL] GET /api/search?tag=cloud_storage — total={data.get('total')}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/search with pagination
        # ---------------------------------------------------------------
        r = client.get("/api/search?limit=1&offset=1")
        data = r.get_json()
        if r.status_code == 200 and len(data["results"]) == 1 and data["total"] == 3:
            print("[PASS] GET /api/search?limit=1&offset=1 — pagination")
            passed += 1
        else:
            print(f"[FAIL] GET /api/search pagination — {data}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/visit/<id>
        # ---------------------------------------------------------------
        r = client.get("/api/visit/1")
        data = r.get_json()
        if r.status_code == 200 and data["full_url"] == SAMPLE_VISITS[0]["full_url"]:
            print("[PASS] GET /api/visit/1 — single visit detail")
            passed += 1
        else:
            print(f"[FAIL] GET /api/visit/1 — {data}")
            failed += 1

        # GET /api/visit/999 — not found
        r = client.get("/api/visit/999")
        if r.status_code == 404:
            print("[PASS] GET /api/visit/999 — 404 for missing visit")
            passed += 1
        else:
            print(f"[FAIL] GET /api/visit/999 — expected 404, got {r.status_code}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/aggregate — group by host
        # ---------------------------------------------------------------
        r = client.get("/api/aggregate?group_by=dns_host")
        data = r.get_json()
        if r.status_code == 200 and len(data["results"]) >= 2:
            labels = {row["label"] for row in data["results"]}
            if "www.google.com" in labels and "drive.google.com" in labels:
                print("[PASS] GET /api/aggregate?group_by=dns_host")
                passed += 1
            else:
                print(f"[FAIL] GET /api/aggregate dns_host — labels={labels}")
                failed += 1
        else:
            print(f"[FAIL] GET /api/aggregate dns_host — {data}")
            failed += 1

        # GET /api/aggregate — group by browser
        r = client.get("/api/aggregate?group_by=browser")
        data = r.get_json()
        if r.status_code == 200 and len(data["results"]) == 2:
            print("[PASS] GET /api/aggregate?group_by=browser")
            passed += 1
        else:
            print(f"[FAIL] GET /api/aggregate browser — {data}")
            failed += 1

        # GET /api/aggregate — group by tags
        r = client.get("/api/aggregate?group_by=tags")
        data = r.get_json()
        if r.status_code == 200 and len(data["results"]) >= 2:
            print("[PASS] GET /api/aggregate?group_by=tags")
            passed += 1
        else:
            print(f"[FAIL] GET /api/aggregate tags — {data}")
            failed += 1

        # GET /api/aggregate — time grouping
        r = client.get("/api/aggregate?group_by=time_day")
        data = r.get_json()
        if r.status_code == 200 and len(data["results"]) == 2:
            print("[PASS] GET /api/aggregate?group_by=time_day")
            passed += 1
        else:
            print(f"[FAIL] GET /api/aggregate time_day — {data}")
            failed += 1

        # GET /api/aggregate — unique_urls metric
        r = client.get("/api/aggregate?group_by=browser&metric=unique_urls")
        data = r.get_json()
        if r.status_code == 200:
            print("[PASS] GET /api/aggregate?metric=unique_urls")
            passed += 1
        else:
            print(f"[FAIL] GET /api/aggregate unique_urls — {r.status_code}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/filters
        # ---------------------------------------------------------------
        r = client.get("/api/filters")
        data = r.get_json()
        if (r.status_code == 200
                and "safari" in data.get("browser", [])
                and "chrome" in data.get("browser", [])
                and "search_query" in data.get("tags", [])
                and data.get("total_visits") == 3
                and data.get("time_range", {}).get("earliest") is not None):
            print("[PASS] GET /api/filters — all filter values present")
            passed += 1
        else:
            print(f"[FAIL] GET /api/filters — {data}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/heatmap
        # ---------------------------------------------------------------
        r = client.get("/api/heatmap")
        data = r.get_json()
        if r.status_code == 200 and len(data.get("cells", [])) >= 1:
            cell = data["cells"][0]
            if "dow" in cell and "hour" in cell and "count" in cell:
                print("[PASS] GET /api/heatmap — returns cells with dow/hour/count")
                passed += 1
            else:
                print(f"[FAIL] GET /api/heatmap — bad cell shape: {cell}")
                failed += 1
        else:
            print(f"[FAIL] GET /api/heatmap — {data}")
            failed += 1

        # GET /api/heatmap with filter
        r = client.get("/api/heatmap?browser=safari")
        data = r.get_json()
        if r.status_code == 200 and len(data.get("cells", [])) >= 1:
            print("[PASS] GET /api/heatmap?browser=safari — filtered heatmap")
            passed += 1
        else:
            print(f"[FAIL] GET /api/heatmap filtered — {data}")
            failed += 1

        # ---------------------------------------------------------------
        # POST /api/reingest — re-classify all visits
        # ---------------------------------------------------------------
        r = client.post("/api/reingest")
        data = r.get_json()
        if r.status_code == 200 and data.get("reclassified") == 3:
            print("[PASS] POST /api/reingest — reclassified 3 visits")
            passed += 1
        else:
            print(f"[FAIL] POST /api/reingest — {data}")
            failed += 1

        # ---------------------------------------------------------------
        # POST /api/rebuild-fts
        # ---------------------------------------------------------------
        r = client.post("/api/rebuild-fts")
        data = r.get_json()
        if r.status_code == 200 and data.get("status") == "ok":
            print("[PASS] POST /api/rebuild-fts")
            passed += 1
        else:
            print(f"[FAIL] POST /api/rebuild-fts — {data}")
            failed += 1

        # Verify FTS still works after rebuild
        r = client.get("/api/search?q=pastebin")
        data = r.get_json()
        if r.status_code == 200 and data["total"] >= 1:
            print("[PASS] FTS search works after rebuild")
            passed += 1
        else:
            print(f"[FAIL] FTS after rebuild — {data}")
            failed += 1

        # ---------------------------------------------------------------
        # POST /api/ingest — missing path
        # ---------------------------------------------------------------
        r = client.post("/api/ingest", json={})
        if r.status_code == 400:
            print("[PASS] POST /api/ingest — 400 on missing path")
            passed += 1
        else:
            print(f"[FAIL] POST /api/ingest empty — {r.status_code}")
            failed += 1

        # POST /api/ingest — nonexistent path
        r = client.post("/api/ingest", json={"path": "/nonexistent/file.7z"})
        if r.status_code == 400:
            print("[PASS] POST /api/ingest — 400 on nonexistent path")
            passed += 1
        else:
            print(f"[FAIL] POST /api/ingest bad path — {r.status_code}")
            failed += 1

        # ---------------------------------------------------------------
        # GET /api/browse — file picker
        # ---------------------------------------------------------------
        r = client.get("/api/browse?path=/")
        data = r.get_json()
        if r.status_code == 200 and "entries" in data and "path" in data:
            print("[PASS] GET /api/browse — lists root directory")
            passed += 1
        else:
            print(f"[FAIL] GET /api/browse — {data}")
            failed += 1

        # GET /api/browse — nonexistent path
        r = client.get("/api/browse?path=/nonexistent_path_xyz")
        if r.status_code == 404:
            print("[PASS] GET /api/browse — 404 for bad path")
            passed += 1
        else:
            print(f"[FAIL] GET /api/browse bad path — {r.status_code}")
            failed += 1

        # ---------------------------------------------------------------
        # POST /api/clear — wipe all data
        # ---------------------------------------------------------------
        r = client.post("/api/clear")
        data = r.get_json()
        if r.status_code == 200 and data.get("status") == "ok":
            print("[PASS] POST /api/clear — data cleared")
            passed += 1
        else:
            print(f"[FAIL] POST /api/clear — {data}")
            failed += 1

        # Verify data is actually gone
        r = client.get("/api/filters")
        data = r.get_json()
        if data.get("total_visits") == 0:
            print("[PASS] POST /api/clear — verified 0 visits remain")
            passed += 1
        else:
            print(f"[FAIL] POST /api/clear verify — {data.get('total_visits')} remain")
            failed += 1

        # Re-seed for sort tests
        seed_db(db_path)

        # ---------------------------------------------------------------
        # Sort by URL length
        # ---------------------------------------------------------------
        r = client.get("/api/search?sort=url_length&sort_dir=desc")
        data = r.get_json()
        if r.status_code == 200 and len(data["results"]) >= 2:
            lens = [len(row["full_url"]) for row in data["results"]]
            if lens == sorted(lens, reverse=True):
                print("[PASS] GET /api/search?sort=url_length — sorted desc")
                passed += 1
            else:
                print(f"[FAIL] sort=url_length desc — lens={lens}")
                failed += 1
        else:
            print(f"[FAIL] sort=url_length — {data}")
            failed += 1

        # Sort by host ascending
        r = client.get("/api/search?sort=host&sort_dir=asc")
        data = r.get_json()
        if r.status_code == 200 and len(data["results"]) >= 2:
            hosts = [row["dns_host"] for row in data["results"]]
            if hosts == sorted(hosts):
                print("[PASS] GET /api/search?sort=host&sort_dir=asc")
                passed += 1
            else:
                print(f"[FAIL] sort=host asc — hosts={hosts}")
                failed += 1
        else:
            print(f"[FAIL] sort=host asc — {data}")
            failed += 1

        # ---------------------------------------------------------------
        # File source (source_db_path) present in results
        # ---------------------------------------------------------------
        r = client.get("/api/search")
        data = r.get_json()
        if r.status_code == 200 and all("source_db_path" in row for row in data["results"]):
            print("[PASS] Results include source_db_path (file source)")
            passed += 1
        else:
            print(f"[FAIL] source_db_path missing from results")
            failed += 1

        # ---------------------------------------------------------------
        # POST /api/ingest with clear=true
        # ---------------------------------------------------------------
        r = client.post("/api/ingest", json={"path": "/nonexistent/file.7z", "clear": True})
        # Should still fail on nonexistent path (but clear param accepted)
        if r.status_code == 400:
            print("[PASS] POST /api/ingest with clear=true — accepts clear param")
            passed += 1
        else:
            print(f"[FAIL] POST /api/ingest clear — {r.status_code}")
            failed += 1

    finally:
        os.unlink(db_path)

    print(f"\n=== {passed} passed, {failed} failed ===")
    return failed == 0


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
