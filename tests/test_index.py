"""Tests for the indexing pipeline stage."""
import json
import os
import sqlite3
import tempfile
import unittest
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from history_search.pipeline.index import (
    init_schema, insert_visits, is_already_ingested,
    rebuild_fts, get_visit_count, TABLE_VISITS, TABLE_FTS,
)
from history_search.pipeline.models import VisitRecord


class TestIndex(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        init_schema(self.db_path)

    def tearDown(self):
        os.unlink(self.db_path)

    def test_schema_creation(self):
        with sqlite3.connect(self.db_path) as conn:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
            self.assertIn(TABLE_VISITS, tables)
            self.assertIn("ingest_log", tables)

    def test_insert_and_count(self):
        records = [
            VisitRecord(
                full_url="https://example.com/page1",
                title="Page 1",
                dns_host="example.com",
                browser="chrome",
                os_platform="macos",
                visit_time_utc="2024-01-15T10:00:00Z",
                tags=["search_query"],
            ),
            VisitRecord(
                full_url="https://evil.tk/bad",
                title="Bad Site",
                dns_host="evil.tk",
                browser="firefox",
                os_platform="windows",
                visit_time_utc="2024-01-15T11:00:00Z",
                tags=["suspicious_tld"],
            ),
        ]
        count = insert_visits(self.db_path, records, source_db="/test/db")
        self.assertEqual(count, 2)
        self.assertEqual(get_visit_count(self.db_path), 2)

    def test_duplicate_detection(self):
        records = [VisitRecord(full_url="https://example.com", dns_host="example.com")]
        insert_visits(self.db_path, records, source_db="/test/db")
        self.assertTrue(is_already_ingested(self.db_path, "/test/db"))
        self.assertFalse(is_already_ingested(self.db_path, "/other/db"))

    def test_fts_search(self):
        records = [
            VisitRecord(full_url="https://github.com/repo", title="My Repository", dns_host="github.com", tags=["cloud_storage"]),
        ]
        insert_visits(self.db_path, records, source_db="/test/db")

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            # FTS search
            rows = conn.execute(
                f"SELECT v.* FROM {TABLE_FTS} fts JOIN {TABLE_VISITS} v ON v.id = fts.rowid "
                f"WHERE {TABLE_FTS} MATCH 'github'"
            ).fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["dns_host"], "github.com")

    def test_rebuild_fts(self):
        records = [VisitRecord(full_url="https://test.com", dns_host="test.com")]
        insert_visits(self.db_path, records, source_db="/test")
        # Should not raise
        rebuild_fts(self.db_path)

    def test_source_db_path_matches_ingest_log_for_sources_join(self):
        # Regression for UA-1/B-1: extractors leave source_db_path unset; insert_visits
        # must overwrite it from source_db so /api/sources (which joins
        # visits.source_db_path = ingest_log.source_db) reports live rows and
        # delete-by-source actually removes them instead of orphaning visits.
        real_path = "/evidence/Users/jdoe/Chrome/History"
        records = [
            VisitRecord(full_url="https://a.example/1", dns_host="a.example"),
            VisitRecord(full_url="https://b.example/2", dns_host="b.example"),
        ]
        # Post-extractor state: source_db_path is unset (a profile string here would
        # be the bug). insert_visits is the single home that fills it.
        self.assertTrue(all(r.source_db_path == "" for r in records))
        insert_visits(self.db_path, records, source_db=real_path,
                      meta_browser="chrome", meta_platform="windows")

        with sqlite3.connect(self.db_path) as conn:
            paths = [r[0] for r in conn.execute(
                "SELECT DISTINCT source_db_path FROM visits").fetchall()]
            self.assertEqual(paths, [real_path])
            # The /api/sources join now reports live rows (was 0 before the fix).
            live = conn.execute(
                "SELECT COUNT(v.id) FROM ingest_log il "
                "LEFT JOIN visits v ON v.source_db_path = il.source_db GROUP BY il.id"
            ).fetchone()[0]
            self.assertEqual(live, 2)
            # delete-by-source removes the visits (no orphans left behind).
            deleted = conn.execute(
                "DELETE FROM visits WHERE source_db_path = ?", (real_path,)).rowcount
            self.assertEqual(deleted, 2)


if __name__ == "__main__":
    unittest.main()
