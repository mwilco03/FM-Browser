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


if __name__ == "__main__":
    unittest.main()
