"""Per-engine extraction tests: build tiny real SQLite DBs for chromium / gecko /
webkit and assert row counts, timestamp conversion, sync/redirect/empty-URL
handling, and schema-probe behavior.

Extractors open DBs with `immutable=1` (uri), so fixtures MUST be real files on
disk — `:memory:` will not work. Each test writes a temp .db, populates it, then
calls the extractor directly with a minimal SourceMetadata.
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from history_search.pipeline.ingest import (
    extract_chromium, extract_gecko, extract_webkit, _probe_engine,
)
from history_search.pipeline.constants import (
    CHROME_EPOCH_OFFSET_S, SAFARI_EPOCH_OFFSET_S, TICK_DIVISOR,
)
from history_search.pipeline.models import SourceMetadata

# A fixed reference instant used across engines: 2024-01-15T10:00:00Z.
UNIX_REF = 1705312800
ISO_REF = "2024-01-15T10:00:00Z"

# Per-engine raw timestamp encodings of UNIX_REF.
CHROME_TS = (UNIX_REF + CHROME_EPOCH_OFFSET_S) * TICK_DIVISOR   # µs since 1601
FIREFOX_TS = UNIX_REF * TICK_DIVISOR                            # µs since 1970
SAFARI_TS = UNIX_REF - SAFARI_EPOCH_OFFSET_S                    # s since 2001


def _meta(browser, engine):
    return SourceMetadata(os_platform="macos", browser=browser,
                          browser_engine=engine, browser_profile="Default",
                          os_username="alice")


class _TmpDB:
    """Context manager yielding (conn, path) for a fresh on-disk SQLite file."""
    def __init__(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

    def __enter__(self):
        self.conn = sqlite3.connect(self.path)
        return self.conn, Path(self.path)

    def __exit__(self, *exc):
        self.conn.close()
        os.unlink(self.path)


# ---------------------------------------------------------------------------
# Chromium
# ---------------------------------------------------------------------------

class TestChromiumExtraction(unittest.TestCase):
    def _build(self, conn, with_visit_source=True):
        conn.executescript("""
            CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT);
            CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER,
                visit_time INTEGER, from_visit INTEGER, transition INTEGER,
                visit_duration INTEGER);
        """)
        if with_visit_source:
            conn.execute("CREATE TABLE visit_source(id INTEGER PRIMARY KEY, source INTEGER)")
        conn.execute("INSERT INTO urls VALUES(1,'https://example.com/a','A')")
        conn.execute("INSERT INTO urls VALUES(2,'https://example.com/b','B')")
        # transition 0x01000000 = LINK core (1) + a qualifier bit; keep simple core=1
        conn.execute("INSERT INTO visits VALUES(10,1,?,0,1,2000000)", (CHROME_TS,))
        conn.execute("INSERT INTO visits VALUES(11,2,?,10,1,0)", (CHROME_TS,))
        if with_visit_source:
            conn.execute("INSERT INTO visit_source VALUES(10,0)")  # 0 = SOURCE_SYNCED (Chromium); visit 11 has no row = local browse
        conn.commit()

    def test_row_count_and_join(self):
        with _TmpDB() as (conn, path):
            self._build(conn)
            recs = extract_chromium(conn, _meta("chrome", "chromium"), "prov")
            self.assertEqual(len(recs), 2)
            self.assertEqual({r.full_url for r in recs},
                             {"https://example.com/a", "https://example.com/b"})

    def test_timestamp_1601_micros(self):
        with _TmpDB() as (conn, path):
            self._build(conn)
            recs = extract_chromium(conn, _meta("chrome", "chromium"), "p")
            self.assertTrue(all(r.visit_time_utc == ISO_REF for r in recs))

    def test_visit_source_classification(self):
        with _TmpDB() as (conn, path):
            self._build(conn, with_visit_source=True)
            recs = extract_chromium(conn, _meta("chrome", "chromium"), "p")
            by_id = {r.raw_visit_id: r for r in recs}
            # visit 10 has an explicit visit_source row of 0 = SOURCE_SYNCED
            self.assertEqual(by_id[10].visit_source, "synced")
            self.assertEqual(by_id[10].visit_source_confidence, "confirmed")
            # visit 11 has NO visit_source row -> local browsing inferred from absence
            self.assertEqual(by_id[11].visit_source, "local")
            self.assertEqual(by_id[11].visit_source_confidence, "likely")

    def test_no_visit_source_table(self):
        with _TmpDB() as (conn, path):
            self._build(conn, with_visit_source=False)
            recs = extract_chromium(conn, _meta("chrome", "chromium"), "p")
            self.assertEqual(len(recs), 2)
            self.assertTrue(all(r.visit_source_confidence == "unknown" for r in recs))

    def test_duration_micros_to_ms(self):
        with _TmpDB() as (conn, path):
            self._build(conn)
            recs = extract_chromium(conn, _meta("chrome", "chromium"), "p")
            by_id = {r.raw_visit_id: r for r in recs}
            self.assertEqual(by_id[10].visit_duration_ms, 2000)  # 2_000_000µs → 2000ms


# ---------------------------------------------------------------------------
# Gecko / Firefox
# ---------------------------------------------------------------------------

class TestGeckoExtraction(unittest.TestCase):
    def _build(self, conn, with_sync=False, frecency=100):
        conn.executescript("""
            CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                last_visit_date INTEGER, frecency INTEGER);
            CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER,
                visit_date INTEGER, visit_type INTEGER, from_visit INTEGER);
        """)
        if with_sync:
            conn.execute("CREATE TABLE moz_meta(key TEXT PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO moz_meta VALUES('sync/deviceID','abc')")
        conn.execute("INSERT INTO moz_places VALUES(1,'https://moz.example/x','X',?,?)",
                     (FIREFOX_TS, frecency))
        conn.execute("INSERT INTO moz_historyvisits VALUES(5,1,?,2,0)", (FIREFOX_TS,))
        conn.commit()

    def test_row_count(self):
        with _TmpDB() as (conn, path):
            self._build(conn)
            recs = extract_gecko(conn, _meta("firefox", "gecko"), "p")
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0].full_url, "https://moz.example/x")

    def test_timestamp_1970_micros(self):
        with _TmpDB() as (conn, path):
            self._build(conn)
            recs = extract_gecko(conn, _meta("firefox", "gecko"), "p")
            self.assertEqual(recs[0].visit_time_utc, ISO_REF)

    def test_visit_type_mapping(self):
        with _TmpDB() as (conn, path):
            self._build(conn)  # visit_type 2 = typed
            recs = extract_gecko(conn, _meta("firefox", "gecko"), "p")
            self.assertEqual(recs[0].transition_type, "typed")

    def test_per_visit_sync_not_determinable_is_local_unknown(self):
        # places.sqlite has no per-visit sync marker (UA-18): never claim
        # confirmed/synced from frecency or moz_meta heuristics.
        with _TmpDB() as (conn, path):
            self._build(conn, with_sync=False)
            recs = extract_gecko(conn, _meta("firefox", "gecko"), "p")
            self.assertEqual(recs[0].visit_source, "local")
            self.assertEqual(recs[0].visit_source_confidence, "unknown")

    def test_negative_frecency_is_not_a_sync_signal(self):
        # frecency < 0 means "not yet recalculated", NOT synced (UA-18).
        with _TmpDB() as (conn, path):
            self._build(conn, with_sync=True, frecency=-1)
            recs = extract_gecko(conn, _meta("firefox", "gecko"), "p")
            self.assertEqual(recs[0].visit_source, "local")
            self.assertEqual(recs[0].visit_source_confidence, "unknown")


# ---------------------------------------------------------------------------
# WebKit / Safari
# ---------------------------------------------------------------------------

class TestWebkitExtraction(unittest.TestCase):
    def _build(self, conn, with_origin=False, with_tombstones=False,
               with_redirect=False, empty_url=False):
        origin_col = ", origin INTEGER" if with_origin else ""
        redirect_cols = (", redirect_source INTEGER, redirect_destination INTEGER"
                         if with_redirect else "")
        # Real Safari: title lives on history_visits, history_items has NO title.
        conn.executescript(f"""
            CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT);
            CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER,
                visit_time REAL, title TEXT{origin_col}{redirect_cols});
        """)
        if with_tombstones:
            conn.execute("CREATE TABLE history_tombstones(id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO history_items VALUES(1,'https://apple.example/p')")
        cols = "id, history_item, visit_time, title"
        vals = "100, 1, ?, ?"
        params = [float(SAFARI_TS), "P"]
        if with_origin:
            cols += ", origin"; vals += ", ?"; params.append(1)
        if with_redirect:
            cols += ", redirect_source, redirect_destination"; vals += ", ?, ?"
            params += [0, 0]
        conn.execute(f"INSERT INTO history_visits({cols}) VALUES({vals})", params)
        if empty_url:
            conn.execute("INSERT INTO history_items VALUES(2,'')")
            conn.execute("INSERT INTO history_visits(id, history_item, visit_time, title) "
                         "VALUES(101, 2, ?, '')", (float(SAFARI_TS),))
        conn.commit()

    def test_row_count_and_join(self):
        with _TmpDB() as (conn, path):
            self._build(conn)
            recs = extract_webkit(conn, _meta("safari", "webkit"), "p")
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0].full_url, "https://apple.example/p")

    def test_timestamp_2001_seconds(self):
        with _TmpDB() as (conn, path):
            self._build(conn)
            recs = extract_webkit(conn, _meta("safari", "webkit"), "p")
            self.assertEqual(recs[0].visit_time_utc, ISO_REF)

    def test_requires_both_tables_probe(self):
        # history_items only → probe must NOT classify as webkit.
        with _TmpDB() as (conn, path):
            conn.execute("CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT)")
            conn.commit()
            self.assertIsNone(_probe_engine(conn))

    def test_extract_returns_empty_when_visits_missing(self):
        with _TmpDB() as (conn, path):
            conn.execute("CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
            conn.commit()
            self.assertEqual(extract_webkit(conn, _meta("safari", "webkit"), "p"), [])

    def test_empty_url_skipped(self):
        with _TmpDB() as (conn, path):
            self._build(conn, empty_url=True)
            recs = extract_webkit(conn, _meta("safari", "webkit"), "p")
            self.assertEqual(len(recs), 1)  # the empty-URL row is dropped

    def test_origin_sync_classification(self):
        with _TmpDB() as (conn, path):
            self._build(conn, with_origin=True)  # origin=1
            recs = extract_webkit(conn, _meta("safari", "webkit"), "p")
            self.assertEqual(recs[0].visit_source, "synced")
            self.assertEqual(recs[0].visit_source_confidence, "likely")

    def test_tombstones_is_local_likely(self):
        with _TmpDB() as (conn, path):
            self._build(conn, with_tombstones=True)  # no origin col
            recs = extract_webkit(conn, _meta("safari", "webkit"), "p")
            self.assertEqual(recs[0].visit_source, "local")
            self.assertEqual(recs[0].visit_source_confidence, "likely")

    def test_no_origin_column_is_local_unknown(self):
        # Older Safari schema without an origin column: sync can't be determined,
        # so confidence must be unknown, not confirmed (UA-18).
        with _TmpDB() as (conn, path):
            self._build(conn)
            recs = extract_webkit(conn, _meta("safari", "webkit"), "p")
            self.assertEqual(recs[0].visit_source, "local")
            self.assertEqual(recs[0].visit_source_confidence, "unknown")

    def test_redirect_columns_optional(self):
        with _TmpDB() as (conn, path):
            self._build(conn, with_redirect=True)
            recs = extract_webkit(conn, _meta("safari", "webkit"), "p")
            self.assertEqual(len(recs), 1)


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

class TestProbe(unittest.TestCase):
    def test_probe_chromium(self):
        with _TmpDB() as (conn, path):
            conn.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT)")
            conn.commit()
            self.assertEqual(_probe_engine(conn), "chromium")

    def test_probe_gecko(self):
        with _TmpDB() as (conn, path):
            conn.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT)")
            conn.commit()
            self.assertEqual(_probe_engine(conn), "gecko")

    def test_probe_webkit_both_tables(self):
        with _TmpDB() as (conn, path):
            conn.executescript("""
                CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT);
                CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL);
            """)
            conn.commit()
            self.assertEqual(_probe_engine(conn), "webkit")


if __name__ == "__main__":
    unittest.main()
