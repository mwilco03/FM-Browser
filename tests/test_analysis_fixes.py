"""Tests for IR-analysis capability fixes:
  1. Referrer/redirect chain resolution (from_visit_url) across engines.
  2. Punycode decode + IDN-homograph (lookalike domain) detection.
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from history_search.pipeline.ingest import (
    _resolve_referrer_urls, extract_chromium, extract_webkit,
)
from history_search.pipeline.classify import (
    decode_punycode_host, is_idn_homograph, classify_batch,
)
from history_search.pipeline.models import SourceMetadata, VisitRecord
from history_search.pipeline.constants import CHROME_EPOCH_OFFSET_S, TICK_DIVISOR, SAFARI_EPOCH_OFFSET_S

UNIX_REF = 1705312800
CHROME_TS = (UNIX_REF + CHROME_EPOCH_OFFSET_S) * TICK_DIVISOR
SAFARI_TS = UNIX_REF - SAFARI_EPOCH_OFFSET_S


def _meta(browser, engine):
    return SourceMetadata(os_platform="macos", browser=browser,
                          browser_engine=engine, browser_profile="Default",
                          os_username="alice")


class _TmpDB:
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
# Fix 1: referrer / redirect chain
# ---------------------------------------------------------------------------

class TestReferrerResolution(unittest.TestCase):
    def test_resolver_maps_from_visit_to_url(self):
        recs = [
            VisitRecord(full_url="https://search.example/q", raw_visit_id=1),
            VisitRecord(full_url="https://evil.example/landing",
                        raw_visit_id=2, raw_from_visit=1),
        ]
        n = _resolve_referrer_urls(recs)
        self.assertEqual(n, 1)
        self.assertEqual(recs[1].from_visit_url, "https://search.example/q")
        self.assertEqual(recs[0].from_visit_url, "")  # origin has no referrer

    def test_resolver_unknown_parent_is_blank(self):
        recs = [VisitRecord(full_url="https://x", raw_visit_id=2, raw_from_visit=99)]
        self.assertEqual(_resolve_referrer_urls(recs), 0)
        self.assertEqual(recs[0].from_visit_url, "")

    def test_chromium_end_to_end_chain(self):
        with _TmpDB() as (conn, path):
            conn.executescript("""
                CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT);
                CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER,
                    visit_time INTEGER, from_visit INTEGER, transition INTEGER,
                    visit_duration INTEGER);
            """)
            conn.execute("INSERT INTO urls VALUES(1,'https://google.com/search?q=x','g')")
            conn.execute("INSERT INTO urls VALUES(2,'https://evil.com/drop','e')")
            conn.execute("INSERT INTO visits VALUES(10,1,?,0,1,0)", (CHROME_TS,))
            conn.execute("INSERT INTO visits VALUES(11,2,?,10,1,0)", (CHROME_TS,))
            conn.commit()
            recs = extract_chromium(conn, _meta("chrome", "chromium"), "p")
            landing = next(r for r in recs if r.full_url == "https://evil.com/drop")
            self.assertEqual(landing.from_visit_url, "https://google.com/search?q=x")

    def test_webkit_redirect_chain(self):
        with _TmpDB() as (conn, path):
            conn.executescript("""
                CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT, title TEXT);
                CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER,
                    visit_time REAL, redirect_source INTEGER, redirect_destination INTEGER);
            """)
            conn.execute("INSERT INTO history_items VALUES(1,'https://ad.example/click','a')")
            conn.execute("INSERT INTO history_items VALUES(2,'https://evil.example/final','f')")
            conn.execute("INSERT INTO history_visits VALUES(100,1,?,NULL,101)", (float(SAFARI_TS),))
            conn.execute("INSERT INTO history_visits VALUES(101,2,?,100,NULL)", (float(SAFARI_TS),))
            conn.commit()
            recs = extract_webkit(conn, _meta("safari", "webkit"), "p")
            final = next(r for r in recs if r.full_url == "https://evil.example/final")
            self.assertEqual(final.from_visit_url, "https://ad.example/click")


# ---------------------------------------------------------------------------
# Fix 2: punycode + IDN homograph
# ---------------------------------------------------------------------------

class TestPunycodeHomograph(unittest.TestCase):
    def test_decode_punycode_label(self):
        # xn--80ak6aa92e == Cyrillic lookalike of "apple"
        decoded = decode_punycode_host("xn--80ak6aa92e.com")
        self.assertNotEqual(decoded, "xn--80ak6aa92e.com")
        self.assertTrue(decoded.endswith(".com"))

    def test_plain_host_unchanged(self):
        self.assertEqual(decode_punycode_host("paypal.com"), "paypal.com")

    def test_cyrillic_mixed_is_homograph(self):
        # 'p' + Cyrillic 'а'(U+0430) + 'ypal.com'
        host = "pаypal.com"
        self.assertTrue(is_idn_homograph(host))

    def test_punycode_homograph_decodes_then_flags(self):
        self.assertTrue(is_idn_homograph("xn--80ak6aa92e.com"))

    def test_legit_ascii_not_homograph(self):
        self.assertFalse(is_idn_homograph("paypal.com"))

    def test_legit_accented_latin_not_homograph(self):
        # münchen.de — Latin-1 accent, single script, must not false-positive
        self.assertFalse(is_idn_homograph("münchen.de"))

    def test_classifier_tags_applied(self):
        rec = VisitRecord(full_url="https://xn--80ak6aa92e.com/login")
        classify_batch([rec])  # classify_visit leaves .tags as a list
        self.assertIn("punycode_host", rec.tags)
        self.assertIn("idn_homograph", rec.tags)

    def test_clean_domain_no_lookalike_tags(self):
        rec = VisitRecord(full_url="https://github.com/foo")
        classify_batch([rec])
        self.assertNotIn("punycode_host", rec.tags)
        self.assertNotIn("idn_homograph", rec.tags)


if __name__ == "__main__":
    unittest.main()
