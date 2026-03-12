"""Tests for the ingestion pipeline stage."""
import os
import sqlite3
import tempfile
import unittest
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from history_search.pipeline.ingest import (
    detect_os_platform, detect_source_metadata, _extract_username_fallback,
    _chrome_time_to_utc, _firefox_time_to_utc, _safari_time_to_utc,
    decode_chrome_transition,
)
from pathlib import Path


class TestOSDetection(unittest.TestCase):
    def test_macos(self):
        p = Path("/tmp/Users/alice/Library/Safari/History.db")
        self.assertEqual(detect_os_platform(p), "macos")

    def test_windows(self):
        p = Path("/tmp/Users/bob/AppData/Local/Google/Chrome/User Data/Default/History")
        self.assertEqual(detect_os_platform(p), "windows")

    def test_linux(self):
        p = Path("/tmp/home/user/.config/google-chrome/Default/History")
        self.assertEqual(detect_os_platform(p), "linux")

    def test_unknown(self):
        p = Path("/tmp/some/random/path.db")
        self.assertEqual(detect_os_platform(p), "unknown")


class TestSourceMetadata(unittest.TestCase):
    def test_chrome_macos(self):
        p = Path("/evidence/Users/alice/Library/Application Support/Google/Chrome/Default/History")
        meta = detect_source_metadata(p, "chromium")
        self.assertEqual(meta.browser, "chrome")
        self.assertEqual(meta.os_platform, "macos")
        self.assertEqual(meta.os_username, "alice")
        self.assertEqual(meta.browser_profile, "Default")

    def test_firefox_windows(self):
        p = Path("/evidence/Users/bob/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default-release/places.sqlite")
        meta = detect_source_metadata(p, "gecko")
        self.assertEqual(meta.browser, "firefox")
        self.assertEqual(meta.os_platform, "windows")
        self.assertEqual(meta.os_username, "bob")

    def test_safari(self):
        p = Path("/evidence/Users/carol/Library/Safari/History.db")
        meta = detect_source_metadata(p, "webkit")
        self.assertEqual(meta.browser, "safari")
        self.assertEqual(meta.os_username, "carol")

    def test_brave_macos(self):
        p = Path("/evidence/Users/dave/Library/Application Support/BraveSoftware/Brave-Browser/Default/History")
        meta = detect_source_metadata(p, "chromium")
        self.assertEqual(meta.browser, "brave")
        self.assertEqual(meta.browser_engine, "chromium")


class TestTimestampConversion(unittest.TestCase):
    def test_chrome_time(self):
        # 2024-01-15 10:00:00 UTC in Chrome epoch
        chrome_ts = (1705312800 + 11644473600) * 1000000
        result = _chrome_time_to_utc(chrome_ts)
        self.assertTrue(result.startswith("2024-01-15T10:00:00"))

    def test_firefox_time(self):
        ff_ts = 1705312800 * 1000000
        result = _firefox_time_to_utc(ff_ts)
        self.assertTrue(result.startswith("2024-01-15T10:00:00"))

    def test_safari_time(self):
        safari_ts = 1705312800 - 978307200
        result = _safari_time_to_utc(safari_ts)
        self.assertTrue(result.startswith("2024-01-15T10:00:00"))

    def test_zero_time(self):
        self.assertEqual(_chrome_time_to_utc(0), "")
        self.assertEqual(_firefox_time_to_utc(0), "")


class TestTransitionDecoding(unittest.TestCase):
    def test_typed(self):
        core, quals = decode_chrome_transition(1)
        self.assertEqual(core, "typed")
        self.assertEqual(quals, "")

    def test_link_with_qualifiers(self):
        raw = 0 | 0x20000000 | 0x80000000  # link + chain_end + server_redirect
        core, quals = decode_chrome_transition(raw)
        self.assertEqual(core, "link")
        self.assertIn("chain_end", quals)
        self.assertIn("server_redirect", quals)


if __name__ == "__main__":
    unittest.main()
