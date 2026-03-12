"""Tests for the classification pipeline stage."""
import json
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from history_search.pipeline.classify import classify_visit, classify_batch, decompose_url, extract_search_terms
from history_search.pipeline.models import VisitRecord


class TestURLDecomposition(unittest.TestCase):
    def test_basic_url(self):
        parts = decompose_url("https://example.com/path?key=value")
        self.assertEqual(parts["host"], "example.com")
        self.assertEqual(parts["path"], "/path")
        self.assertIn("key=value", parts["query_string"])

    def test_encoded_params(self):
        parts = decompose_url("https://example.com/search?q=hello+world&lang=en")
        self.assertIn("q=hello world", parts["query_string"])

    def test_empty_url(self):
        parts = decompose_url("")
        self.assertEqual(parts["host"], "")

    def test_malformed_url(self):
        parts = decompose_url("not a url at all")
        self.assertEqual(parts["host"], "")


class TestClassifiers(unittest.TestCase):
    def _classify(self, url, host=""):
        r = VisitRecord(full_url=url, dns_host=host or "")
        return classify_visit(r)

    def test_internal_network(self):
        r = self._classify("http://192.168.1.1/admin", "192.168.1.1")
        self.assertIn("internal_network", r.tags)

    def test_cloud_storage(self):
        r = self._classify("https://drive.google.com/file/d/abc", "drive.google.com")
        self.assertIn("cloud_storage", r.tags)

    def test_download_url(self):
        r = self._classify("https://evil.com/payload.exe", "evil.com")
        self.assertIn("download_url", r.tags)

    def test_paste_site(self):
        r = self._classify("https://pastebin.com/raw/abc123", "pastebin.com")
        self.assertIn("paste_site", r.tags)

    def test_suspicious_tld(self):
        r = self._classify("https://bad-site.tk/phish", "bad-site.tk")
        self.assertIn("suspicious_tld", r.tags)

    def test_non_standard_port(self):
        r = self._classify("https://example.com:8443/api", "example.com")
        self.assertIn("non_standard_port", r.tags)

    def test_file_scheme(self):
        r = self._classify("file:///etc/passwd")
        self.assertIn("file_scheme", r.tags)

    def test_search_query(self):
        r = self._classify("https://www.google.com/search?q=forensic+tools", "www.google.com")
        self.assertIn("search_query", r.tags)

    def test_ip_address_host(self):
        r = self._classify("http://10.0.0.1:8080/dashboard", "10.0.0.1")
        self.assertIn("ip_address_host", r.tags)
        self.assertIn("internal_network", r.tags)

    def test_no_false_positives_normal_url(self):
        r = self._classify("https://www.google.com/", "www.google.com")
        # Should not have most forensic tags
        self.assertNotIn("internal_network", r.tags)
        self.assertNotIn("download_url", r.tags)
        self.assertNotIn("paste_site", r.tags)

    def test_batch_classify(self):
        records = [
            VisitRecord(full_url="https://evil.tk/bad", dns_host="evil.tk"),
            VisitRecord(full_url="https://example.com/", dns_host="example.com"),
        ]
        results = classify_batch(records)
        self.assertEqual(len(results), 2)
        self.assertIn("suspicious_tld", results[0].tags)


class TestSearchTermExtraction(unittest.TestCase):
    def test_google(self):
        terms = extract_search_terms("https://www.google.com/search?q=forensic+browser+history")
        self.assertEqual(terms, "forensic browser history")

    def test_bing(self):
        terms = extract_search_terms("https://www.bing.com/search?q=dfir+tools")
        self.assertEqual(terms, "dfir tools")

    def test_non_search(self):
        terms = extract_search_terms("https://www.example.com/page")
        self.assertIsNone(terms)


if __name__ == "__main__":
    unittest.main()
