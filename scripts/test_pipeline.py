#!/usr/bin/env python3
"""Quick smoke test for the pipeline modules."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from history_search.pipeline.enums import Browser, BrowserEngine, BROWSER_ENGINE_MAP
from history_search.pipeline.models import VisitRecord, ExtractedFile, SourceMetadata
from history_search.pipeline.classify import classify_visit, decompose_url
from history_search.pipeline.constants import CHROME_TRANSITION_CORE
from history_search.pipeline.index import SCHEMA_DDL, TABLE_VISITS

def test_enums():
    assert Browser.CHROME.value == "chrome"
    assert BROWSER_ENGINE_MAP[Browser.CHROME] == BrowserEngine.CHROMIUM
    assert BROWSER_ENGINE_MAP[Browser.FIREFOX] == BrowserEngine.GECKO
    assert BROWSER_ENGINE_MAP[Browser.SAFARI] == BrowserEngine.WEBKIT
    print("[PASS] enums")

def test_models():
    r = VisitRecord(full_url="https://example.com", title="Test")
    assert r.visit_source == "unknown"
    assert r.tags == []
    ef = ExtractedFile(temp_path="/tmp/test", provenance_chain="a > b", original_archive_path="b")
    assert ef.provenance_chain == "a > b"
    print("[PASS] models")

def test_url_decomposition():
    parts = decompose_url("https://www.google.com/search?q=test+query&hl=en")
    assert parts["host"] == "www.google.com"
    assert parts["path"] == "/search"
    assert "q=test query" in parts["query_string"]
    print("[PASS] url decomposition")

def test_classifiers():
    # Internal network
    r = VisitRecord(full_url="http://192.168.1.1/admin", dns_host="192.168.1.1")
    r = classify_visit(r)
    assert "internal_network" in r.tags
    assert "ip_address_host" in r.tags

    # Cloud storage
    r2 = VisitRecord(full_url="https://drive.google.com/file/d/123", dns_host="drive.google.com")
    r2 = classify_visit(r2)
    assert "cloud_storage" in r2.tags

    # Download URL
    r3 = VisitRecord(full_url="https://example.com/malware.exe", dns_host="example.com")
    r3 = classify_visit(r3)
    assert "download_url" in r3.tags

    # Search query
    r4 = VisitRecord(full_url="https://www.google.com/search?q=how+to+hack", dns_host="www.google.com")
    r4 = classify_visit(r4)
    assert "search_query" in r4.tags

    # Suspicious TLD
    r5 = VisitRecord(full_url="https://evil.tk/payload", dns_host="evil.tk")
    r5 = classify_visit(r5)
    assert "suspicious_tld" in r5.tags

    # Non-standard port
    r6 = VisitRecord(full_url="https://example.com:8443/api", dns_host="example.com")
    r6 = classify_visit(r6)
    assert "non_standard_port" in r6.tags

    print("[PASS] classifiers")

def test_schema():
    assert TABLE_VISITS in SCHEMA_DDL
    assert "visits_fts" in SCHEMA_DDL
    assert "ingest_log" in SCHEMA_DDL
    assert "unicode61" in SCHEMA_DDL
    print("[PASS] schema")

if __name__ == "__main__":
    test_enums()
    test_models()
    test_url_decomposition()
    test_classifiers()
    test_schema()
    print("\n=== All tests passed ===")
