"""SQLite forensic carving: WAL recovery, freelist parsing, unallocated space scanning.

Recovers browser history records that were "deleted" by the user. SQLite DELETE
only marks pages as free; actual data persists in the freelist, WAL file, and
unallocated page slack until overwritten.

References:
  - SQLite WAL format: https://www.sqlite.org/walformat.html
  - SQLite file format: https://www.sqlite.org/fileformat2.html
  - Belkasoft: https://belkasoft.com/sqlite-analysis
  - Sanderson Forensics WAL walkback technique
"""
from __future__ import annotations

import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from urllib.parse import urlparse

from .models import VisitRecord, SourceMetadata

LOG = logging.getLogger("history_search.carve")

# Maximum file size we'll attempt to carve (512 MB)
_MAX_CARVE_SIZE = 512 * 1024 * 1024

# URL pattern for carving raw bytes
_URL_RE = re.compile(rb'(https?://[^\x00-\x1f\x7f-\x9f\s"\'<>]{8,2048})')

# Characters that are valid in URLs per RFC 3986
_URL_VALID_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789-._~:/?#[]@!$&'()*+,;=%"
)

# Chrome epoch: microseconds since 1601-01-01 00:00:00 UTC
_CHROME_EPOCH_OFFSET = 11644473600
_TICK_DIVISOR = 1_000_000

# Safari/WebKit epoch: seconds since 2001-01-01 00:00:00 UTC
_WEBKIT_EPOCH_OFFSET = 978307200

# Firefox: microseconds since Unix epoch (same divisor as Chrome but no offset)


# ---------------------------------------------------------------------------
# WAL file parser
# ---------------------------------------------------------------------------

_WAL_MAGIC_BE = 0x377F0682  # big-endian WAL
_WAL_MAGIC_LE = 0x377F0683  # little-endian WAL
_WAL_HEADER_SIZE = 32
_WAL_FRAME_HEADER_SIZE = 24


def parse_wal(wal_path: Path, db_path: Path) -> List[bytes]:
    """Parse a SQLite WAL file and return all frame page data.

    Returns a list of raw page bytes from every WAL frame, including
    older frames that may contain pre-deletion data.
    """
    try:
        wal_data = wal_path.read_bytes()
    except OSError as e:
        LOG.debug("Cannot read WAL %s: %s", wal_path, e)
        return []

    if len(wal_data) < _WAL_HEADER_SIZE:
        return []

    # WAL header: magic(4) version(4) page_size(4) checkpoint_seq(4) ...
    magic = struct.unpack(">I", wal_data[:4])[0]
    if magic not in (_WAL_MAGIC_BE, _WAL_MAGIC_LE):
        return []

    page_size = struct.unpack(">I", wal_data[8:12])[0]
    if page_size < 512 or page_size > 65536:
        return []

    pages = []
    offset = _WAL_HEADER_SIZE
    frame_size = _WAL_FRAME_HEADER_SIZE + page_size

    while offset + frame_size <= len(wal_data):
        # Frame header: page_number(4) commit_size(4) salt1(4) salt2(4) checksum1(4) checksum2(4)
        page_data = wal_data[offset + _WAL_FRAME_HEADER_SIZE:offset + frame_size]
        pages.append(page_data)
        offset += frame_size

    LOG.info("WAL %s: %d frames, page_size=%d", wal_path.name, len(pages), page_size)
    return pages


# ---------------------------------------------------------------------------
# SQLite freelist page extraction
# ---------------------------------------------------------------------------

def get_freelist_pages(db_data: bytes) -> List[bytes]:
    """Extract all freelist pages from a SQLite database file.

    The freelist is a linked list of trunk pages, each pointing to leaf pages.
    Deleted data persists on these pages until they are reused.
    """
    if len(db_data) < 100:
        return []

    # Database header at offset 0
    # Bytes 16-17: page size (or 1 = 65536)
    page_size_raw = struct.unpack(">H", db_data[16:18])[0]
    page_size = 65536 if page_size_raw == 1 else page_size_raw
    if page_size < 512 or page_size > 65536:
        return []

    # Bytes 32-35: first freelist trunk page number (1-based, 0 = none)
    # Bytes 36-39: total freelist pages
    first_trunk = struct.unpack(">I", db_data[32:36])[0]
    total_free = struct.unpack(">I", db_data[36:40])[0]

    if first_trunk == 0 or total_free == 0:
        return []

    LOG.info("SQLite freelist: %d free pages, trunk starts at page %d", total_free, first_trunk)

    pages = []
    visited: Set[int] = set()
    trunk_page = first_trunk

    while trunk_page > 0 and trunk_page not in visited:
        visited.add(trunk_page)
        offset = (trunk_page - 1) * page_size

        if offset + page_size > len(db_data):
            break

        trunk_data = db_data[offset:offset + page_size]
        pages.append(trunk_data)

        # Trunk page format: next_trunk(4) leaf_count(4) then leaf_page_numbers(4 each)
        next_trunk = struct.unpack(">I", trunk_data[:4])[0]
        leaf_count = struct.unpack(">I", trunk_data[4:8])[0]

        # Sanity cap
        max_leaves = (page_size - 8) // 4
        leaf_count = min(leaf_count, max_leaves)

        for i in range(leaf_count):
            leaf_offset = 8 + i * 4
            if leaf_offset + 4 > len(trunk_data):
                break
            leaf_page = struct.unpack(">I", trunk_data[leaf_offset:leaf_offset + 4])[0]
            if leaf_page == 0:
                continue
            page_off = (leaf_page - 1) * page_size
            if page_off + page_size <= len(db_data):
                pages.append(db_data[page_off:page_off + page_size])

        trunk_page = next_trunk

        # Safety: don't loop forever
        if len(visited) > 100000:
            break

    LOG.info("Extracted %d freelist pages", len(pages))
    return pages


# ---------------------------------------------------------------------------
# URL carving from raw bytes
# ---------------------------------------------------------------------------

def carve_urls_from_pages(pages: List[bytes]) -> List[Dict[str, str]]:
    """Scan raw page data for URL strings and nearby timestamps.

    Returns list of dicts with 'url', 'title' (if found nearby), and
    'timestamp_utc' (if a plausible timestamp is found near the URL).
    """
    seen_urls: Set[str] = set()
    results: List[Dict[str, str]] = []

    for page_data in pages:
        for m in _URL_RE.finditer(page_data):
            try:
                raw = m.group(1).decode("utf-8", errors="replace")
                # Clean up: strip null bytes and truncate at first non-URL char.
                # SQLite cells pack fields tightly — title text often follows the URL
                # with no delimiter. Truncate at the first char not valid in a URL.
                url = raw.rstrip("\x00")
                cleaned = []
                for ch in url:
                    if ch in _URL_VALID_CHARS:
                        cleaned.append(ch)
                    else:
                        break
                url = "".join(cleaned).rstrip(".,;:!?)'\"")  # strip trailing punctuation
                if len(url) < 10 or "://" not in url:
                    continue
                # Validate: must have a real hostname with at least one dot
                try:
                    p = urlparse(url)
                    host = p.hostname or ""
                    if not host or "." not in host:
                        continue
                    # Reject if hostname has non-ASCII or control chars
                    if not all(c.isascii() and c.isprintable() for c in host):
                        continue
                except Exception:
                    continue
            except Exception:
                continue

            # Deduplicate
            if url in seen_urls:
                continue
            seen_urls.add(url)

            # Try to find a timestamp near the URL in the same page
            ts = _find_nearby_timestamp(page_data, m.start())

            # Try to find a title (printable text before the URL)
            title = _find_nearby_title(page_data, m.start())

            results.append({
                "url": url,
                "title": title,
                "timestamp_utc": ts,
            })

    return results


def _find_nearby_timestamp(data: bytes, url_offset: int) -> str:
    """Look for Chrome/Firefox/Safari timestamps near a URL in raw page data."""
    # Search in a window around the URL
    search_start = max(0, url_offset - 256)
    search_end = min(len(data), url_offset + 256)
    window = data[search_start:search_end]

    # Try 8-byte Chrome timestamps (microseconds since 1601)
    for i in range(0, len(window) - 7):
        try:
            val = struct.unpack("<Q", window[i:i + 8])[0]
            # Chrome timestamp range: ~2000 to ~2100
            unix_ts = (val / _TICK_DIVISOR) - _CHROME_EPOCH_OFFSET
            if 946684800 <= unix_ts <= 4102444800:
                return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (struct.error, OSError, OverflowError, ValueError):
            continue

    # Try 8-byte float Safari timestamps (seconds since 2001)
    for i in range(0, len(window) - 7):
        try:
            val = struct.unpack("<d", window[i:i + 8])[0]
            unix_ts = val + _WEBKIT_EPOCH_OFFSET
            if 946684800 <= unix_ts <= 4102444800 and val > 0:
                return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (struct.error, OSError, OverflowError, ValueError):
            continue

    return ""


def _find_nearby_title(data: bytes, url_offset: int) -> str:
    """Try to extract a page title near a URL in raw page data.

    Titles are often stored as length-prefixed UTF-8 strings near URLs
    in browser history SQLite records.
    """
    # Look backwards from the URL for a printable UTF-8 string
    search_start = max(0, url_offset - 512)
    prefix = data[search_start:url_offset]

    # Find the last substantial printable string before the URL
    # SQLite stores text as raw UTF-8 in cell payloads
    try:
        text = prefix.decode("utf-8", errors="replace")
        # Split on non-printable chars and take the last meaningful chunk
        chunks = re.split(r'[\x00-\x1f]+', text)
        for chunk in reversed(chunks):
            chunk = chunk.strip()
            # A title should be at least 3 chars, mostly printable, not a URL
            if (len(chunk) >= 3 and not chunk.startswith("http")
                    and not chunk.startswith("/")
                    and sum(c.isalnum() or c == ' ' for c in chunk) > len(chunk) * 0.5
                    and '\ufffd' not in chunk):  # reject replacement chars
                return chunk[:256]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Full carve pipeline for a single evidence database
# ---------------------------------------------------------------------------

def carve_deleted_records(
    db_path: Path,
    meta: SourceMetadata,
    provenance: str,
    active_urls: Optional[Set[str]] = None,
) -> List[VisitRecord]:
    """Carve deleted browser history from a SQLite database file.

    Scans three sources:
      1. WAL file (pre-deletion page frames)
      2. Freelist pages (marked-free but not yet overwritten)
      3. Unallocated space in the main DB file

    Args:
        db_path: Path to the evidence SQLite database
        meta: Source metadata (browser, OS, etc.)
        provenance: Provenance chain string
        active_urls: Set of URLs already extracted via normal SQL queries.
                     Carved URLs matching these are skipped (not truly deleted).

    Returns:
        List of VisitRecords with visit_source="carved" and appropriate tags.
    """
    records: List[VisitRecord] = []
    active = active_urls or set()
    all_pages: List[bytes] = []

    # --- 1. WAL file ---
    wal_path = Path(str(db_path) + "-wal")
    if not wal_path.exists():
        # Also check without hyphen (some forensic tools rename)
        alt = db_path.parent / (db_path.name + "-wal")
        if alt.exists():
            wal_path = alt

    if wal_path.exists():
        wal_pages = parse_wal(wal_path, db_path)
        all_pages.extend(wal_pages)
        LOG.info("WAL recovery: %d page frames from %s", len(wal_pages), wal_path.name)

    # --- 2. Freelist pages ---
    try:
        db_size = db_path.stat().st_size
        if db_size <= _MAX_CARVE_SIZE:
            db_data = db_path.read_bytes()
            free_pages = get_freelist_pages(db_data)
            all_pages.extend(free_pages)

            # --- 3. Unallocated: scan entire file for URLs not in active pages ---
            # For efficiency, we scan the whole file as one big "page"
            all_pages.append(db_data)
        else:
            LOG.warning("DB too large to carve (%d MB), skipping freelist/unalloc",
                        db_size // (1024 * 1024))
    except OSError as e:
        LOG.warning("Cannot read %s for carving: %s", db_path, e)

    if not all_pages:
        return records

    # --- Carve URLs from all collected pages ---
    carved = carve_urls_from_pages(all_pages)
    LOG.info("Carved %d unique URLs from %s", len(carved), db_path.name)

    # Build a set of active hostnames+paths for fuzzy matching
    # (carved URLs may have title text appended, so exact match isn't reliable)
    active_prefixes: Set[str] = set()
    for aurl in active:
        try:
            p = urlparse(aurl)
            # Store host+path as prefix for matching
            active_prefixes.add(f"{p.hostname}{p.path}")
        except Exception:
            pass

    # Filter out URLs that are still in the active database
    new_count = 0
    for item in carved:
        url = item["url"]
        if url in active:
            continue  # Exact match — not deleted

        # Fuzzy match: check if the carved URL's host+path prefix matches an active one
        try:
            p = urlparse(url)
            prefix = f"{p.hostname}{p.path}"
            # If the host+start-of-path matches an active URL, skip it
            if any(prefix.startswith(ap) or ap.startswith(prefix) for ap in active_prefixes):
                continue
        except Exception:
            pass

        new_count += 1
        records.append(VisitRecord(
            provenance_chain=provenance,
            source_db_path=str(db_path),
            os_platform=meta.os_platform,
            browser=meta.browser,
            browser_engine=meta.browser_engine,
            browser_profile=meta.browser_profile,
            os_username=meta.os_username,
            endpoint_name=meta.endpoint_name,
            visit_time_utc=item.get("timestamp_utc", ""),
            full_url=url,
            title=item.get("title", ""),
            visit_source="carved",
            visit_source_confidence="likely",
            transition_type="other",
            tags=["recovered_deleted"],
        ))

    LOG.info("Recovered %d deleted URLs from %s (filtered %d active)",
             new_count, db_path.name, len(carved) - new_count)
    return records
