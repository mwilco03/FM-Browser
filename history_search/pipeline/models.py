"""Data models for the forensic browser history pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class ExtractedFile:
    """A file discovered during archive extraction."""
    temp_path: Path
    provenance_chain: str  # "outer.7z > inner.tar.gz > Users/alice/Library/Safari/History.db"
    original_archive_path: str


@dataclass
class SourceMetadata:
    """Metadata extracted from the file path within an archive."""
    os_platform: str = "unknown"       # "macos" | "windows" | "linux" | "unknown"
    browser: str = "unknown"           # "safari" | "chrome" | "firefox" | "edge" | "brave" | etc.
    browser_engine: str = "unknown"    # "webkit" | "chromium" | "gecko"
    browser_profile: str = ""          # "Default" | "Profile 1" | etc.
    os_username: str = ""              # extracted from Users/{user} segment
    endpoint_name: str = ""            # from archive name or hostname files


@dataclass
class VisitRecord:
    """A single browser visit, normalized across all browser engines."""
    # Source identification
    provenance_chain: str = ""
    source_db_path: str = ""
    os_platform: str = ""
    browser: str = ""
    browser_engine: str = ""
    browser_profile: str = ""
    os_username: str = ""
    endpoint_name: str = ""

    # Visit data
    visit_time_utc: str = ""
    full_url: str = ""
    title: str = ""

    # URL decomposition (populated in Stage 3)
    dns_host: str = ""
    url_path: str = ""
    query_string_decoded: str = ""

    # Navigation metadata
    visit_source: str = "unknown"
    visit_source_confidence: str = "unknown"
    transition_type: str = "other"
    transition_qualifiers: str = ""
    from_visit_url: str = ""
    visit_duration_ms: int = 0

    # Raw values for classification stage
    raw_transition: int = 0
    raw_from_visit: int = 0
    raw_visit_id: int = 0

    # Classification (populated in Stage 3)
    tags: List[str] = field(default_factory=list)
