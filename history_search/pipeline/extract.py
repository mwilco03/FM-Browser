"""Stage 1: Recursive archive extraction with provenance tracking."""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, List, Optional

from .constants import ARCHIVE_PASSWORDS, MAX_EXTRACTION_RATIO, MAX_EXTRACTED_SIZE_BYTES, MAX_NESTING_DEPTH
from .models import ExtractedFile

LOG = logging.getLogger("history_search.extract")

ARCHIVE_EXTENSIONS = {".7z", ".zip", ".tgz", ".tar", ".gz", ".rar"}


def _is_archive(path: Path) -> bool:
    """Check if a file is a recognized archive format."""
    suffix = path.suffix.lower()
    if suffix in ARCHIVE_EXTENSIONS:
        return True
    suffixes = "".join(s.lower() for s in path.suffixes)
    return ".tar.gz" in suffixes or ".tar.bz2" in suffixes


def _check_path_traversal(archive_path: Path, output_dir: Path) -> bool:
    """Reject archives containing path traversal attempts."""
    try:
        result = subprocess.run(
            ["7z", "l", str(archive_path)],
            capture_output=True, text=True, timeout=30
        )
        if ".." in result.stdout:
            LOG.warning("Path traversal detected in %s, skipping", archive_path)
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return True


def _try_extract_7z(archive_path: Path, dest: Path) -> bool:
    """Try extracting with 7z using password list."""
    for password in ARCHIVE_PASSWORDS:
        try:
            cmd = ["7z", "x", f"-o{dest}", "-y", str(archive_path)]
            if password:
                cmd.insert(2, f"-p{password}")
            result = subprocess.run(cmd, capture_output=True, timeout=600)
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return False


def _try_extract_zip(archive_path: Path, dest: Path) -> bool:
    """Try extracting zip with password list."""
    for password in ARCHIVE_PASSWORDS:
        try:
            cmd = ["unzip", "-o", str(archive_path), "-d", str(dest)]
            if password:
                cmd.insert(2, "-P")
                cmd.insert(3, password)
            result = subprocess.run(cmd, capture_output=True, timeout=600)
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    # Fallback to 7z for AES-encrypted zips
    return _try_extract_7z(archive_path, dest)


def _try_extract_tar(archive_path: Path, dest: Path) -> bool:
    """Extract tar/tar.gz/tgz archives."""
    try:
        result = subprocess.run(
            ["tar", "xf", str(archive_path), "-C", str(dest)],
            capture_output=True, timeout=600
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return _try_extract_7z(archive_path, dest)


def _extract_single(archive_path: Path, dest: Path) -> bool:
    """Extract a single archive file to the destination directory."""
    dest.mkdir(parents=True, exist_ok=True)
    suffix = archive_path.suffix.lower()
    suffixes = "".join(s.lower() for s in archive_path.suffixes)

    if suffix == ".7z":
        return _try_extract_7z(archive_path, dest)
    elif suffix == ".zip":
        return _try_extract_zip(archive_path, dest)
    elif ".tar" in suffixes or suffix in (".tgz", ".gz"):
        return _try_extract_tar(archive_path, dest)
    elif suffix == ".rar":
        return _try_extract_7z(archive_path, dest)
    else:
        return _try_extract_7z(archive_path, dest)


def _check_extraction_size(dest: Path) -> bool:
    """Check total extraction size doesn't exceed safety limits."""
    total = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
    if total > MAX_EXTRACTED_SIZE_BYTES:
        LOG.warning("Extraction size %d exceeds limit %d", total, MAX_EXTRACTED_SIZE_BYTES)
        return False
    return True


def extract_recursive(
    archive_path: Path,
    dest: Path,
    provenance: str = "",
    depth: int = 0,
    on_progress: Optional[Callable[[str], None]] = None,
) -> Path:
    """Recursively extract archives, handling nested containers.

    Args:
        archive_path: Path to the archive file or directory.
        dest: Destination directory for extraction.
        provenance: Parent provenance chain string.
        depth: Current nesting depth (for safety limit).
        on_progress: Optional callback for progress reporting.

    Returns:
        The root extraction directory.
    """
    if depth > MAX_NESTING_DEPTH:
        LOG.warning("Max nesting depth %d reached at %s", MAX_NESTING_DEPTH, archive_path)
        return dest

    archive_path = archive_path.resolve()
    chain = f"{provenance} > {archive_path.name}" if provenance else archive_path.name

    if on_progress:
        on_progress(f"Extracting: {chain} (depth {depth})")

    LOG.info("Extracting [depth=%d]: %s", depth, archive_path.name)

    if not _check_path_traversal(archive_path, dest):
        return dest

    if not _extract_single(archive_path, dest):
        LOG.warning("Failed to extract: %s", archive_path)
        return dest

    if not _check_extraction_size(dest):
        return dest

    # Recurse into nested archives
    for child in sorted(dest.rglob("*")):
        if not child.is_file():
            continue
        if _is_archive(child):
            nested_dest = child.parent / (child.stem + "_extracted")
            try:
                extract_recursive(child, nested_dest, chain, depth + 1, on_progress)
                LOG.info("  nested: %s", child.name)
            except Exception as e:
                LOG.warning("  nested extract failed %s: %s", child.name, e)

    return dest


def discover_files(root: Path, provenance_base: str = "") -> List[ExtractedFile]:
    """Walk an extraction directory and yield all discovered files with provenance."""
    results = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # Skip archive residue and temp files
        if _is_archive(path):
            continue

        rel = path.relative_to(root)
        chain = f"{provenance_base} > {rel}" if provenance_base else str(rel)

        results.append(ExtractedFile(
            temp_path=path,
            provenance_chain=chain,
            original_archive_path=str(rel),
        ))
    return results
