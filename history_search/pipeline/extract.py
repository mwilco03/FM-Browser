"""Stage 1: Recursive archive extraction with provenance tracking.

Portable extraction strategy:
  1. zip/tar/tar.gz/tar.bz2 — stdlib zipfile/tarfile (always available)
  2. .7z — py7zr if installed, else 7z CLI
  3. .rar — rarfile if installed, else 7z CLI
  4. Anything else — 7z CLI as last resort

Install `pip install fm-browser[archives]` for fully portable mode
(no system 7z/unzip/tar required).
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, List, Optional

from .constants import ARCHIVE_PASSWORDS, MAX_EXTRACTION_RATIO, MAX_EXTRACTED_SIZE_BYTES, MAX_NESTING_DEPTH
from .models import ExtractedFile

LOG = logging.getLogger("history_search.extract")

ARCHIVE_EXTENSIONS = {".7z", ".zip", ".tgz", ".tar", ".gz", ".rar"}

# Lazy-loaded optional libraries
_py7zr = None
_rarfile = None


def _get_py7zr():
    """Lazy import py7zr (optional dependency)."""
    global _py7zr
    if _py7zr is None:
        try:
            import py7zr
            _py7zr = py7zr
        except ImportError:
            _py7zr = False
    return _py7zr if _py7zr is not False else None


def _get_rarfile():
    """Lazy import rarfile (optional dependency)."""
    global _rarfile
    if _rarfile is None:
        try:
            import rarfile
            _rarfile = rarfile
        except ImportError:
            _rarfile = False
    return _rarfile if _rarfile is not False else None


def _has_7z_cli() -> bool:
    """Check if 7z command is available."""
    return shutil.which("7z") is not None


def _is_archive(path: Path) -> bool:
    """Check if a file is a recognized archive format."""
    suffix = path.suffix.lower()
    if suffix in ARCHIVE_EXTENSIONS:
        return True
    suffixes = "".join(s.lower() for s in path.suffixes)
    return ".tar.gz" in suffixes or ".tar.bz2" in suffixes


# ---------------------------------------------------------------------------
# Path-traversal safety
# ---------------------------------------------------------------------------

def _is_path_safe(member_name: str) -> bool:
    """Reject archive members with path traversal components."""
    return ".." not in Path(member_name).parts


def _check_path_traversal_zip(archive_path: Path) -> bool:
    """Check zip archive for path traversal using stdlib."""
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            for name in zf.namelist():
                if not _is_path_safe(name):
                    LOG.warning("Path traversal detected in %s: %s", archive_path, name)
                    return False
    except (zipfile.BadZipFile, Exception):
        pass
    return True


def _check_path_traversal_tar(archive_path: Path) -> bool:
    """Check tar archive for path traversal using stdlib."""
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            for member in tf.getmembers():
                if not _is_path_safe(member.name):
                    LOG.warning("Path traversal detected in %s: %s", archive_path, member.name)
                    return False
    except (tarfile.TarError, Exception):
        pass
    return True


def _check_path_traversal_7z_cli(archive_path: Path) -> bool:
    """Check archive via 7z CLI listing (fallback)."""
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


def _check_path_traversal(archive_path: Path, output_dir: Path) -> bool:
    """Reject archives containing path traversal attempts."""
    suffix = archive_path.suffix.lower()
    suffixes = "".join(s.lower() for s in archive_path.suffixes)

    if suffix == ".zip":
        return _check_path_traversal_zip(archive_path)
    elif ".tar" in suffixes or suffix in (".tgz", ".gz"):
        return _check_path_traversal_tar(archive_path)
    elif _has_7z_cli():
        return _check_path_traversal_7z_cli(archive_path)
    return True


# ---------------------------------------------------------------------------
# Pure-Python extractors (stdlib)
# ---------------------------------------------------------------------------

def _try_extract_zip_python(archive_path: Path, dest: Path) -> bool:
    """Extract zip using stdlib zipfile with password support."""
    for password in ARCHIVE_PASSWORDS:
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                pwd = password.encode("utf-8") if password else None
                for member in zf.infolist():
                    if not _is_path_safe(member.filename):
                        continue
                    zf.extract(member, dest, pwd=pwd)
                return True
        except (RuntimeError, zipfile.BadZipFile):
            # RuntimeError for bad password or unsupported compression
            continue
        except Exception as e:
            LOG.debug("zipfile failed for %s: %s", archive_path, e)
            continue
    return False


def _try_extract_tar_python(archive_path: Path, dest: Path) -> bool:
    """Extract tar/tar.gz/tar.bz2 using stdlib tarfile."""
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            safe_members = [m for m in tf.getmembers() if _is_path_safe(m.name)]
            tf.extractall(dest, members=safe_members)
        return True
    except (tarfile.TarError, Exception) as e:
        LOG.debug("tarfile failed for %s: %s", archive_path, e)
        return False


def _try_extract_7z_python(archive_path: Path, dest: Path) -> bool:
    """Extract .7z using py7zr (optional dependency)."""
    py7zr = _get_py7zr()
    if py7zr is None:
        return False
    for password in ARCHIVE_PASSWORDS:
        try:
            pwd = password if password else None
            with py7zr.SevenZipFile(archive_path, "r", password=pwd) as sz:
                sz.extractall(path=dest)
            return True
        except Exception:
            continue
    return False


def _try_extract_rar_python(archive_path: Path, dest: Path) -> bool:
    """Extract .rar using rarfile (optional dependency)."""
    rf = _get_rarfile()
    if rf is None:
        return False
    for password in ARCHIVE_PASSWORDS:
        try:
            with rf.RarFile(archive_path, "r") as rar:
                pwd = password if password else None
                rar.extractall(dest, pwd=pwd)
            return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# CLI-based extractors (fallback)
# ---------------------------------------------------------------------------

def _try_extract_7z_cli(archive_path: Path, dest: Path) -> bool:
    """Try extracting with 7z CLI using password list."""
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


def _try_extract_zip_cli(archive_path: Path, dest: Path) -> bool:
    """Try extracting zip with unzip CLI."""
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
    return False


def _try_extract_tar_cli(archive_path: Path, dest: Path) -> bool:
    """Extract tar archives via CLI."""
    try:
        result = subprocess.run(
            ["tar", "xf", str(archive_path), "-C", str(dest)],
            capture_output=True, timeout=600
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Dispatch: try Python first, fall back to CLI
# ---------------------------------------------------------------------------

def _extract_single(archive_path: Path, dest: Path) -> bool:
    """Extract a single archive file to the destination directory.

    Strategy: pure-Python first (portable), CLI fallback (for edge cases).
    """
    dest.mkdir(parents=True, exist_ok=True)
    suffix = archive_path.suffix.lower()
    suffixes = "".join(s.lower() for s in archive_path.suffixes)

    if suffix == ".zip":
        if _try_extract_zip_python(archive_path, dest):
            return True
        # AES-encrypted zips need CLI
        if _try_extract_zip_cli(archive_path, dest):
            return True
        return _try_extract_7z_cli(archive_path, dest)

    elif ".tar" in suffixes or suffix in (".tgz", ".gz"):
        if _try_extract_tar_python(archive_path, dest):
            return True
        if _try_extract_tar_cli(archive_path, dest):
            return True
        return _try_extract_7z_cli(archive_path, dest)

    elif suffix == ".7z":
        if _try_extract_7z_python(archive_path, dest):
            return True
        return _try_extract_7z_cli(archive_path, dest)

    elif suffix == ".rar":
        if _try_extract_rar_python(archive_path, dest):
            return True
        return _try_extract_7z_cli(archive_path, dest)

    else:
        # Unknown format — try everything
        return _try_extract_7z_cli(archive_path, dest)


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
