"""Stage 1: Recursive archive extraction with provenance tracking.

Archive type detection uses **magic bytes** (file header signatures), not file
extensions.  A file named ``evidence.bin`` with a ZIP header is handled as a
ZIP, while a ``.zip`` whose header is actually 7z is handled as 7z.  Extension
is only consulted as a last-resort fallback when the header cannot be read.

Portable extraction strategy:
  1. zip/tar/tar.gz/tar.bz2 — stdlib zipfile/tarfile (always available)
  2. 7z — py7zr if installed, else 7z CLI
  3. rar — rarfile if installed, else 7z CLI
  4. Unknown magic — try all extractors, CLI 7z as last resort

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

# Magic byte signatures for archive detection (offset, bytes)
_MAGIC_SIGNATURES = {
    "zip":   (0, b"PK\x03\x04"),
    "zip_empty": (0, b"PK\x05\x06"),       # empty zip
    "zip_spanned": (0, b"PK\x07\x08"),     # spanned zip
    "7z":    (0, b"7z\xbc\xaf\x27\x1c"),
    "rar4":  (0, b"Rar!\x1a\x07\x00"),
    "rar5":  (0, b"Rar!\x1a\x07\x01\x00"),
    "gzip":  (0, b"\x1f\x8b"),
    "bzip2": (0, b"BZh"),
    "xz":    (0, b"\xfd7zXZ\x00"),
}
_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"

# Maximum bytes we need to read for any signature check
_MAGIC_READ_SIZE = 512


def _detect_archive_type(path: Path) -> Optional[str]:
    """Detect archive type by reading header bytes (magic signatures).

    Returns one of: 'zip', '7z', 'rar', 'tar', 'gzip', 'bzip2', 'xz', or None.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(_MAGIC_READ_SIZE)
    except (OSError, IOError):
        return None

    if len(header) == 0:
        return None

    # Check fixed-offset signatures
    for sig_name, (offset, magic) in _MAGIC_SIGNATURES.items():
        if len(header) >= offset + len(magic) and header[offset:offset + len(magic)] == magic:
            if sig_name.startswith("zip"):
                return "zip"
            if sig_name.startswith("rar"):
                return "rar"
            return sig_name

    # tar has magic at offset 257
    if len(header) >= _TAR_MAGIC_OFFSET + len(_TAR_MAGIC):
        if header[_TAR_MAGIC_OFFSET:_TAR_MAGIC_OFFSET + len(_TAR_MAGIC)] == _TAR_MAGIC:
            return "tar"

    return None


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
    """Check if a file is a recognized archive format using magic bytes.

    Reads the file header to identify archive type regardless of extension.
    Falls back to extension check only if the file cannot be read.
    """
    if not path.is_file():
        return False
    detected = _detect_archive_type(path)
    if detected is not None:
        return True
    # Fallback: extension-only check for exotic formats the CLI tools may handle
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
    """Reject archives containing path traversal attempts.

    Uses magic-byte detection to determine the correct traversal checker
    regardless of file extension.
    """
    archive_type = _detect_archive_type(archive_path)

    if archive_type == "zip":
        return _check_path_traversal_zip(archive_path)
    elif archive_type in ("tar", "gzip", "bzip2", "xz"):
        return _check_path_traversal_tar(archive_path)
    elif archive_type in ("7z", "rar") and _has_7z_cli():
        return _check_path_traversal_7z_cli(archive_path)
    elif _has_7z_cli():
        # Unknown type — try 7z CLI listing as best-effort check
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

    Uses magic-byte detection to choose the correct extractor regardless of
    file extension.  Strategy: pure-Python first (portable), CLI fallback.
    """
    dest.mkdir(parents=True, exist_ok=True)
    archive_type = _detect_archive_type(archive_path)

    LOG.debug("Magic-byte detection for %s: %s", archive_path.name, archive_type or "unknown")

    if archive_type == "zip":
        if _try_extract_zip_python(archive_path, dest):
            return True
        # AES-encrypted zips need CLI
        if _try_extract_zip_cli(archive_path, dest):
            return True
        return _try_extract_7z_cli(archive_path, dest)

    elif archive_type in ("tar", "gzip", "bzip2", "xz"):
        if _try_extract_tar_python(archive_path, dest):
            return True
        if _try_extract_tar_cli(archive_path, dest):
            return True
        return _try_extract_7z_cli(archive_path, dest)

    elif archive_type == "7z":
        if _try_extract_7z_python(archive_path, dest):
            return True
        return _try_extract_7z_cli(archive_path, dest)

    elif archive_type == "rar":
        if _try_extract_rar_python(archive_path, dest):
            return True
        return _try_extract_7z_cli(archive_path, dest)

    else:
        # Magic bytes didn't match — try everything as last resort
        LOG.debug("No magic match for %s, trying all extractors", archive_path.name)
        if _try_extract_zip_python(archive_path, dest):
            return True
        if _try_extract_tar_python(archive_path, dest):
            return True
        if _try_extract_7z_python(archive_path, dest):
            return True
        if _try_extract_rar_python(archive_path, dest):
            return True
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
