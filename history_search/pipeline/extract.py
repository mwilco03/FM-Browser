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


# ---------------------------------------------------------------------------
# Extraction failure tracking
# ---------------------------------------------------------------------------

# Reasons a single archive can fail to extract, surfaced to the caller so the
# server can return them in /api/ingest responses.
FAIL_PASSWORD = "password_required"
FAIL_UNSUPPORTED = "unsupported_format"
FAIL_TRAVERSAL = "path_traversal"
FAIL_SIZE_LIMIT = "extraction_size_limit"
FAIL_UNKNOWN = "unknown"


class ExtractionResult:
    """Aggregated outcome of an extraction run."""

    def __init__(self):
        self.failures: List[dict] = []

    def record(self, archive: Path, reason: str, detail: str = "") -> None:
        self.failures.append({
            "archive": str(archive),
            "reason": reason,
            "detail": detail,
        })

    def needs_password(self) -> bool:
        return any(f["reason"] == FAIL_PASSWORD for f in self.failures)


def _resolve_passwords(user_passwords: Optional[List[str]]) -> List[str]:
    """Build attempt order: user-supplied passwords first, then defaults.

    The empty password is always tried first so unencrypted archives are not
    slowed down by three failed decryption attempts.
    """
    seen: set = set()
    out: List[str] = []
    # Always start with the empty password.
    out.append("")
    seen.add("")
    for src in (user_passwords or [], ARCHIVE_PASSWORDS):
        for p in src:
            if p not in seen:
                out.append(p)
                seen.add(p)
    return out

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

# Each `_try_extract_*` returns one of:
#   "ok"             — extraction succeeded
#   "password"       — archive is encrypted and no supplied password worked
#   "unsupported"    — handler does not support this archive (fall through)
#   "error"          — handler threw an unexpected error

def _is_password_error(exc: BaseException) -> bool:
    """Heuristic: did this exception come from an encrypted-archive path?"""
    msg = str(exc).lower()
    needles = ("password", "encrypted", "decrypt", "crc")
    return any(n in msg for n in needles)


def _try_extract_zip_python(archive_path: Path, dest: Path,
                            passwords: List[str]) -> str:
    """Extract zip using stdlib zipfile with password support."""
    saw_password_error = False
    for password in passwords:
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                pwd = password.encode("utf-8") if password else None
                for member in zf.infolist():
                    if not _is_path_safe(member.filename):
                        continue
                    zf.extract(member, dest, pwd=pwd)
                return "ok"
        except RuntimeError as e:
            # zipfile raises RuntimeError for bad password ("Bad password ...")
            # and for unsupported compression. Treat as password issue.
            saw_password_error = True
            LOG.debug("zip password attempt failed for %s: %s", archive_path, e)
            continue
        except zipfile.BadZipFile:
            return "unsupported"
        except Exception as e:
            if _is_password_error(e):
                saw_password_error = True
                continue
            LOG.debug("zipfile failed for %s: %s", archive_path, e)
            return "error"
    return "password" if saw_password_error else "error"


def _try_extract_tar_python(archive_path: Path, dest: Path,
                            passwords: List[str]) -> str:
    """Extract tar/tar.gz/tar.bz2 using stdlib tarfile (no password support)."""
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            safe_members = [m for m in tf.getmembers() if _is_path_safe(m.name)]
            tf.extractall(dest, members=safe_members)
        return "ok"
    except tarfile.TarError as e:
        LOG.debug("tarfile failed for %s: %s", archive_path, e)
        return "unsupported"
    except Exception as e:
        LOG.debug("tarfile failed for %s: %s", archive_path, e)
        return "error"


def _try_extract_7z_python(archive_path: Path, dest: Path,
                           passwords: List[str]) -> str:
    """Extract .7z using py7zr (optional dependency)."""
    py7zr = _get_py7zr()
    if py7zr is None:
        return "unsupported"
    saw_password_error = False
    for password in passwords:
        try:
            pwd = password if password else None
            with py7zr.SevenZipFile(archive_path, "r", password=pwd) as sz:
                sz.extractall(path=dest)
            return "ok"
        except Exception as e:
            if _is_password_error(e):
                saw_password_error = True
                continue
            LOG.debug("py7zr failed for %s: %s", archive_path, e)
            continue
    return "password" if saw_password_error else "error"


def _try_extract_rar_python(archive_path: Path, dest: Path,
                            passwords: List[str]) -> str:
    """Extract .rar using rarfile (optional dependency)."""
    rf = _get_rarfile()
    if rf is None:
        return "unsupported"
    saw_password_error = False
    for password in passwords:
        try:
            with rf.RarFile(archive_path, "r") as rar:
                pwd = password if password else None
                rar.extractall(dest, pwd=pwd)
            return "ok"
        except Exception as e:
            if _is_password_error(e):
                saw_password_error = True
                continue
            LOG.debug("rarfile failed for %s: %s", archive_path, e)
            continue
    return "password" if saw_password_error else "error"


# ---------------------------------------------------------------------------
# CLI-based extractors (fallback)
# ---------------------------------------------------------------------------

# 7z exit codes:
#   0 = success, 1 = warning, 2 = fatal, 7 = command line error,
#   8 = not enough memory, 255 = user stopped. We treat 0/1 as success.
_SEVENZIP_OK_RETURNCODES = {0, 1}
_PASSWORD_KEYWORDS = (b"password", b"wrong password", b"data error",
                      b"encrypted", b"cannot open")


def _seven_zip_returncode_means_password(stderr: bytes, stdout: bytes) -> bool:
    blob = (stderr + stdout).lower()
    return any(kw in blob for kw in _PASSWORD_KEYWORDS)


def _try_extract_7z_cli(archive_path: Path, dest: Path,
                        passwords: List[str]) -> str:
    """Try extracting with 7z CLI using password list."""
    if not _has_7z_cli():
        return "unsupported"
    saw_password_error = False
    for password in passwords:
        try:
            cmd = ["7z", "x", f"-o{dest}", "-y"]
            if password:
                cmd.append(f"-p{password}")
            else:
                # Tell 7z to not prompt; treat missing password as failure.
                cmd.append("-p-")
            cmd.append(str(archive_path))
            result = subprocess.run(cmd, capture_output=True, timeout=600)
            if result.returncode in _SEVENZIP_OK_RETURNCODES:
                return "ok"
            if _seven_zip_returncode_means_password(result.stderr, result.stdout):
                saw_password_error = True
                continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return "password" if saw_password_error else "error"


def _try_extract_zip_cli(archive_path: Path, dest: Path,
                         passwords: List[str]) -> str:
    """Try extracting zip with unzip CLI."""
    if shutil.which("unzip") is None:
        return "unsupported"
    saw_password_error = False
    for password in passwords:
        try:
            cmd = ["unzip", "-o"]
            if password:
                cmd += ["-P", password]
            cmd += [str(archive_path), "-d", str(dest)]
            result = subprocess.run(cmd, capture_output=True, timeout=600)
            if result.returncode == 0:
                return "ok"
            # unzip exits 82 on incorrect password, 81 on wrong-method
            if result.returncode in (81, 82):
                saw_password_error = True
                continue
            blob = (result.stderr + result.stdout).lower()
            if b"password" in blob or b"incorrect" in blob:
                saw_password_error = True
                continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return "password" if saw_password_error else "error"


def _try_extract_tar_cli(archive_path: Path, dest: Path,
                         passwords: List[str]) -> str:
    """Extract tar archives via CLI (no password support)."""
    if shutil.which("tar") is None:
        return "unsupported"
    try:
        result = subprocess.run(
            ["tar", "xf", str(archive_path), "-C", str(dest)],
            capture_output=True, timeout=600
        )
        return "ok" if result.returncode == 0 else "error"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "error"


# ---------------------------------------------------------------------------
# Dispatch: try Python first, fall back to CLI
# ---------------------------------------------------------------------------

def _combine(*results: str) -> str:
    """Reduce a list of extractor outcomes to one final result.

    Priority: ok > password > error > unsupported. So if any handler can
    actually extract, "ok" wins; if any handler tells us the archive is
    encrypted, surface that over a generic "error".
    """
    order = {"ok": 0, "password": 1, "error": 2, "unsupported": 3}
    best = "unsupported"
    for r in results:
        if order[r] < order[best]:
            best = r
    return best


def _extract_single(archive_path: Path, dest: Path,
                    passwords: List[str]) -> str:
    """Extract a single archive file to the destination directory.

    Uses magic-byte detection to choose the correct extractor regardless of
    file extension. Strategy: pure-Python first (portable), CLI fallback.

    Returns one of: "ok", "password", "error", "unsupported".
    """
    dest.mkdir(parents=True, exist_ok=True)
    archive_type = _detect_archive_type(archive_path)

    LOG.debug("Magic-byte detection for %s: %s", archive_path.name, archive_type or "unknown")

    if archive_type == "zip":
        results = []
        for fn in (_try_extract_zip_python, _try_extract_zip_cli, _try_extract_7z_cli):
            r = fn(archive_path, dest, passwords)
            if r == "ok":
                return "ok"
            results.append(r)
        return _combine(*results)

    elif archive_type in ("tar", "gzip", "bzip2", "xz"):
        results = []
        for fn in (_try_extract_tar_python, _try_extract_tar_cli, _try_extract_7z_cli):
            r = fn(archive_path, dest, passwords)
            if r == "ok":
                return "ok"
            results.append(r)
        return _combine(*results)

    elif archive_type == "7z":
        results = []
        for fn in (_try_extract_7z_python, _try_extract_7z_cli):
            r = fn(archive_path, dest, passwords)
            if r == "ok":
                return "ok"
            results.append(r)
        return _combine(*results)

    elif archive_type == "rar":
        results = []
        for fn in (_try_extract_rar_python, _try_extract_7z_cli):
            r = fn(archive_path, dest, passwords)
            if r == "ok":
                return "ok"
            results.append(r)
        return _combine(*results)

    else:
        # Magic bytes didn't match — try everything as last resort.
        LOG.debug("No magic match for %s, trying all extractors", archive_path.name)
        results = []
        for fn in (_try_extract_zip_python, _try_extract_tar_python,
                   _try_extract_7z_python, _try_extract_rar_python,
                   _try_extract_7z_cli):
            r = fn(archive_path, dest, passwords)
            if r == "ok":
                return "ok"
            results.append(r)
        return _combine(*results)


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
    passwords: Optional[List[str]] = None,
    result: Optional[ExtractionResult] = None,
) -> ExtractionResult:
    """Recursively extract archives, handling nested containers.

    Args:
        archive_path: Path to the archive file or directory.
        dest: Destination directory for extraction.
        provenance: Parent provenance chain string.
        depth: Current nesting depth (for safety limit).
        on_progress: Optional callback for progress reporting.
        passwords: User-supplied archive passwords to try before defaults.
        result: Optional ExtractionResult to accumulate failures into.

    Returns:
        ExtractionResult with .failures populated for any archive that could
        not be extracted. The destination directory contains whatever was
        successfully extracted regardless of failures.
    """
    if result is None:
        result = ExtractionResult()
    pw_list = _resolve_passwords(passwords)

    if depth > MAX_NESTING_DEPTH:
        LOG.warning("Max nesting depth %d reached at %s", MAX_NESTING_DEPTH, archive_path)
        return result

    archive_path = archive_path.resolve()
    chain = f"{provenance} > {archive_path.name}" if provenance else archive_path.name

    if on_progress:
        on_progress(f"Extracting: {chain} (depth {depth})")

    LOG.info("Extracting [depth=%d]: %s", depth, archive_path.name)

    if not _check_path_traversal(archive_path, dest):
        result.record(archive_path, FAIL_TRAVERSAL,
                      "archive contains path-traversal entries")
        return result

    outcome = _extract_single(archive_path, dest, pw_list)
    if outcome == "password":
        LOG.warning("Password required: %s", archive_path)
        result.record(archive_path, FAIL_PASSWORD,
                      "archive is encrypted; supply --archive-password "
                      "(or the Passwords field in the SPA Ingest panel)")
        if on_progress:
            on_progress(f"  password required: {archive_path.name}")
        return result
    if outcome == "unsupported":
        LOG.warning("Unsupported format: %s", archive_path)
        result.record(archive_path, FAIL_UNSUPPORTED,
                      "no available extractor recognized this archive format")
        return result
    if outcome != "ok":
        LOG.warning("Failed to extract: %s", archive_path)
        result.record(archive_path, FAIL_UNKNOWN, "extraction failed")
        return result

    if not _check_extraction_size(dest):
        result.record(archive_path, FAIL_SIZE_LIMIT,
                      "extraction exceeded MAX_EXTRACTED_SIZE_BYTES")
        return result

    # Recurse into nested archives
    for child in sorted(dest.rglob("*")):
        if not child.is_file():
            continue
        if _is_archive(child):
            nested_dest = child.parent / (child.stem + "_extracted")
            try:
                extract_recursive(child, nested_dest, chain, depth + 1,
                                  on_progress, pw_list, result)
                LOG.info("  nested: %s", child.name)
            except Exception as e:
                LOG.warning("  nested extract failed %s: %s", child.name, e)
                result.record(child, FAIL_UNKNOWN, str(e))

    return result


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
