"""Stage 3: Classification, URL decomposition, and tag assignment."""
from __future__ import annotations

import base64
import json
import logging
import re
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote_plus, urlparse

from .constants import (
    CLOUD_STORAGE_HOSTS, DOWNLOAD_EXTENSIONS, INTERNAL_NETWORK_PATTERNS,
    PASTE_SITE_HOSTS, SEARCH_ENGINE_PATTERNS, SENSITIVE_PARAM_KEYS,
    SUSPICIOUS_TLDS,
)
from .models import VisitRecord

LOG = logging.getLogger("history_search.classify")

# ---------------------------------------------------------------------------
# URL decomposition
# ---------------------------------------------------------------------------

_B64_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r")


def _looks_b64(s: str) -> bool:
    if not s or len(s) < 8:
        return False
    raw = s.strip()
    try:
        b = raw.encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        return False
    if any(ch not in _B64_CHARS for ch in b):
        return False
    clean = raw.replace("\n", "").replace("\r", "")
    if len(clean) % 4 != 0:
        return False
    try:
        decoded = base64.b64decode(clean, validate=True)
        if len(decoded) < 4:
            return False
        decoded.decode("utf-8")
        return True
    except Exception:
        return False


def _maybe_decode_b64(v: str) -> str:
    if _looks_b64(v):
        try:
            return base64.b64decode(v.strip()).decode("utf-8")
        except Exception:
            pass
    return v


def decompose_url(url: str) -> Dict[str, Any]:
    """Parse a URL into host, path, decoded query string, scheme, and port."""
    try:
        parsed = urlparse(url)
    except Exception:
        return {"host": "", "query_string": "", "path": "", "scheme": "", "port": None}

    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    ordered: OrderedDict[str, List[str]] = OrderedDict()
    for k, v in pairs:
        dk = unquote_plus(k)
        dv = _maybe_decode_b64(unquote_plus(v))
        ordered.setdefault(dk, []).append(dv)

    flat = [f"{k}={v}" for k, vs in ordered.items() for v in vs]

    return {
        "host": parsed.hostname or "",
        "query_string": "&".join(flat),
        "path": parsed.path or "",
        "scheme": parsed.scheme or "",
        "port": parsed.port,
    }


# ---------------------------------------------------------------------------
# Classifier functions — each returns a tag name or None
# ---------------------------------------------------------------------------

Classifier = Callable[[VisitRecord], Optional[str]]

_CLASSIFIER_REGISTRY: List[Tuple[str, Classifier]] = []


def classifier(name: str):
    """Decorator to register a classifier function."""
    def decorator(fn: Classifier):
        _CLASSIFIER_REGISTRY.append((name, fn))
        return fn
    return decorator


@classifier("cred_in_url")
def _cls_cred_in_url(r: VisitRecord) -> Optional[str]:
    """Detect credentials embedded in URL (user:pass@host)."""
    try:
        parsed = urlparse(r.full_url)
        if parsed.username or parsed.password:
            return "cred_in_url"
    except Exception:
        pass
    return None


@classifier("token_in_params")
def _cls_token_in_params(r: VisitRecord) -> Optional[str]:
    """Detect sensitive tokens/keys in query parameters."""
    try:
        parsed = urlparse(r.full_url)
        for k, _ in parse_qsl(parsed.query, keep_blank_values=True):
            if SENSITIVE_PARAM_KEYS.match(k):
                return "token_in_params"
    except Exception:
        pass
    return None


@classifier("oauth_redirect")
def _cls_oauth_redirect(r: VisitRecord) -> Optional[str]:
    """Detect OAuth redirect/callback URLs."""
    url_lower = r.full_url.lower()
    if any(p in url_lower for p in ("/oauth/", "/callback", "/authorize")):
        return "oauth_redirect"
    try:
        parsed = urlparse(r.full_url)
        params = dict(parse_qsl(parsed.query))
        if any(k in params for k in ("code", "state", "redirect_uri")):
            return "oauth_redirect"
    except Exception:
        pass
    return None


@classifier("b64_payload")
def _cls_b64_payload(r: VisitRecord) -> Optional[str]:
    """Detect base64-encoded payloads in query parameters."""
    try:
        parsed = urlparse(r.full_url)
        for _, v in parse_qsl(parsed.query, keep_blank_values=True):
            v = unquote_plus(v)
            if len(v) >= 44 and _looks_b64(v):  # 32+ bytes encoded
                return "b64_payload"
    except Exception:
        pass
    return None


@classifier("internal_network")
def _cls_internal_network(r: VisitRecord) -> Optional[str]:
    """Detect RFC1918/internal network addresses."""
    host = r.dns_host.lower()
    if INTERNAL_NETWORK_PATTERNS.match(host):
        return "internal_network"
    # Bare hostname with no TLD
    if host and "." not in host and host not in ("localhost",):
        return "internal_network"
    return None


@classifier("non_standard_port")
def _cls_non_standard_port(r: VisitRecord) -> Optional[str]:
    """Detect URLs with non-standard ports."""
    try:
        parsed = urlparse(r.full_url)
        if parsed.port and parsed.port not in (80, 443):
            return "non_standard_port"
    except Exception:
        pass
    return None


@classifier("cloud_storage")
def _cls_cloud_storage(r: VisitRecord) -> Optional[str]:
    """Detect cloud storage service URLs."""
    if CLOUD_STORAGE_HOSTS.search(r.dns_host):
        return "cloud_storage"
    return None


@classifier("file_scheme")
def _cls_file_scheme(r: VisitRecord) -> Optional[str]:
    """Detect non-HTTP URL schemes."""
    try:
        scheme = urlparse(r.full_url).scheme.lower()
        if scheme in ("file", "data", "javascript", "blob", "chrome-extension", "moz-extension"):
            return "file_scheme"
    except Exception:
        pass
    return None


@classifier("download_url")
def _cls_download_url(r: VisitRecord) -> Optional[str]:
    """Detect URLs pointing to executable/archive downloads."""
    if DOWNLOAD_EXTENSIONS.search(r.full_url):
        return "download_url"
    return None


@classifier("paste_site")
def _cls_paste_site(r: VisitRecord) -> Optional[str]:
    """Detect paste/upload service URLs."""
    if PASTE_SITE_HOSTS.search(r.dns_host):
        return "paste_site"
    return None


@classifier("encoded_long_payload")
def _cls_long_payload(r: VisitRecord) -> Optional[str]:
    """Detect suspiciously long query strings (potential exfiltration)."""
    try:
        qs = urlparse(r.full_url).query
        if len(qs) > 2000:
            return "encoded_long_payload"
    except Exception:
        pass
    return None


@classifier("dns_over_https")
def _cls_doh(r: VisitRecord) -> Optional[str]:
    """Detect DNS-over-HTTPS query URLs."""
    doh_hosts = ("cloudflare-dns.com", "dns.google", "dns.quad9.net", "doh.opendns.com")
    if r.dns_host in doh_hosts and "/dns-query" in r.full_url:
        return "dns_over_https"
    return None


@classifier("suspicious_tld")
def _cls_suspicious_tld(r: VisitRecord) -> Optional[str]:
    """Detect commonly abused TLDs."""
    if SUSPICIOUS_TLDS.search(r.dns_host):
        return "suspicious_tld"
    return None


@classifier("search_query")
def _cls_search_query(r: VisitRecord) -> Optional[str]:
    """Detect and tag search engine queries."""
    for pattern, param_name in SEARCH_ENGINE_PATTERNS:
        if pattern.search(r.full_url):
            return "search_query"
    return None


@classifier("ip_address_host")
def _cls_ip_host(r: VisitRecord) -> Optional[str]:
    """Detect IP address as hostname."""
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", r.dns_host):
        return "ip_address_host"
    return None


@classifier("jwt_token")
def _cls_jwt(r: VisitRecord) -> Optional[str]:
    """Detect JWT tokens in URLs."""
    if re.search(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}", r.full_url):
        return "jwt_token"
    return None


# ---------------------------------------------------------------------------
# Search query extraction
# ---------------------------------------------------------------------------

def extract_search_terms(url: str) -> Optional[str]:
    """Extract search terms from known search engine URLs."""
    for pattern, param_name in SEARCH_ENGINE_PATTERNS:
        if pattern.search(url):
            try:
                parsed = urlparse(url)
                params = dict(parse_qsl(parsed.query))
                terms = params.get(param_name, "")
                if terms:
                    return unquote_plus(terms)
            except Exception:
                pass
    return None


# ---------------------------------------------------------------------------
# Main classification entry point
# ---------------------------------------------------------------------------

def classify_visit(record: VisitRecord) -> VisitRecord:
    """Run all classifiers on a visit record and populate URL decomposition + tags."""
    # URL decomposition
    parts = decompose_url(record.full_url)
    record.dns_host = parts["host"]
    record.url_path = parts["path"]
    record.query_string_decoded = parts["query_string"]

    # Run all classifiers
    tags = []
    for name, clf_fn in _CLASSIFIER_REGISTRY:
        try:
            result = clf_fn(record)
            if result:
                tags.append(result)
        except Exception as e:
            LOG.debug("Classifier %s error: %s", name, e)

    record.tags = sorted(set(tags))
    return record


def classify_batch(records: List[VisitRecord]) -> List[VisitRecord]:
    """Classify a batch of visit records."""
    return [classify_visit(r) for r in records]
