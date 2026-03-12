"""Stage 3: Classification, URL decomposition, and tag assignment."""
from __future__ import annotations

import base64
import json
import logging
import re
import struct
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, unquote_plus, urlparse

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
# URL Unfurling — extract forensic artifacts from URL structure
# ---------------------------------------------------------------------------

# Params whose values are typically embedded URLs
_URL_PARAMS = re.compile(
    r"^(url|redirect_uri|redirect|next|return|return_to|continue|dest|destination|"
    r"target|goto|link|href|ref|referer|referrer|callback|forward|rurl|"
    r"ReturnUrl|RelayState|SAMLRequest|SAMLResponse|TargetResource|login_hint|"
    r"service|source_url|image_url|content_url|download_url|file_url)$", re.I
)

# Params that often contain epoch timestamps
_TIMESTAMP_PARAMS = re.compile(
    r"^(t|ts|time|timestamp|date|created|modified|updated|expires|exp|iat|nbf|"
    r"start|end|since|until|from|to|after|before|auth_time|at|dt|"
    r"start_time|end_time|created_at|updated_at|last_modified)$", re.I
)

# Google protobuf URL pattern:  !<index><type><value>
# Types: 1=varint 2=string 3=group_start 4=group_end 5=32bit
# In Google Maps: !1s=string !2d=double(lon) !3d=double(lat) !4m=group
_PB_TOKEN_RE = re.compile(r"!([\d]+)([a-z])((?:(?!![\d]+[a-z]).)*)", re.S)

# Google Maps specific patterns
_GMAPS_PLACE_RE = re.compile(r"place/([^/]+)")
_GMAPS_COORDS_RE = re.compile(r"@(-?[\d.]+),(-?[\d.]+)")

# Chrome epoch offset
_CHROME_EPOCH_OFFSET = 11644473600
_WEBKIT_EPOCH_OFFSET = 978307200


def unfurl_url(url: str) -> List[Dict[str, str]]:
    """Extract forensic artifacts from a URL.

    Returns a list of dicts with keys: type, key, value.
    Covers: search terms, embedded URLs, timestamps in params,
    Google protobuf URLs, geo coordinates, fragment data,
    multi-layer encoding.
    """
    findings: List[Dict[str, str]] = []
    try:
        parsed = urlparse(url)
    except Exception:
        return findings

    # --- 1. Query parameter analysis ---
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
    except Exception:
        pairs = []

    for k, v in pairs:
        dk = unquote_plus(k)
        dv = unquote_plus(v)

        # Multi-layer decode (e.g. double-encoded %2528 -> %28 -> ()
        prev = dv
        for _ in range(3):
            decoded = unquote(prev)
            if decoded == prev:
                break
            prev = decoded
        if prev != unquote_plus(v):
            findings.append({"type": "encoded_param", "key": dk, "value": prev})
            dv = prev

        # Embedded URLs in params
        if _URL_PARAMS.match(dk) and dv.startswith(("http://", "https://", "//")):
            findings.append({"type": "embedded_url", "key": dk, "value": dv})
            # Recurse one level into the embedded URL
            sub = unfurl_url(dv)
            for s in sub:
                s["key"] = f"{dk} > {s['key']}"
                findings.append(s)

        # Timestamp detection in param values
        if _TIMESTAMP_PARAMS.match(dk):
            ts = _try_parse_timestamp(dv)
            if ts:
                findings.append({"type": "embedded_timestamp", "key": dk, "value": ts})

        # Even for non-timestamp-named params, detect epoch values
        if not _TIMESTAMP_PARAMS.match(dk) and re.match(r"^\d{10,13}$", dv):
            ts = _try_parse_timestamp(dv)
            if ts:
                findings.append({"type": "embedded_timestamp", "key": dk, "value": ts})

        # Try binary protobuf decode on base64 values
        if len(dv) >= 20 and _looks_b64(dv):
            try:
                raw = base64.b64decode(dv.strip())
                pb_fields = decode_protobuf_binary(raw)
                if pb_fields and len(pb_fields) >= 2:
                    flat = _flatten_protobuf(pb_fields, f"{dk}.")
                    if flat:
                        findings.extend(flat)
            except Exception:
                pass

    # --- 2. Search engine query extraction ---
    for pattern, param_name in SEARCH_ENGINE_PATTERNS:
        if pattern.search(url):
            params = dict(pairs)
            terms = params.get(param_name, "")
            if terms:
                findings.append({"type": "search_terms", "key": param_name, "value": unquote_plus(terms)})
            break

    # --- 3. Google protobuf URL decoding ---
    # These appear in Google Maps, News, etc. as data= or /maps/place/...
    pb_text = parsed.query or parsed.path or ""
    if "!" in pb_text and _PB_TOKEN_RE.search(pb_text):
        pb_findings = _decode_protobuf_url(pb_text)
        findings.extend(pb_findings)

    # --- 4. Google Maps specific ---
    host = (parsed.hostname or "").lower()
    if "google" in host and ("/maps" in parsed.path or "maps.google" in host):
        # Place name from /place/Encoded+Name/
        m = _GMAPS_PLACE_RE.search(parsed.path)
        if m:
            place = unquote_plus(m.group(1).replace("+", " "))
            findings.append({"type": "geo_place", "key": "place_name", "value": place})

        # @lat,lon from URL path
        m = _GMAPS_COORDS_RE.search(parsed.path)
        if m:
            findings.append({"type": "geo_coords", "key": "lat,lon",
                             "value": f"{m.group(1)}, {m.group(2)}"})

    # --- 5. Fragment analysis (SPA state, anchors) ---
    if parsed.fragment:
        frag = parsed.fragment
        # Try parsing fragment as query string (Gmail, Angular apps)
        # Only treat as key-value if there are actual = signs
        frag_pairs = parse_qsl(frag, keep_blank_values=True) if "=" in frag else []
        if frag_pairs:
            for fk, fv in frag_pairs:
                dfk = unquote_plus(fk)
                dfv = unquote_plus(fv)
                if dfv.startswith(("http://", "https://")):
                    findings.append({"type": "fragment_url", "key": f"#{dfk}", "value": dfv})
                elif re.match(r"^\d{10,13}$", dfv):
                    ts = _try_parse_timestamp(dfv)
                    if ts:
                        findings.append({"type": "embedded_timestamp", "key": f"#{dfk}", "value": ts})
                elif len(dfv) > 3:
                    findings.append({"type": "fragment", "key": f"#{dfk}", "value": dfv})
        elif "/" in frag or "=" in frag:
            # SPA route in fragment
            findings.append({"type": "fragment", "key": "#route", "value": frag})
        elif frag:
            findings.append({"type": "fragment", "key": "#anchor", "value": frag})

    # --- 6. Google ei parameter (encrypted timestamp) ---
    ei = dict(pairs).get("ei", "")
    if ei and host and "google" in host:
        ts = _decode_google_ei(ei)
        if ts:
            findings.append({"type": "embedded_timestamp", "key": "ei (Google timestamp)", "value": ts})

    # --- 7. Google ved parameter ---
    ved = dict(pairs).get("ved", "")
    if ved and host and "google" in host:
        findings.append({"type": "google_ved", "key": "ved", "value": f"(tracking token, {len(ved)} chars)"})

    return findings


def _try_parse_timestamp(val: str) -> str:
    """Try to interpret a string as a timestamp. Returns ISO-8601 or empty."""
    try:
        num = float(val)
    except (ValueError, OverflowError):
        return ""

    # Try as Unix epoch seconds
    if 946684800 <= num <= 4102444800:  # 2000-01-01 to 2100-01-01
        try:
            return datetime.fromtimestamp(num, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, OverflowError, ValueError):
            pass

    # Try as Unix epoch milliseconds
    if 946684800000 <= num <= 4102444800000:
        try:
            return datetime.fromtimestamp(num / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, OverflowError, ValueError):
            pass

    # Try as Chrome epoch (microseconds since 1601-01-01)
    if num > 12000000000000000:  # reasonable Chrome timestamp range
        try:
            unix_ts = (num / 1_000_000) - _CHROME_EPOCH_OFFSET
            if 0 < unix_ts < 4102444800:
                return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") + " (Chrome epoch)"
        except (OSError, OverflowError, ValueError):
            pass

    # Try as WebKit/Safari epoch (seconds since 2001-01-01)
    if 0 < num < 1000000000 and num + _WEBKIT_EPOCH_OFFSET > 946684800:
        try:
            unix_ts = num + _WEBKIT_EPOCH_OFFSET
            if unix_ts < 4102444800:
                return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") + " (WebKit epoch)"
        except (OSError, OverflowError, ValueError):
            pass

    return ""


def _decode_protobuf_url(text: str) -> List[Dict[str, str]]:
    """Decode Google-style protobuf URL parameters.

    Format: !<field_number><type_char><value>
    Type chars: s=string, d=double, f=float, i=int, m=group(start),
                e=enum, b=bool, x=fixed64, y=fixed32
    """
    findings = []
    for m in _PB_TOKEN_RE.finditer(text):
        field_num = m.group(1)
        type_char = m.group(2)
        value = m.group(3)

        if not value:
            continue

        label = f"pb!{field_num}{type_char}"

        if type_char == "s":
            # String value — often a place ID, address, or name
            decoded = unquote_plus(value)
            if len(decoded) > 2:
                # Check if it looks like coordinates
                if re.match(r"^0x[0-9a-f]+:0x[0-9a-f]+$", decoded):
                    findings.append({"type": "protobuf", "key": label + " (place_id)", "value": decoded})
                elif decoded.startswith("http"):
                    findings.append({"type": "protobuf", "key": label + " (url)", "value": decoded})
                else:
                    findings.append({"type": "protobuf", "key": label + " (string)", "value": decoded})

        elif type_char == "d":
            # Double — often longitude or latitude
            try:
                dval = float(value)
                if -180 <= dval <= 180:
                    findings.append({"type": "protobuf", "key": label + " (double/coord)", "value": str(dval)})
            except ValueError:
                pass

        elif type_char in ("i", "e"):
            # Integer or enum
            try:
                ival = int(value)
                # Check if it could be a timestamp
                ts = _try_parse_timestamp(value)
                if ts:
                    findings.append({"type": "embedded_timestamp", "key": label, "value": ts})
                elif ival > 100:  # skip small enums
                    findings.append({"type": "protobuf", "key": label + " (int)", "value": value})
            except ValueError:
                pass

        elif type_char == "f":
            try:
                fval = float(value)
                findings.append({"type": "protobuf", "key": label + " (float)", "value": str(fval)})
            except ValueError:
                pass

    # Look for lat/lon pairs in the protobuf data
    doubles = []
    for m in _PB_TOKEN_RE.finditer(text):
        if m.group(2) == "d":
            try:
                doubles.append(float(m.group(3)))
            except ValueError:
                pass
    # If we have consecutive doubles that look like lat/lon
    for i in range(len(doubles) - 1):
        if -90 <= doubles[i + 1] <= 90 and -180 <= doubles[i] <= 180:
            findings.append({"type": "geo_coords", "key": "protobuf lat,lon",
                             "value": f"{doubles[i + 1]}, {doubles[i]}"})
            break

    return findings


# ---------------------------------------------------------------------------
# Schemaless protobuf binary decoder (like blackboxprotobuf, zero deps)
# ---------------------------------------------------------------------------

def decode_protobuf_binary(data: bytes, depth: int = 0) -> List[Dict[str, Any]]:
    """Decode raw protobuf wire format without a schema.

    Like blackboxprotobuf: interprets field numbers and wire types,
    recursively decodes nested messages, extracts strings/ints/floats.
    """
    if depth > 5:
        return []
    fields = []
    pos = 0
    while pos < len(data):
        try:
            # Read varint tag
            tag, pos = _read_varint(data, pos)
            if tag < 0:
                break
            field_num = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 0:  # Varint
                val, pos = _read_varint(data, pos)
                entry = {"field": field_num, "wire_type": "varint", "value": val}
                # Check if it could be a timestamp
                ts = _try_parse_timestamp(str(val))
                if ts:
                    entry["decoded"] = ts
                fields.append(entry)

            elif wire_type == 1:  # 64-bit (fixed64 / double)
                if pos + 8 > len(data):
                    break
                raw = data[pos:pos + 8]
                pos += 8
                dval = struct.unpack("<d", raw)[0]
                ival = struct.unpack("<Q", raw)[0]
                entry = {"field": field_num, "wire_type": "fixed64"}
                if -180 <= dval <= 180 and dval != 0:
                    entry["value"] = dval
                    entry["decoded"] = f"double: {dval}"
                else:
                    entry["value"] = ival
                fields.append(entry)

            elif wire_type == 2:  # Length-delimited (string/bytes/nested)
                length, pos = _read_varint(data, pos)
                if length < 0 or pos + length > len(data):
                    break
                chunk = data[pos:pos + length]
                pos += length
                entry = {"field": field_num, "wire_type": "bytes", "length": length}
                # Try to decode as UTF-8 string
                try:
                    text = chunk.decode("utf-8")
                    if all(c.isprintable() or c in "\n\r\t" for c in text):
                        entry["value"] = text
                        entry["decoded"] = f"string: {text}"
                    else:
                        raise ValueError
                except (UnicodeDecodeError, ValueError):
                    # Try as nested protobuf
                    nested = decode_protobuf_binary(chunk, depth + 1)
                    if nested and len(nested) >= 1:
                        entry["value"] = nested
                        entry["decoded"] = "nested message"
                    else:
                        entry["value"] = chunk.hex()
                fields.append(entry)

            elif wire_type == 5:  # 32-bit (fixed32 / float)
                if pos + 4 > len(data):
                    break
                raw = data[pos:pos + 4]
                pos += 4
                fval = struct.unpack("<f", raw)[0]
                ival = struct.unpack("<I", raw)[0]
                entry = {"field": field_num, "wire_type": "fixed32"}
                if abs(fval) < 1e10 and fval != 0:
                    entry["value"] = fval
                else:
                    entry["value"] = ival
                fields.append(entry)
            else:
                break  # Unknown wire type
        except (IndexError, struct.error):
            break
    return fields


def _read_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Read a protobuf varint from data at pos. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            return -1, pos
    return -1, pos


def _flatten_protobuf(fields: List[Dict], prefix: str = "") -> List[Dict[str, str]]:
    """Flatten decoded protobuf fields into unfurl findings."""
    findings = []
    for f in fields:
        label = f"{prefix}field_{f['field']}"
        if isinstance(f.get("value"), list):
            # Nested message
            findings.extend(_flatten_protobuf(f["value"], label + "."))
        elif f.get("decoded"):
            findings.append({
                "type": "protobuf",
                "key": f"{label} ({f['wire_type']})",
                "value": str(f["decoded"])
            })
        elif isinstance(f.get("value"), (int, float)):
            val = f["value"]
            if isinstance(val, float) and -180 <= val <= 180 and val != 0:
                findings.append({"type": "protobuf", "key": f"{label} (coord?)", "value": str(val)})
            elif isinstance(val, int) and val > 1000000:
                ts = _try_parse_timestamp(str(val))
                if ts:
                    findings.append({"type": "embedded_timestamp", "key": label, "value": ts})
    return findings


def _decode_google_ei(ei: str) -> str:
    """Decode Google's ei parameter which encodes a timestamp.

    The ei parameter is a base64-encoded protobuf with the timestamp
    as a varint in the first field.
    """
    # Google uses URL-safe base64 with no padding
    try:
        padded = ei + "=" * (4 - len(ei) % 4) if len(ei) % 4 else ei
        raw = base64.urlsafe_b64decode(padded)
        if len(raw) < 4:
            return ""
        # First 4 bytes are a little-endian uint32 Unix timestamp
        ts = struct.unpack("<I", raw[:4])[0]
        if 946684800 <= ts <= 4102444800:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass
    return ""


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

    # URL unfurling
    try:
        record.unfurl = unfurl_url(record.full_url)
    except Exception as e:
        LOG.debug("Unfurl error: %s", e)
        record.unfurl = []

    # Run all classifiers
    tags = []
    for name, clf_fn in _CLASSIFIER_REGISTRY:
        try:
            result = clf_fn(record)
            if result:
                tags.append(result)
        except Exception as e:
            LOG.debug("Classifier %s error: %s", name, e)

    # Add tags from unfurl findings
    for f in record.unfurl:
        if f["type"] == "geo_coords":
            tags.append("has_geo_coords")
        elif f["type"] == "embedded_url":
            tags.append("has_embedded_url")
        elif f["type"] == "embedded_timestamp":
            tags.append("has_embedded_timestamp")
        elif f["type"] == "protobuf":
            tags.append("protobuf_data")

    record.tags = sorted(set(tags))
    return record


def classify_batch(records: List[VisitRecord]) -> List[VisitRecord]:
    """Classify a batch of visit records."""
    return [classify_visit(r) for r in records]
