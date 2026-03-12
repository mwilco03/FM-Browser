"""Constants, patterns, and classifier registry."""
import re

# Archive extraction passwords (tried in order)
ARCHIVE_PASSWORDS = ["infected", "dangerous", ""]

# Maximum extraction ratio (zip bomb protection)
MAX_EXTRACTION_RATIO = 100
MAX_EXTRACTED_SIZE_BYTES = 10 * 1024 * 1024 * 1024  # 10GB
MAX_NESTING_DEPTH = 10

# Timestamp epoch offsets
CHROME_EPOCH_OFFSET_S = 11644473600  # 1601-01-01 to 1970-01-01
SAFARI_EPOCH_OFFSET_S = 978307200    # 2001-01-01 to 1970-01-01
TICK_DIVISOR = 1_000_000             # microseconds to seconds

# Chrome transition core types (lower 8 bits)
CHROME_TRANSITION_CORE = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe",
    4: "manual_subframe", 5: "generated", 6: "auto_toplevel",
    7: "form_submit", 8: "reload", 9: "keyword", 10: "keyword_generated",
}

# Chrome transition qualifier bits
CHROME_TRANSITION_QUALIFIERS = {
    0x00800000: "blocked",
    0x01000000: "forward_back",
    0x02000000: "from_address_bar",
    0x04000000: "home_page",
    0x08000000: "from_api",
    0x10000000: "chain_start",
    0x20000000: "chain_end",
    0x40000000: "client_redirect",
    0x80000000: "server_redirect",
}

# Chrome visit_source table values
CHROME_VISIT_SOURCE = {
    0: "local",
    1: "synced",
    2: "extension",
    3: "imported",
    4: "local",  # BROWSED (newer Chrome)
}

# Firefox visit types
FIREFOX_VISIT_TYPE = {
    1: "link", 2: "typed", 3: "bookmark", 4: "embed",
    5: "redirect_permanent", 6: "redirect_temporary",
    7: "download", 8: "framed_link", 9: "reload",
}

# Schema detection probes
SCHEMA_PROBES = {
    "chromium": "SELECT 1 FROM urls LIMIT 1",
    "webkit":   "SELECT 1 FROM history_items LIMIT 1",
    "gecko":    "SELECT 1 FROM moz_places LIMIT 1",
}

# macOS browser path patterns: (regex, browser_name)
MACOS_BROWSER_PATHS = [
    (re.compile(r"Users/([^/]+)/Library/Safari/History\.db", re.I), "safari"),
    (re.compile(r"Users/([^/]+)/Library/Application Support/Google/Chrome/([^/]+)/History", re.I), "chrome"),
    (re.compile(r"Users/([^/]+)/Library/Application Support/Firefox/Profiles/([^/]+)/places\.sqlite", re.I), "firefox"),
    (re.compile(r"Users/([^/]+)/Library/Application Support/BraveSoftware/Brave-Browser/([^/]+)/History", re.I), "brave"),
    (re.compile(r"Users/([^/]+)/Library/Application Support/Microsoft Edge/([^/]+)/History", re.I), "edge"),
    (re.compile(r"Users/([^/]+)/Library/Application Support/Vivaldi/([^/]+)/History", re.I), "vivaldi"),
    (re.compile(r"Users/([^/]+)/Library/Application Support/Arc/User Data/([^/]+)/History", re.I), "arc"),
]

# Windows browser path patterns
WINDOWS_BROWSER_PATHS = [
    (re.compile(r"Users/([^/]+)/AppData/Local/Google/Chrome/User Data/([^/]+)/History", re.I), "chrome"),
    (re.compile(r"Users/([^/]+)/AppData/Roaming/Mozilla/Firefox/Profiles/([^/]+)/places\.sqlite", re.I), "firefox"),
    (re.compile(r"Users/([^/]+)/AppData/Local/Microsoft/Edge/User Data/([^/]+)/History", re.I), "edge"),
    (re.compile(r"Users/([^/]+)/AppData/Local/BraveSoftware/Brave-Browser/User Data/([^/]+)/History", re.I), "brave"),
    (re.compile(r"Users/([^/]+)/AppData/Local/Vivaldi/User Data/([^/]+)/History", re.I), "vivaldi"),
]

# OS detection patterns
OS_PATH_INDICATORS = {
    "windows": [
        re.compile(r"(Users|Documents and Settings)[/\\].*AppData", re.I),
        re.compile(r"[A-Z]:[/\\]", re.I),
    ],
    "macos": [
        re.compile(r"Library[/\\](Application Support|Safari)", re.I),
        re.compile(r"/Users/[^/]+/Library", re.I),
    ],
    "linux": [
        re.compile(r"/home/[^/]+/\.(mozilla|config/(google-chrome|chromium))", re.I),
    ],
}

# Sensitive query parameter key patterns
SENSITIVE_PARAM_KEYS = re.compile(
    r"^(key|token|api_?key|access_token|secret|password|auth|bearer|"
    r"session_id|csrf|client_secret|refresh_token)$", re.I
)

# Search engine patterns for extracting search queries
SEARCH_ENGINE_PATTERNS = [
    (re.compile(r"google\.\w+/search"), "q"),
    (re.compile(r"bing\.com/search"), "q"),
    (re.compile(r"duckduckgo\.com/"), "q"),
    (re.compile(r"yahoo\.com/search"), "p"),
    (re.compile(r"search\.yahoo\.com"), "p"),
    (re.compile(r"baidu\.com/s"), "wd"),
    (re.compile(r"yandex\.\w+/search"), "text"),
]

# RFC1918 / internal network patterns
INTERNAL_NETWORK_PATTERNS = re.compile(
    r"^(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"127\.\d+\.\d+\.\d+|localhost|::1|.*\.(local|internal|corp|lan)$)"
)

# Cloud storage host patterns
CLOUD_STORAGE_HOSTS = re.compile(
    r"(\.s3\.amazonaws\.com|s3\..*\.amazonaws\.com|storage\.googleapis\.com|"
    r"\.blob\.core\.windows\.net|drive\.google\.com|docs\.google\.com|"
    r"dropbox\.com|onedrive\.live\.com|mega\.nz|box\.com)", re.I
)

# Paste/upload site hosts
PASTE_SITE_HOSTS = re.compile(
    r"(pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.com|dpaste\.org|"
    r"transfer\.sh|file\.io|wetransfer\.com|sendgb\.com|gofile\.io|"
    r"anonfiles\.com)", re.I
)

# Download file extensions
DOWNLOAD_EXTENSIONS = re.compile(
    r"\.(exe|msi|dmg|pkg|deb|rpm|zip|7z|rar|tar\.gz|iso|"
    r"docm|xlsm|ps1|bat|sh|py|jar|apk|ipa|cmd|scr|dll)\b", re.I
)

# Suspicious TLDs
SUSPICIOUS_TLDS = re.compile(
    r"\.(tk|ml|ga|cf|gq|buzz|top|xyz|work|click|loan|racing|win|bid|stream)\b", re.I
)

# Interesting string detection patterns
INTERESTING_PATTERNS = {
    "base64_payload":  re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    "jwt_token":       re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
    "ip_address_host": re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}"),
    "long_hex":        re.compile(r"[0-9a-f]{32,}", re.I),
    "oauth_code":      re.compile(r"(code|token|access_token|id_token)=[A-Za-z0-9._-]{20,}"),
    "protobuf_url":    re.compile(r"![\d]+[a-z]"),
}

# strftime patterns for time-based aggregation
INTERVAL_STRFTIME = {
    "hour":  "%Y-%m-%dT%H:00:00Z",
    "day":   "%Y-%m-%d",
    "week":  "%Y-W%W",
    "month": "%Y-%m",
}

# Search/pagination defaults
DEFAULT_SEARCH_LIMIT = 50
MAX_SEARCH_LIMIT = 500
