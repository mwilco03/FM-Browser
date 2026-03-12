# Browser History Forensic Search Engine

## Design Document v1.0

---

## 1. Problem Statement

Given a 7z-compressed forensic acquisition from an endpoint (Mac or Windows), containing all browser history SQLite databases, build a tool that:

- Recursively decompresses nested archives (7z, zip, tar.gz, arbitrary nesting) using password "infected"
- Discovers and ingests Safari, Chrome, Firefox, and Chromium-derivative browser history databases
- Indexes all visit data into a SQLite FTS5 full-text search engine
- Serves a web-based SPA for searching, filtering, and exploring the ingested data
- Progressively builds and populates dashboard views as the user interacts with the data (no pre-rendered static dashboards)

---

## 2. Architecture Overview

Four discrete pipeline stages, each independently testable, followed by a server and SPA layer.

```
[Archive File]
     |
     v
 STAGE 1: EXTRACT
 Recursive decompression, yields temp files + provenance chains
     |
     v
 STAGE 2: INGEST
 Browser-specific SQLite queries, per-visit rows, normalize timestamps
     |
     v
 STAGE 3: CLASSIFY
 Tag each visit: sync vs local, interesting strings, URL decomposition
     |
     v
 STAGE 4: INDEX
 Insert into FTS5 index with all columns and tags
     |
     v
 [Flask Server + SPA]
 REST API, progressive dashboard views, full-text search
```

Each stage is a Python module with a clear input/output contract. Re-running Stage 3 does not require re-running Stages 1-2. Adding a new classifier does not touch extraction code.

---

## 3. Stage 1: Extract

### 3.1 Recursive Archive Walker

The extractor receives a single file path. It asks "is this an archive?" and if so, extracts to a temp directory, then walks every file in that directory asking the same question. This recurses until no more archives are found.

Supported formats and nesting patterns:

| Pattern | Example |
|---|---|
| Single 7z | `evidence.7z` |
| Double 7z | `evidence.7z` containing `inner.7z` |
| 7z wrapping zip | `evidence.7z` containing `data.zip` |
| 7z wrapping tar.gz | `evidence.7z` containing `data.tar.gz` |
| Triple nesting | `outer.7z` > `mid.7z` > `inner.tar.gz` |

### 3.2 Password Handling

At every decompression level, try passwords in this order:

1. "infected"
2. "dangerous"
3. No password (inner archives are not always encrypted)

If all fail, log the file path and skip. Do not halt the pipeline.

### 3.3 Implementation

Shell out to the `7z` command-line tool for all formats. It handles 7z, zip (including AES-encrypted zip which Python's zipfile module cannot), tar.gz, and nested archives uniformly. Python's stdlib zipfile and tarfile are insufficient for the encrypted cases.

Install dependency: `apt-get install p7zip-full` or equivalent.

```
7z x -p{password} -o{output_dir} {archive_path}
```

For tar.gz specifically, `7z` extracts the .gz first producing a .tar, then extract the .tar in a second pass. The recursive walker handles this naturally.

### 3.4 Safety

- Check for path traversal: reject any archived path containing `..`
- Check for zip bombs: set a maximum extraction ratio (e.g. 100:1) and a maximum total extracted size (e.g. 10GB)
- Extract into a unique temp directory per archive level
- Clean up temp directories after ingestion completes (configurable: keep for debugging)

### 3.5 Output

Each discovered file yields a record:

```python
@dataclass
class ExtractedFile:
    temp_path: Path           # where the file was extracted to
    provenance_chain: str     # "outer.7z > inner.tar.gz > Users/alice/Library/Safari/History.db"
    original_archive_path: str # path within the outermost archive
```

### 3.6 Platform and Browser Detection From Paths

The file's path within the archive encodes the source OS, browser, user, and profile. Detection rules:

**macOS indicators** (path contains `Library`):

| Browser | Path pattern |
|---|---|
| Safari | `Users/{user}/Library/Safari/History.db` |
| Chrome | `Users/{user}/Library/Application Support/Google/Chrome/{profile}/History` |
| Firefox | `Users/{user}/Library/Application Support/Firefox/Profiles/{hash}.{profile}/places.sqlite` |
| Brave | `Users/{user}/Library/Application Support/BraveSoftware/Brave-Browser/{profile}/History` |
| Edge | `Users/{user}/Library/Application Support/Microsoft Edge/{profile}/History` |
| Vivaldi | `Users/{user}/Library/Application Support/Vivaldi/{profile}/History` |
| Arc | `Users/{user}/Library/Application Support/Arc/User Data/{profile}/History` |

**Windows indicators** (path contains `AppData`):

| Browser | Path pattern |
|---|---|
| Chrome | `Users/{user}/AppData/Local/Google/Chrome/User Data/{profile}/History` |
| Firefox | `Users/{user}/AppData/Roaming/Mozilla/Firefox/Profiles/{hash}.{profile}/places.sqlite` |
| Edge | `Users/{user}/AppData/Local/Microsoft/Edge/User Data/{profile}/History` |
| Brave | `Users/{user}/AppData/Local/BraveSoftware/Brave-Browser/User Data/{profile}/History` |
| Vivaldi | `Users/{user}/AppData/Local/Vivaldi/User Data/{profile}/History` |

Extract from each matched path:

```python
@dataclass
class SourceMetadata:
    os_platform: str        # "macos" | "windows"
    browser: str            # "safari" | "chrome" | "firefox" | "edge" | "brave" | "vivaldi" | "arc"
    browser_engine: str     # "webkit" | "chromium" | "gecko"
    browser_profile: str    # "Default" | "Profile 1" | "abc123.default-release" etc.
    os_username: str        # extracted from the Users/{user} segment
    endpoint_name: str      # if recoverable from archive name or hostname files
```

The `browser_engine` field matters because all Chromium derivatives share the same History schema. Use an enum to map:

```python
class BrowserEngine(Enum):
    CHROMIUM = "chromium"  # Chrome, Edge, Brave, Vivaldi, Arc, Opera
    GECKO = "gecko"        # Firefox
    WEBKIT = "webkit"      # Safari
```

Use the engine, not the browser name, to select the SQL extraction query.

---

## 4. Stage 2: Ingest

### 4.1 The Core Problem With the Current Queries

The existing code queries summary tables (`urls` in Chrome, `moz_places` in Firefox) which only store the last visit time and an aggregate count. These are **deduplicated summaries**, not visit logs. The actual per-visit records with forensically critical metadata live in separate tables.

### 4.2 Chrome / Chromium Schema (all Chromium derivatives)

The correct query joins `urls` with `visits`:

```sql
SELECT
    urls.url,
    urls.title,
    visits.visit_time,
    visits.from_visit,
    visits.transition,
    visits.visit_duration,
    visits.incremented_omnibox_typed_score,
    COALESCE(visit_source.source, 0) AS visit_source
FROM visits
JOIN urls ON urls.id = visits.url
LEFT JOIN visit_source ON visit_source.id = visits.id
ORDER BY visits.visit_time DESC
```

**Critical columns:**

`visits.visit_time`: microseconds since 1601-01-01 (Windows/Chrome epoch). Convert: `(visit_time / 1000000) - 11644473600` to get Unix timestamp.

`visit_source.source` (the sync detection column):

| Value | Constant | Meaning |
|---|---|---|
| 0 | LOCAL | User navigated on this machine |
| 1 | SYNCED | Arrived via Chrome Sync |
| 2 | EXTENSION | Navigated by a browser extension |
| 3 | IMPORTED | Imported from another browser |
| 4 | BROWSED | (newer Chrome) browsing on this device |

Note: the `visit_source` table may not exist in all Chrome versions. Use LEFT JOIN. If the table is absent, default all visits to LOCAL.

`visits.transition`: a bitmask encoding navigation type. The lower 8 bits are the core type:

| Value | Constant | Meaning |
|---|---|---|
| 0 | LINK | Clicked a link |
| 1 | TYPED | Typed URL in address bar |
| 2 | AUTO_BOOKMARK | Opened from bookmark |
| 3 | AUTO_SUBFRAME | Subframe navigation (ads, iframes) |
| 4 | MANUAL_SUBFRAME | User-initiated subframe |
| 5 | GENERATED | Generated (e.g. form submission) |
| 6 | AUTO_TOPLEVEL | Auto top-level (e.g. pre-render) |
| 7 | FORM_SUBMIT | Form submission |
| 8 | RELOAD | Page reload |
| 9 | KEYWORD | Omnibox keyword search |
| 10 | KEYWORD_GENERATED | Omnibox keyword (auto) |

Upper bits are qualifiers:

| Bit | Meaning |
|---|---|
| 0x00800000 | BLOCKED (navigation blocked) |
| 0x01000000 | FORWARD_BACK (forward/back button) |
| 0x02000000 | FROM_ADDRESS_BAR (typed or selected from bar) |
| 0x04000000 | HOME_PAGE (home page navigation) |
| 0x08000000 | FROM_API (initiated by API) |
| 0x10000000 | CHAIN_START (start of redirect chain) |
| 0x20000000 | CHAIN_END (end of redirect chain) |
| 0x40000000 | CLIENT_REDIRECT |
| 0x80000000 | SERVER_REDIRECT |

Store the raw integer and decode in the classify stage. The `from_visit` column references another visit ID, forming a navigation chain (referrer relationships).

### 4.3 Firefox / Gecko Schema

```sql
SELECT
    moz_places.url,
    moz_places.title,
    moz_historyvisits.visit_date,
    moz_historyvisits.visit_type,
    moz_historyvisits.from_visit,
    moz_places.visit_count,
    moz_places.frecency
FROM moz_historyvisits
JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
ORDER BY moz_historyvisits.visit_date DESC
```

`moz_historyvisits.visit_date`: microseconds since Unix epoch.

`moz_historyvisits.visit_type`:

| Value | Constant | Meaning |
|---|---|---|
| 1 | TRANSITION_LINK | Clicked a link |
| 2 | TRANSITION_TYPED | Typed in address bar |
| 3 | TRANSITION_BOOKMARK | Opened from bookmark |
| 4 | TRANSITION_EMBED | Embedded (iframe/subframe) |
| 5 | TRANSITION_REDIRECT_PERMANENT | 301 redirect |
| 6 | TRANSITION_REDIRECT_TEMPORARY | 302 redirect |
| 7 | TRANSITION_DOWNLOAD | Download |
| 8 | TRANSITION_FRAMED_LINK | Framed link click |

**Firefox sync detection**: Firefox does not store a `visit_source` column like Chrome. Sync provenance detection requires heuristic analysis:

1. Check for `weave/` directory or `storage-sync-v2.sqlite` in the same profile; its presence confirms Sync was enabled
2. Check `moz_meta` table for a `sync/deviceID` key; if present, this profile was synced
3. Visits that arrive via sync typically have no `from_visit` parent (the navigation chain starts at that visit with no referrer on this machine), and they may appear in clusters at similar timestamps (sync batch arrival)
4. If the profile has Sync enabled but a visit has a `from_visit` chain rooted in another local visit, it is LOCAL

This is heuristic, not definitive. Mark the confidence level: `CONFIRMED_LOCAL`, `CONFIRMED_SYNCED`, `LIKELY_SYNCED`, `UNKNOWN`.

### 4.4 Safari / WebKit Schema

```sql
SELECT
    history_items.url,
    history_items.title,
    history_visits.visit_time,
    history_visits.redirect_source,
    history_visits.redirect_destination,
    history_visits.origin,
    history_visits.generation,
    history_visits.attributes,
    history_visits.score
FROM history_visits
JOIN history_items ON history_items.id = history_visits.history_item
ORDER BY history_visits.visit_time DESC
```

`history_visits.visit_time`: seconds since 2001-01-01 (Apple/Core Data epoch). Convert: `visit_time + 978307200` to get Unix timestamp.

`history_visits.origin`: encodes navigation source. Values vary by Safari version; newer versions provide richer data.

`history_visits.redirect_source` / `redirect_destination`: link visits into redirect chains.

**Safari sync detection**: Safari syncs via iCloud. There is no explicit sync flag in the SQLite schema. Heuristic approach:

1. Look for `history_tombstones` table; its presence indicates sync is active
2. Sync-arrived visits tend to appear in bulk batches with sub-second timestamp spacing (many visits inserted at nearly identical times, which is not organic browsing behavior)
3. Check if `history_visits.origin` column exists and has distinguishing values (schema-version dependent)

### 4.5 Timestamp Normalization

All timestamps must be normalized to ISO-8601 UTC strings for storage and comparison. Each browser has its own epoch:

| Browser Engine | Epoch | Unit | Conversion to Unix seconds |
|---|---|---|---|
| Chromium | 1601-01-01 | microseconds | `(value / 1000000) - 11644473600` |
| Gecko | 1970-01-01 | microseconds | `value / 1000000` |
| WebKit | 2001-01-01 | seconds | `value + 978307200` |

Store as ISO-8601 string (`2024-01-15T10:30:00Z`) for FTS5 range queries and human readability.

### 4.6 Output

Each visit becomes a record:

```python
@dataclass
class VisitRecord:
    # Source identification
    provenance_chain: str
    source_db_path: str
    os_platform: str
    browser: str
    browser_engine: str
    browser_profile: str
    os_username: str
    endpoint_name: str

    # Visit data
    visit_time_utc: str
    full_url: str
    title: str

    # URL decomposition (populated in Stage 3)
    dns_host: str
    url_path: str
    query_string_decoded: str

    # Navigation metadata
    visit_source: str          # "local" | "synced" | "extension" | "imported" | "unknown"
    visit_source_confidence: str  # "confirmed" | "likely" | "unknown"
    transition_type: str       # "typed" | "link" | "bookmark" | "redirect" | "form" | "reload" | etc.
    transition_qualifiers: str # comma-separated: "from_address_bar,chain_end,server_redirect"
    from_visit_url: str        # the referring URL if recoverable from from_visit chain
    visit_duration_ms: int     # if available (Chrome only)

    # Classification (populated in Stage 3)
    tags: str                  # JSON array of classifier hits
```

---

## 5. Stage 3: Classify

### 5.1 URL Decomposition

For every visit, parse the URL into:
- `dns_host`: hostname
- `url_path`: path component
- `query_string_decoded`: all query params with percent-decoding, plus-decoding, and base64 decoding where detected

For Google-specific encoded params (`ved`, `ei`, `aqs`, `oq`, `gs_lcrp`), attempt protobuf decoding. Use the raw `protobuf.decode_raw` approach (schema-less wire-format decoding) since we do not have Google's .proto definitions. Store the decoded field tree as a readable string. If Unfurl is available as a dependency, delegate to it.

### 5.2 Visit Source Resolution

Apply the logic from Section 4 to populate `visit_source` and `visit_source_confidence`:

For Chromium: direct lookup from `visit_source` table. Confidence is always `confirmed`.

For Firefox: apply the heuristic (sync enabled + no from_visit parent + cluster arrival = `likely_synced`; sync not enabled = `confirmed_local`).

For Safari: apply the heuristic (tombstones table present + batch timestamp pattern = `likely_synced`; no tombstones = `confirmed_local`).

### 5.3 Transition Type Normalization

Map each browser's raw transition value to a unified enum:

```python
class TransitionType(Enum):
    TYPED = "typed"
    LINK = "link"
    BOOKMARK = "bookmark"
    REDIRECT_PERMANENT = "redirect_permanent"
    REDIRECT_TEMPORARY = "redirect_temporary"
    FORM_SUBMIT = "form_submit"
    RELOAD = "reload"
    EMBEDDED = "embedded"
    DOWNLOAD = "download"
    GENERATED = "generated"
    KEYWORD = "keyword"
    OTHER = "other"
```

For Chrome, also extract qualifier bits into a comma-separated string.

### 5.4 Interesting String Classifiers

Each classifier is a function `(VisitRecord) -> Optional[str]` that returns a tag name if the condition matches, or None. All classifiers run on every visit. Results accumulate into the `tags` JSON array.

Classifier registry (each is a separate function, registered declaratively):

| Tag | Detection Logic |
|---|---|
| `cred_in_url` | URL contains `user:pass@host` pattern or `userinfo` component |
| `token_in_params` | Query params contain keys matching: `key`, `token`, `api_key`, `apikey`, `access_token`, `secret`, `password`, `auth`, `bearer`, `session_id`, `csrf` |
| `oauth_redirect` | URL path contains `/oauth/`, `/callback`, `/authorize`; or params include `code=`, `state=`, `redirect_uri=` |
| `b64_payload` | Query param value is base64-encoded and decodes to 32+ bytes of valid UTF-8 |
| `protobuf_encoded` | Google-style protobuf params detected (`ved`, `ei`, or wire-format heuristic on decoded b64) |
| `internal_network` | Host is RFC1918 (`10.*`, `172.16-31.*`, `192.168.*`), `localhost`, `127.*`, `::1`, `.local`, `.internal`, `.corp`, `.lan`, or a bare hostname with no TLD |
| `non_standard_port` | URL contains explicit port that is not 80 or 443 |
| `cloud_storage` | Host matches S3 bucket patterns (`*.s3.amazonaws.com`, `s3.*.amazonaws.com`), `storage.googleapis.com`, `*.blob.core.windows.net`, `drive.google.com`, `docs.google.com`, `dropbox.com`, `onedrive.live.com`, `mega.nz`, `box.com` |
| `file_scheme` | URL scheme is `file://`, `data:`, `javascript:`, `blob:`, `chrome-extension://`, `moz-extension://` |
| `download_url` | URL path ends in executable/archive/document extension: `.exe`, `.msi`, `.dmg`, `.pkg`, `.deb`, `.rpm`, `.zip`, `.7z`, `.rar`, `.tar.gz`, `.iso`, `.docm`, `.xlsm`, `.ps1`, `.bat`, `.sh`, `.py`, `.jar` |
| `paste_site` | Host matches known paste/upload services: `pastebin.com`, `paste.ee`, `hastebin.com`, `ghostbin.com`, `dpaste.org`, `transfer.sh`, `file.io`, `wetransfer.com`, `sendgb.com`, `gofile.io`, `anonfiles.com` |
| `encoded_long_payload` | Total query string length exceeds 2000 characters (potential data exfiltration or encoded command) |
| `dns_over_https` | Host matches known DoH providers and path contains `/dns-query` |
| `suspicious_tld` | TLD is in a watchlist of commonly abused TLDs (configurable, e.g. `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.buzz`, `.top`, `.xyz` for high-volume abuse) |
| `search_query` | URL is a recognized search engine query (Google, Bing, DuckDuckGo, Yahoo); extract and store the search terms |

The classifier list is declared as a constant registry (list of functions). Adding a classifier means writing one function and appending it to the registry. No other code changes.

### 5.5 From-Visit Chain Resolution

For Chrome and Firefox, the `from_visit` column references another visit ID in the same table. Walk this chain (up to a max depth of 10 to avoid cycles) to find the root referrer URL. Store as `from_visit_url` on the visit record. This reconstructs the user's navigation path: "user searched on Google, clicked result X, which redirected to Y."

---

## 6. Stage 4: Index

### 6.1 Schema

```sql
CREATE TABLE visits (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Source identification
    provenance_chain        TEXT NOT NULL DEFAULT '',
    source_db_path          TEXT NOT NULL DEFAULT '',
    os_platform             TEXT NOT NULL DEFAULT '',   -- "macos" | "windows"
    browser                 TEXT NOT NULL DEFAULT '',   -- "chrome" | "safari" | "firefox" | "edge" | "brave" ...
    browser_engine          TEXT NOT NULL DEFAULT '',   -- "chromium" | "gecko" | "webkit"
    browser_profile         TEXT NOT NULL DEFAULT '',
    os_username             TEXT NOT NULL DEFAULT '',
    endpoint_name           TEXT NOT NULL DEFAULT '',

    -- Visit data
    visit_time_utc          TEXT NOT NULL DEFAULT '',
    full_url                TEXT NOT NULL,
    title                   TEXT NOT NULL DEFAULT '',

    -- URL decomposition
    dns_host                TEXT NOT NULL DEFAULT '',
    url_path                TEXT NOT NULL DEFAULT '',
    query_string_decoded    TEXT NOT NULL DEFAULT '',

    -- Navigation metadata
    visit_source            TEXT NOT NULL DEFAULT 'unknown',
    visit_source_confidence TEXT NOT NULL DEFAULT 'unknown',
    transition_type         TEXT NOT NULL DEFAULT 'other',
    transition_qualifiers   TEXT NOT NULL DEFAULT '',
    from_visit_url          TEXT NOT NULL DEFAULT '',
    visit_duration_ms       INTEGER NOT NULL DEFAULT 0,

    -- Classification
    tags                    TEXT NOT NULL DEFAULT '[]'
);

-- Indexes for filtered queries and aggregations
CREATE INDEX idx_visits_host          ON visits(dns_host);
CREATE INDEX idx_visits_time          ON visits(visit_time_utc);
CREATE INDEX idx_visits_browser       ON visits(browser);
CREATE INDEX idx_visits_user          ON visits(os_username);
CREATE INDEX idx_visits_platform      ON visits(os_platform);
CREATE INDEX idx_visits_source        ON visits(visit_source);
CREATE INDEX idx_visits_transition    ON visits(transition_type);
CREATE INDEX idx_visits_endpoint      ON visits(endpoint_name);

-- FTS5 full-text index (content-sync mode)
CREATE VIRTUAL TABLE visits_fts USING fts5(
    full_url,
    title,
    query_string_decoded,
    dns_host,
    tags,
    from_visit_url,
    content=visits,
    content_rowid=id
);

-- Auto-sync triggers (INSERT, DELETE, UPDATE)
-- [same trigger pattern as current code, extended for new FTS columns]

-- Ingestion tracking
CREATE TABLE ingest_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_db   TEXT NOT NULL,
    browser     TEXT NOT NULL,
    os_platform TEXT NOT NULL DEFAULT '',
    row_count   INTEGER NOT NULL DEFAULT 0,
    ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### 6.2 FTS5 Configuration

Use the `unicode61` tokenizer with `remove_diacritics=2` for broad matching. Consider adding `porter` stemming as a secondary tokenizer if natural-language title search is important.

```sql
CREATE VIRTUAL TABLE visits_fts USING fts5(
    full_url,
    title,
    query_string_decoded,
    dns_host,
    tags,
    from_visit_url,
    content=visits,
    content_rowid=id,
    tokenize='unicode61 remove_diacritics 2'
);
```

---

## 7. Server (Flask REST API)

### 7.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Serve SPA |
| POST | `/api/ingest` | Accept archive path, run full pipeline (Stages 1-4) |
| POST | `/api/reingest` | Re-run Stages 3-4 only (reclassify without re-extracting) |
| POST | `/api/rebuild-fts` | Rebuild FTS5 index |
| GET | `/api/search` | Full-text search with filters and pagination |
| GET | `/api/visit/{id}` | Single visit detail with full metadata |
| GET | `/api/aggregate` | Dynamic aggregation endpoint (see 7.2) |
| GET | `/api/filters` | Return available filter values (browsers, users, platforms, tags, hosts) |

### 7.2 The Aggregate Endpoint (Progressive Dashboards)

Instead of pre-built dashboard endpoints, a single `/api/aggregate` endpoint accepts parameters that describe what to compute. The SPA requests aggregations on demand as the user navigates.

```
GET /api/aggregate?
    group_by=dns_host           # column to group by
    &metric=count               # "count" | "unique_urls" | "unique_users"
    &limit=20                   # top N
    &sort=desc                  # "asc" | "desc"
    &host=google.com            # optional filters (any indexed column)
    &browser=chrome
    &visit_source=synced
    &start=2024-01-01
    &end=2024-06-01
    &tag=token_in_params
```

Supported `group_by` values: `dns_host`, `browser`, `os_platform`, `os_username`, `browser_profile`, `endpoint_name`, `visit_source`, `transition_type`, `tags`, `time_hour`, `time_day`, `time_week`, `time_month`.

For `group_by=tags`, since tags is a JSON array, the query explodes the array using `json_each()`:

```sql
SELECT j.value AS tag, COUNT(*) AS count
FROM visits, json_each(visits.tags) AS j
WHERE ...filters...
GROUP BY j.value
ORDER BY count DESC
LIMIT ?
```

For time-based grouping, use `strftime()` with the appropriate pattern.

This single endpoint replaces the need for `/api/stats`, `/api/hosts`, `/api/timeline`, `/api/users` from the previous design. The SPA composes its views by making multiple aggregate calls as needed.

### 7.3 Search Endpoint Detail

```
GET /api/search?
    q=google+maps+restaurant    # FTS5 query (supports AND, OR, NOT, phrases, column: prefix)
    &host=www.google.com        # exact host filter
    &browser=chrome
    &visit_source=local         # "local" | "synced" | "extension" | "imported"
    &transition_type=typed
    &tag=cloud_storage          # filter to visits with this tag
    &os_platform=macos
    &os_username=alice
    &start=2024-01-01T00:00:00Z
    &end=2024-06-30T23:59:59Z
    &limit=50
    &offset=0
    &sort=time                  # "time" (chronological) | "rank" (BM25 relevance, default when q is present)
```

Response:

```json
{
    "total": 1432,
    "limit": 50,
    "offset": 0,
    "results": [
        {
            "id": 5821,
            "visit_time_utc": "2024-03-15T14:22:31Z",
            "full_url": "https://...",
            "title": "...",
            "dns_host": "...",
            "url_path": "...",
            "query_string_decoded": "...",
            "browser": "chrome",
            "browser_profile": "Default",
            "os_platform": "macos",
            "os_username": "alice",
            "endpoint_name": "ALICE-MBP",
            "visit_source": "local",
            "visit_source_confidence": "confirmed",
            "transition_type": "typed",
            "transition_qualifiers": "from_address_bar,chain_end",
            "from_visit_url": "",
            "visit_duration_ms": 45000,
            "tags": ["search_query"],
            "provenance_chain": "evidence.7z > Users/alice/Library/Application Support/Google/Chrome/Default/History",
            "source_db_path": "..."
        }
    ]
}
```

---

## 8. SPA Frontend

### 8.1 Design Philosophy

The interface is a forensic data workbench. It is not a dashboard application with pre-populated charts. Views are empty until the user asks a question or clicks into something. Every visual element is a response to a user action.

Aesthetic direction: dark forensic terminal. IBM Plex Mono for data, DM Sans for UI chrome. Dark background, high-contrast data, color-coded by meaning (amber for hosts, green for decoded params, blue for accent/interactive, red for flagged items).

### 8.2 Navigation

Three top-level views accessible via tabs:

1. **Search** (default, landing view)
2. **Explore** (progressive aggregation builder)
3. **Ingest** (archive import and pipeline status)

### 8.3 Search View

The primary interface. A single search input at the top, always focused on load.

**Search input**: FTS5 query syntax. Supports `AND`, `OR`, `NOT`, quoted phrases, column-scoped queries (`title:news`, `dns_host:google`, `tags:cloud_storage`). Display a small syntax hint below the input.

**Filter bar**: Below the search input. Dropdowns and inputs for: host, browser, platform, visit source (local/synced), transition type, tag, date range. All filters are populated lazily: when the user clicks a dropdown, it calls `/api/aggregate?group_by={column}&limit=50` to get available values. Not pre-fetched.

**Results table**: Columns: Time, Host, Title, URL, Visit Source (with icon: local pin vs. sync cloud), Browser badge, Tags (as small pills). Rows are clickable to expand.

**Expanded row detail**: Shows all fields for the visit. Includes the full provenance chain, decoded query string, transition type, referrer URL, visit duration, and all tags with brief explanations.

**Host drill-down**: Clicking a hostname in results or in any aggregation view sets it as a filter and re-runs the search. This is how users "zoom in" without a pre-built host detail page.

**Tag drill-down**: Clicking a tag pill filters to all visits with that tag.

**Pagination**: Offset-based. Show current range and total. Prev/Next buttons.

### 8.4 Explore View

Not a static dashboard. It is a tool for building aggregation queries visually.

The view starts nearly empty with a prompt: "Choose a dimension to explore."

**Dimension selector**: A row of clickable chips for each groupable column: Hosts, Browsers, Platforms, Users, Profiles, Endpoints, Visit Source, Transition Type, Tags, Timeline.

Clicking a dimension chip fires `/api/aggregate?group_by={dimension}` and renders the result as a horizontal bar chart below the chips. The same filter bar from the Search view is available here; changing any filter re-fires the aggregation.

**Timeline dimension**: Selecting "Timeline" shows interval toggle buttons (hour / day / week / month). Renders a bar chart (canvas-drawn) of visit counts over time. Clicking a bar in the timeline sets a date range filter, which updates both the timeline and any other active dimension chart.

**Stacking**: The user can select a second dimension to cross-tabulate. For example, selecting "Hosts" then "Visit Source" shows the top hosts broken down by local vs. synced. This fires two aggregate calls and overlays the results.

**Drill-through**: Clicking any bar in any chart applies it as a filter and switches to the Search view with that filter pre-applied. Example: clicking "github.com" in the Hosts chart switches to Search with `host=github.com`.

All charts animate in when data arrives (staggered reveal, bar growth from zero).

### 8.5 Ingest View

**Archive import**: Text input for the archive file path on the server's filesystem. "Ingest" button. Progress feedback during pipeline execution:

1. "Extracting archives..." (with count of nested levels found)
2. "Discovering databases..." (with count found)
3. "Ingesting visits..." (with count per database)
4. "Classifying..." (with progress count)
5. "Indexing..." (done)

Show a summary table of what was ingested: source path, browser, OS, profile, user, row count, status (new / skipped / error).

**Re-classify button**: Runs Stage 3+4 only. Useful after adding new classifier functions.

### 8.6 Visit Source Visual Treatment

Throughout the interface, visit source is indicated by a small icon or badge:

| Source | Icon | Color |
|---|---|---|
| Local | pin / monitor icon | Default text color |
| Synced | cloud / sync icon | Blue |
| Extension | puzzle piece icon | Purple |
| Imported | arrow-down icon | Gray |
| Unknown | question mark | Dim gray |

Where confidence is `likely` rather than `confirmed`, the icon is rendered at reduced opacity with a dashed border, and hovering shows "Likely synced (heuristic)".

---

## 9. Dependencies

| Package | Purpose |
|---|---|
| `flask` | HTTP server and REST API |
| `p7zip-full` | System package for recursive archive extraction (all formats, AES zip support) |
| Standard library | `sqlite3`, `json`, `pathlib`, `re`, `base64`, `urllib.parse`, `subprocess`, `tempfile`, `dataclasses`, `enum` |

Optional / future:

| Package | Purpose |
|---|---|
| `dfir-unfurl` | Deep URL parsing and protobuf decoding |
| `sqlite-vec` | Vector/semantic search extension |

No heavy frameworks. No JavaScript build step. The SPA is a single HTML file using React via CDN and Babel standalone.

---

## 10. File Structure

```
history_search/
    server.py               # Flask app, API endpoints, DB connection management
    pipeline/
        __init__.py
        extract.py          # Stage 1: recursive archive decompression
        ingest.py           # Stage 2: browser-specific SQLite extraction
        classify.py         # Stage 3: classifiers, URL decomposition, sync detection
        index.py            # Stage 4: FTS5 insertion, schema management
        models.py           # Dataclasses: ExtractedFile, SourceMetadata, VisitRecord
        enums.py            # Browser, BrowserEngine, TransitionType, VisitSource, etc.
        constants.py        # All magic numbers, patterns, classifier registry
    static/
        index.html          # SPA (React, single file)
```

---

## 11. Open Questions for Implementation

1. **Endpoint hostname recovery**: Some forensic acquisitions include hostname files (`/etc/hostname`, `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName`). Should the extractor look for these and populate `endpoint_name`, or is the archive filename sufficient?

2. **WAL-only databases**: If only a `-wal` file exists without the main DB, SQLite cannot open it directly. Should the pipeline attempt WAL reconstruction, or skip and log?

3. **Protobuf decoding depth**: Should we attempt raw protobuf wire-format decoding on all unrecognized base64 blobs, or only on known Google parameter names? The former catches more but produces false positives; the latter is conservative.

4. **Classifier extensibility**: Should classifiers be loadable from a YAML/JSON config file (for non-developer analysts to add patterns), or is Python-function-only sufficient?

5. **Multi-archive support**: Should the ingest endpoint accept multiple archive paths in one call, or is one-at-a-time sufficient?

---

*End of design document.*
