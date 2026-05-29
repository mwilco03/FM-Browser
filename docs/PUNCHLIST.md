# FM-Browser Punch List

Living triage doc. Source: three-agent code/architecture/forensic review (2026-05-04) plus user-reported bugs. Severity tags are **Blocker / High / Medium / Low**. Confidence tags are **Confirmed / Likely / Possible** per the user's epistemic discipline rules.

The "🔥 USER" prefix marks issues the user explicitly called out.

---

## Active work

| ID | Title | Status |
|----|-------|--------|
| F-01 | Rip out API token paste UX | **done** (2026-05-04) |
| F-02 | Fix archive password handling | **done** (2026-05-04) |
| F-03 | Overhaul search | **done** (2026-05-04) |
| F-04 | Fix Safari History.db parsing | **partial** — defensive hardening landed; needs sample DB to nail the user's specific failure |
| F-05 | Document Dockerfile state | **partial** — Dockerfile updated for new auth model; README still TODO |

### What changed in this hotfix sprint

- `history_search/server.py`: dropped `API_TOKEN`, `--no-auth`, `?token=` accept path, `secrets`, the `require_token` decorator. Added `require_local` (loopback gate + same-origin CSRF check) and `--allow-remote` flag. `BROWSE_ROOTS` now defaults to CWD instead of "everything." Refactored search/export to share `_build_search_sql`. Added `_smart_to_fts5`, `_like_escape`, `_safe_int`. Wrapped MATCH and `int()` in try/except returning 400.
- `history_search/static/index.html`: removed token paste panel, `getToken/setToken/authHeaders`. Added Passwords textarea on the Ingest panel. Added Extraction Failures table. Search defaults to Smart mode with an Advanced toggle exposing FTS5/Contains/Regex.
- `history_search/pipeline/extract.py`: every extractor now returns one of `ok|password|error|unsupported`. `extract_recursive` returns an `ExtractionResult` with `.failures` populated; `_resolve_passwords` merges user passwords with defaults; CLI extractors detect password failures via exit codes (`unzip` 81/82) and stderr keywords (`7z` `password`/`encrypted`/`data error`).
- `history_search/pipeline/constants.py`: `ARCHIVE_PASSWORDS` reordered so empty password is tried first. Added iOS Safari backup-path patterns to `MACOS_BROWSER_PATHS`.
- `history_search/pipeline/ingest.py`: `_probe_engine` now requires `history_visits` for `webkit`. `extract_webkit` no longer swallows errors, drops empty-URL rows, and fixes the dubious tombstone source-classification heuristic.
- `Dockerfile`: CMD now includes `--allow-remote --browse-root /evidence` to work with the new same-origin gate.

---

## 🔥 USER-REPORTED (top of queue)

### F-01 [Blocker]  Rip out API token paste UX
**Confidence**: Confirmed.
**Files**: `history_search/server.py:50-71,815-841`, `history_search/static/index.html:219-222,966,1013-1017`.
**Symptom**: Random token printed on stdout, user must copy-paste into a Security panel in the SPA, stored in `sessionStorage`. UX hostile. Token can also be passed via `?token=` query param which then leaks into Flask access logs.
**Fix**:
- Drop `API_TOKEN` global, `require_token` decorator, `--no-auth` flag, `?token=` accept path.
- Bind to `127.0.0.1` (already default) and trust loopback. CSRF defense via Origin/Referer same-origin check on all mutating endpoints.
- Add `--allow-remote` flag for non-loopback binds; print a loud warning + recommend reverse proxy with auth.
- SPA: delete the token input, the Security panel, and `authHeaders()`.

### F-02 [Blocker]  Password-protected archive extraction does not work
**Confidence**: Confirmed (no `--archive-password` flag; passwords are a hardcoded malware-analysis list `["infected", "dangerous", ""]` in `constants.py:5`).
**Files**: `history_search/pipeline/constants.py:5`, `history_search/pipeline/extract.py:213-309`, `history_search/server.py:813-823`.
**Symptom**: For any archive with a password not in the hardcoded list, every extractor silently fails. No error surfaces to the user; the SPA just shows "0 databases found."
**Fix**:
- Add `--archive-password` (repeatable) CLI flag.
- Add `passwords` field in `/api/ingest` POST body.
- Plumb passwords through `extract_recursive` -> `_extract_single` -> each `_try_extract_*`.
- Surface extraction failures with a clear reason: "archive is password-protected; supply --archive-password".
- Default password list becomes empty (or just `[""]`); malware-analysis defaults move behind an opt-in flag like `--malware-passwords`.

### F-03 [High]  Search is broken for normal queries
**Confidence**: Confirmed.
**Files**: `history_search/server.py:230-286,319-403`, `history_search/static/index.html:474-608`.
**Symptoms**:
- Default mode is FTS5 with raw user input passed to MATCH; any string with quotes, parentheses, colons, AND/OR/NOT keywords, or just `@` produces `sqlite3.OperationalError: fts5: syntax error` -> 500 response and empty UI.
- Three-mode toggle (FTS5/Contains/Regex) puts query-language complexity on the user.
- LIKE contains-mode does not escape `%` or `_` (silent wrong results).
- Tag filter `LIKE '%"tag"%'` breaks on tags containing `"` or `\`.
- `int()` on `?limit=` and `?offset=` is unguarded -> 500 on non-numeric input.
**Fix**:
- Single smart mode by default. Sanitizer:
  1. Strip/escape FTS5 metacharacters; tokenize on whitespace.
  2. Quote bare phrases; turn each token into `token*` for prefix match.
  3. Try FTS5 first. On `OperationalError`, fall back to LIKE with proper `%`/`_` escaping.
- Keep advanced mode behind a toggle that exposes raw FTS5 syntax.
- Wrap `int()` parsing in try/except returning 400.
- Wrap MATCH execution in try/except returning 400 with the parser error.

### F-04 [High]  Safari History.db parsing fails
**Confidence**: Possible (specific failure mode not yet characterized; user reported "fails to parse properly").
**Files**: `history_search/pipeline/ingest.py:395-466`, `history_search/pipeline/constants.py:62`.
**Hypotheses worth testing first**:
- iOS backup paths (MD5-hashed filenames) are not matched by `MACOS_BROWSER_PATHS` -> `endpoint_name` and `os_username` come back empty -> the file is silently skipped or mis-classified.
- iCloud-synced visits with `history_tombstones` present get `source = "unknown"` (`ingest.py:440-442`); the polarity of that branch is debatable.
- Safari 17+ schema variants (added/removed columns) — `_has_column` shields the basics but a missing `history_visits` table (with present `history_items`) passes the `webkit` schema probe (probes only `history_items`) and then the SELECT throws and is swallowed by the broad `except sqlite3.Error`.
- `history_items.url` can be NULL for some entries (synthesized history); query forces `or ""` which produces empty-URL records that should be dropped, not stored.
**Fix sequence**:
1. Have user attach a sample (or schema dump) of the failing Safari DB so we can see which specific failure path it hits.
2. In the meantime, harden the ingest path: probe BOTH `history_items` AND `history_visits` for the webkit engine, log the actual sqlite error instead of swallowing it, drop empty-URL records.

### F-05 [Medium]  Dockerfile state not obvious to user
**Confidence**: Confirmed (Dockerfile exists at repo root, 19 lines).
**Files**: `Dockerfile`.
**Issue**: User wasn't sure whether a Dockerfile existed. There's no `docs/DEPLOY.md`, no README mention of Docker is prominent, and the Dockerfile binds to `0.0.0.0` with no `--browse-root`, exposing the entire container filesystem to anyone who reaches the port.
**Fix**:
- Document Docker usage in README.
- Change Docker `CMD` to require `--browse-root /evidence` (the existing `VOLUME`).
- Once F-01 lands, ensure Docker default still works behind a reverse proxy.

---

## Blockers from review

### B-1 [Blocker]  `source_db_path` field set to profile string instead of path
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/ingest.py:266,352,449`, `history_search/server.py:144,691,721`.
**Symptom**: Every extractor sets `source_db_path = str(meta.browser_profile)` (e.g. `"Default"`). `ingest_log.source_db` is set separately to the real path. The two columns disagree, so:
- `/api/sources` `live_rows` join always returns 0.
- `/api/sources/delete` removes the `ingest_log` row but leaves visits orphaned (silent forensic data orphaning).
- E2E tests (`test_e2e_server.py`) seed the DB via raw SQL using matched values, masking the bug.
**Fix**: Force `insert_visits` to overwrite each record's `source_db_path` from its `source_db=` keyword arg; remove the field assignment from extractors. Add a regression test that ingests a real archive and asserts `live_rows > 0` for `/api/sources`.

### B-2 [Blocker]  Tar extraction admits absolute paths -> write-anywhere
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/extract.py:143-145`.
**Mechanism**: `_is_path_safe` checks `".." not in Path(member_name).parts`, but `Path("/etc/passwd").parts == ('/', 'etc', 'passwd')` passes that check. `tarfile.extractall` then writes to the absolute path.
**Fix**: Reject `Path(name).is_absolute()` and `".." not in parts`. Pass `filter='data'` to `extractall` on Python 3.12+.

### B-3 [Blocker]  No source-archive hash; no tool/classifier version stamp
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/index.py:93-103` (schema), `history_search/server.py:run_pipeline`.
**Symptom**: Forensic admissibility hole. There is no SHA-256 of the source archive recorded with the ingest, and no record of which classifier version produced the tags. A defense expert asking "what was the SHA-256 of the archive you loaded?" or "which classifier version produced this tag?" cannot be answered from the database.
**Fix**: Add columns `source_hash`, `source_hash_algorithm`, `tool_version`, `classifier_version`, `source_size_bytes`, `source_original_path` to `ingest_log`. Compute SHA-256 of archive and each evidence SQLite. Stamp tool version from `pyproject.toml` and a fingerprint of the classifier registry.

### B-4 [Blocker]  No audit log for destructive operations
**Confidence**: Confirmed.
**Files**: `history_search/server.py:738-805`.
**Symptom**: `/api/clear`, `/api/sources/delete`, `/api/reingest`, `/api/rebuild-fts` are silent. `ingest_log` is itself DELETEd by clear and delete-source, destroying provenance.
**Fix**: Append-only `action_log(id, action_type, actor, timestamp_utc, target, before_count, after_count, payload_json)` written before every destructive op. Soft-delete `ingest_log` rows (status='deleted') instead of DELETE.

### B-5 [Blocker]  `/api/browse` defaults to unrestricted filesystem traversal
**Confidence**: Confirmed.
**Files**: `history_search/server.py:74-80,843-847`.
**Mechanism**: When `BROWSE_ROOTS` is empty, `_is_within_browse_roots` returns True for every path. The Dockerfile does not set `--browse-root` and binds to `0.0.0.0`.
**Fix**: Default-deny when no root set. Make `--browse-root` mandatory or default to CWD.

### B-6 [Blocker]  Flask `debug=args.verbose` enables Werkzeug RCE debugger
**Confidence**: Confirmed.
**Files**: `history_search/server.py:873`.
**Mechanism**: `app.run(..., debug=args.verbose)` couples log verbosity with the interactive debugger; analyst running `--verbose` accidentally exposes RCE.
**Fix**: Decouple logging from `debug=`. Set `debug=False` unconditionally.

### B-7 [Blocker]  Sync ingest on Flask request thread + no WAL
**Confidence**: Confirmed (no `PRAGMA journal_mode=WAL` anywhere).
**Files**: `history_search/server.py:765-769`, `history_search/pipeline/index.py:init_schema`.
**Symptom**: Ingests block all reads; concurrent requests get `database is locked`. Browser hangs for the duration with no progress feedback.
**Fix**:
- Enable WAL: `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL` in `init_schema`.
- Move ingest off the request thread: in-process `concurrent.futures` worker + `jobs(id, status, progress, started_at, finished_at, payload)` table. Return `202 Accepted` from `/api/ingest` with a job ID, expose `/api/ingest/stream/<id>` (SSE) for progress.

### B-8 [Blocker]  Unhandled exceptions return 500 to clients
**Confidence**: Confirmed.
**Files**: `history_search/server.py:333-334,380-382,469,513,582`.
**Mechanisms**:
- `int(request.args.get("limit"))` raises `ValueError` on non-numeric input.
- FTS5 `MATCH` raises `sqlite3.OperationalError` on syntactically invalid queries.
**Fix**: Try/except around both, returning 400 with a JSON error.

### B-9 [Blocker]  `raw_transition`, `raw_from_visit`, `raw_visit_id` are not persisted
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/index.py:106-114` (no columns / not in `INSERT_VISIT_SQL`), `history_search/pipeline/models.py` (fields exist on `VisitRecord` but not in DB).
**Forensic impact**: The raw Chrome transition bitmask is the primary evidence for "was this URL typed vs followed from a link". Dropping it after classification means the decoded string is the only record and cannot be independently verified.
**Fix**: Add the three columns to the schema and insert path. Include in CSV export.

---

## High-priority correctness/security

### H-1  Rebuild-FTS fired on every destructive op, even though triggers maintain it
**Confidence**: Confirmed. **Files**: `history_search/server.py:728,743-744,766-767,795-796`.
Triggers (`trg_visits_ai/ad/au` in `index.py`) already keep FTS in sync. Calling `rebuild_fts()` after every clear/delete/reingest is O(N) wasted work and not transactional with the preceding deletes.
**Fix**: Drop the rebuild calls; keep `/api/rebuild-fts` as a manual escape hatch.

### H-2  `api_reingest` reaches across stage boundaries with a fragmentary VisitRecord
**Confidence**: Confirmed. **Files**: `history_search/server.py:773-797`.
Rebuilds a `VisitRecord(full_url=..., title=...)` from three columns then runs classifiers; bypasses the canonical model. No version stamp recorded.
**Fix**: Move into `history_search/orchestrate.py` as `reclassify_in_place(db_path)`; record an action_log row with classifier version.

### H-3  `tags` filtered by `LIKE '%"tag"%'`
**Confidence**: Confirmed. **Files**: `history_search/server.py:265-266`, `pipeline/index.py:tags column`.
JSON-in-TEXT filtered with substring LIKE breaks on tags containing `"` or `\`, can match adjacent fields, and isn't indexable.
**Fix**: Migrate to a `visit_tags(visit_id, tag)` join table with a `(tag, visit_id)` covering index.

### H-4  LIKE search does not escape `%` or `_` wildcards
**Confidence**: Confirmed. **Files**: `history_search/server.py:250`. (Search for `foo%bar` matches `foofizzbar` instead of literal text.)
**Fix**: Escape and add `ESCAPE '\\'` to the LIKE clauses.

### H-5  CDN-loaded React + Babel with no SRI
**Confidence**: Confirmed. **Files**: `history_search/static/index.html:7-10`.
External JS executes in the analyst's session with no integrity check. CDN compromise -> code injection. Air-gapped IR networks fail entirely.
**Fix**: Vendor the JS into `history_search/static/vendor/`, or add SRI hashes.

### H-6  WAL file read into memory without size limit
**Confidence**: Confirmed. **Files**: `history_search/pipeline/carve.py:67`.
`wal_path.read_bytes()` has no size check; only the main DB has the 512 MB cap. Large WAL OOMs the process.
**Fix**: Apply the same cap.

### H-7  `MAX_EXTRACTION_RATIO` defined but unused (zip-bomb gap)
**Confidence**: Confirmed. **Files**: `history_search/pipeline/constants.py:8`, `history_search/pipeline/extract.py:29`.
Constant imported but never compared against actual extraction ratio. Bomb that fits under absolute size limit passes.
**Fix**: Either implement the ratio check or remove the unused import.

### H-8  Legacy root `server.py` and `fm-browser.html` still in repo
**Confidence**: Confirmed. **Files**: `server.py`, `fm-browser.html`.
Not packaged, not imported, but fully runnable Flask servers with their own duplicate enums and weaker extraction logic. Anyone who runs `python server.py` instead of `python -m history_search.server` gets a server with no path-traversal check and no auth.
**Fix**: Delete both. Tag the prior commit `legacy-monolith` for reference.

### H-9  No request access log
**Confidence**: Confirmed. **Files**: nowhere — there is no `before_request`/`after_request` log handler.
**Forensic impact**: Cannot answer "who searched for what when" or "who triggered the clear."
**Fix**: Structured `after_request` handler logging method, path, redacted query, source IP, status, response time.

### H-10  Token (when present) accepted via `?token=` query param
**Confidence**: Confirmed. **Files**: `history_search/server.py:67`.
Even if F-01 weren't already replacing this entire mechanism, the query-param accept path leaks the token into Flask access logs. Will be removed wholesale by F-01.

### H-11  Ingest dedup key is the ephemeral tmp path
**Confidence**: Confirmed. **Files**: `history_search/server.py:113,115`.
`is_already_ingested(index_db, str(db_path))` keys on a path inside `tempfile.mkdtemp(prefix="hist_")`, which differs every run. Re-running ingest on the same archive always re-ingests.
**Fix**: Key on `(provenance_chain, sha256(db_bytes))`.

### H-12  `ingest_log.ingested_at` not timezone-tagged
**Confidence**: Confirmed. **Files**: `history_search/pipeline/index.py:102`.
`DEFAULT (datetime('now'))` returns a string without "Z" or offset.
**Fix**: Set from Python via `datetime.now(timezone.utc).isoformat()`, or change default to `datetime('now') || 'Z'`.

---

## Medium-priority maintainability

### M-1  Duplicate epoch constants in `carve.py`
**Confidence**: Confirmed. **Files**: `history_search/pipeline/carve.py:41-45` vs `pipeline/constants.py:13-15`.
Three constants (`_CHROME_EPOCH_OFFSET`, `_WEBKIT_EPOCH_OFFSET`, `_TICK_DIVISOR`) redefined locally instead of imported. Drift risk.

### M-2  `run_pipeline` lives in `server.py`
**Confidence**: Confirmed. **Files**: `history_search/server.py:87-188`.
Pipeline orchestration belongs in `history_search/pipeline/orchestrate.py` (or `history_search/orchestrate.py`), called from both CLI and HTTP handlers.

### M-3  `api_aggregate` is a god endpoint
**Confidence**: Confirmed. **Files**: `history_search/server.py:~580` (78 lines branching on `group_by`).
Mixes 3 query shapes (column / time bucket / tag). Split or use a strategy table.

### M-4  Search/Export duplicate the WHERE/ORDER builder (~40 lines)
**Confidence**: Confirmed. **Files**: `history_search/server.py:319-403,469-...`. Drift risk.
**Fix**: Extract `build_search_query(filters, q, mode, sort) -> (sql, params)`.

### M-5  `SORT_MAP` defined twice (search and export)
**Confidence**: Confirmed. **Files**: `history_search/server.py:351-361,428-438`.
Module-level constant.

### M-6  No index on `visits.source_db_path` or `ingest_log.source_db`
**Confidence**: Confirmed. **Files**: `history_search/pipeline/index.py:57-65`.
Source delete and ingest dedup do full-table scans.

### M-7  `api_browse` ingestable detection uses extension; pipeline uses magic bytes
**Confidence**: Confirmed. **Files**: `history_search/server.py:663-666`.
File picker disagrees with the extractor about what's ingestable.

### M-8  Stage-5 carving has a hardcoded special case
**Confidence**: Confirmed. **Files**: `history_search/server.py:158`.
`if engine not in ("teams_json",)`. Promote carving to a documented Stage 5 with a per-adapter `supports_carving()` flag.

### M-9  `test_e2e_server.py` not pytest-discoverable
**Confidence**: Confirmed. **Files**: `tests/test_e2e_server.py`.
No `TestCase` subclasses, no `test_` prefixed functions. CI sees zero tests from this file.

### M-10  No `--case-id` / `--examiner` CLI args; no metadata in `ingest_log`
**Confidence**: Confirmed.
**Forensic impact**: After a case is closed, no record of who/what/when an ingest was performed.

### M-11  Browser extensibility requires editing 6 places across 3 files
**Confidence**: Confirmed. **Files**: `enums.py`, `constants.py`, `ingest.py`.
**Fix**: `BrowserAdapter` protocol with `discover()/detect_metadata()/extract()/supports_carving()`.

---

## Low-priority

### L-1  CSV export filename always `export.csv`, no metadata header
**Confidence**: Confirmed. **Files**: `history_search/server.py:484`.
**Fix**: Timestamped filename + first-row metadata block (tool, version, export time, query parameters).

### L-2  Carve timestamp confidence not labeled
**Confidence**: Confirmed. **Files**: `history_search/pipeline/carve.py:235-263`.
512-byte-window heuristic produces "likely" timestamps; should be `"possible"` for carved entries.

### L-3  `_is_path_safe` for 7z uses substring `".."` -> false positives
**Confidence**: Confirmed. **Files**: `history_search/pipeline/extract.py:174-186`.
Filename like `"version..2.txt"` flags as traversal.

### L-4  `unfurl` JSON column is in FTS5 index
**Confidence**: Confirmed. **Files**: `history_search/pipeline/index.py:16`.
FTS tokenizes JSON punctuation; matches happen by accident.

### L-5  Regex search mode unbounded
**Confidence**: Confirmed. **Files**: `history_search/server.py:_regexp,243`.
ReDoS surface; no complexity check or watchdog.

### L-6  Unfurl-derived tags bypass `@classifier` registry
**Confidence**: Confirmed. **Files**: `history_search/pipeline/classify.py:classify_visit`.
`has_geo_coords`/`has_embedded_url`/etc. tags added inline. Move into the registry for consistency.

### L-7  Username extractor falls back silently for service accounts
**Confidence**: Confirmed. **Files**: `history_search/pipeline/ingest.py:_extract_username_fallback`.
Skips `default/public` only; `WDAGUtilityAccount` and similar Windows service accounts pass through silently.

### L-8  Classifier registry uses module-global mutable list
**Confidence**: Likely. **Files**: `history_search/pipeline/classify.py:_CLASSIFIER_REGISTRY`.
Re-import path could double-register. Guard with name uniqueness.

### L-9  README claims "15 forensic classifiers" but registry has 16
Cosmetic.

---

## Test coverage gaps

- No test for path-traversal rejection in any archive format.
- No test that verifies `source_db_path` value in the `visits` table after a real ingest.
- No test for `api_reingest` preserving original visit metadata.
- No test for FTS5 error handling on malformed queries.
- No test for `carve_deleted_records` or any WAL/freelist parsing path.
- No test for LIKE-metacharacter escaping.
- No test for password-protected archive extraction with a custom password.
- No test for Safari iOS-backup path recognition.

---

## Sequencing proposal

**Hotfix sprint** (start now): F-01, F-02, F-03, F-04, B-2, B-6, B-8, H-8.
**Forensic-soundness sprint** (week 2): B-3, B-4, B-5, B-9, H-9, H-12, M-10, L-1.
**Architecture sprint** (week 3): B-1, B-7, H-1, H-2, M-2, M-4, M-8, M-11.
**Data-architecture sprint** (week 4): H-3, H-6, H-7, H-11, M-1, M-3, M-5, M-6, M-7.
