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

**Standing decision (2026-06-20, user — restated emphatically):** the API-token model is **permanently rejected**; the user considers the entire token workflow idiotic. Do NOT reintroduce token/bearer auth in any form, in code, tests, docs, or review suggestions. The model is loopback + same-origin CSRF (`require_local`), with a reverse proxy for remote auth. Any lingering token reference is rot to delete — e.g. `tests/test_e2e_server.py` still reads `srv.API_TOKEN` (which no longer exists) and breaks the suite; fix by removing it, not by restoring the token.

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
**Status: FIXED 2026-06-20 (see UA-1).** Regression test added: `tests/test_index.py::TestIndex::test_source_db_path_matches_ingest_log_for_sources_join` asserts `insert_visits` overwrites `source_db_path`, the `/api/sources` join yields `live_rows > 0`, and delete-by-source removes the rows. Also exercised end-to-end against the real acquisition in CT 228 (see Round-trip log).

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

---

## Usability & Analysis review (2026-06-20)

Source: a second full pass re-framed around the **analyst's investigative workflow** — can someone load an acquisition and answer forensic questions, and can they trust and navigate what the tool tells them? Security/passwords explicitly out of scope for this pass (tracked above). Severity = analyst impact. Confidence per epistemic-discipline rules.

### UA-1 [Blocker]  Source Manager reports 0 live rows and "delete" orphans every browser visit
**Confidence**: Confirmed (read + empirically reproduced, see Round-trip log).
**Files**: `history_search/pipeline/ingest.py:298,387,510` (all three browser extractors set `source_db_path=str(meta.browser_profile)`, e.g. `"Default"`), `history_search/pipeline/index.py:158` (`ingest_log.source_db` = real path), `history_search/server.py:839` (`LEFT JOIN visits v ON v.source_db_path = il.source_db`), `:869` (`DELETE FROM visits WHERE source_db_path = ?`).
**Symptom**: profile-string never equals the real path, so `/api/sources` `live_rows` is always 0 for Chromium/Gecko/WebKit sources and "Remove source" deletes the `ingest_log` row while leaving every visit orphaned. Carve/Teams rows set the path correctly (`carve.py`, `ingest.py:624`), so the inventory is inconsistent on top of being wrong. This is the same root cause as **B-1** and is still live.
**Fix**: have `insert_visits` overwrite each record's `source_db_path` from its `source_db=` kwarg (single home), and drop the field assignment from the extractors. Validated below.
**Status: FIXED 2026-06-20.** `insert_visits` (`index.py`) now overwrites `source_db_path` from `source_db`; the three `str(meta.browser_profile)` assignments were removed from `extract_chromium`/`extract_gecko`/`extract_webkit`. This also fixes carved sources (whose `ingest_log.source_db` is `<path> [carved]`) and the Gecko fallback path (which omitted the field). Re-verified through the real pipeline + live endpoints in CT 228: `/api/sources` → `live_rows: 4`, `/api/sources/delete` → removed 4, 0 orphaned; suite 7/7 green.

### UA-2 [High]  Ingest gives the analyst no progress — during the one operation that takes minutes-to-hours
**Confidence**: Confirmed.
**Files**: `history_search/server.py:136-219` (`run_pipeline` is fully instrumented with `on_progress(...)` messages), `:922` (`/api/ingest` calls `run_pipeline` with **no** `on_progress` and synchronously in the request thread).
**Symptom**: the progress messages exist and are emitted into a callback that is never supplied, so the IngestView "live log" stays empty and the analyst can't tell working from hung.
**Fix**: move ingest off the request thread (job + SSE/poll) and pass an `on_progress` that streams to the UI.

### UA-3 [High]  Timeline silently drops out-of-range timestamps
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/ingest.py:167,170-171,180,193` (hardcoded year-2100 ceiling `4102444800` and swallowed `datetime` errors → `""`, no log).
**Forensic impact**: clock-skewed/tampered times — themselves leads — vanish from the timeline with no flag. The analyst sees a clean timeline with invisible holes.
**Fix**: preserve and **flag** out-of-range/unparseable timestamps (e.g. `time_anomaly` tag + keep raw); never silently null.

### UA-4 [High]  WAL-resident recent visits are mislabeled "recovered_deleted"
**Confidence**: Confirmed (mechanism); Likely (frequency depends on browser WAL state).
**Files**: `history_search/pipeline/ingest.py:703` (`immutable=1` makes Stage 2 ignore the WAL), `history_search/pipeline/carve.py:54-95` + `history_search/server.py:227` (carve scrapes the WAL and tags rows `recovered_deleted`).
**Forensic impact**: the newest, live, never-deleted browsing can surface flagged as deleted → an analyst could wrongly conclude/testify "the user deleted this."
**Fix**: merge committed WAL frames into Stage-2 visits; reserve `recovered_deleted` for freelist/slack carving, or label WAL-origin rows distinctly with explicit confidence.
**Status: FIXED 2026-06-21.** `ingest_database` (`ingest.py`) now detects a non-empty `-wal` sidecar and extracts with it applied via `_ingest_wal_applied`: it copies `db` + `-wal` + `-shm` to a temp dir, opens the COPY normally so SQLite replays/checkpoints the WAL, and extracts — the original evidence + sidecars stay byte-for-byte intact. Committed-but-uncheckpointed visits are now LIVE; the carver's active-URL filter then keeps them out of `recovered_deleted`. Proven with a synthetic uncheckpointed WAL: `immutable=1` saw 1 URL, `ingest_database` saw both (the WAL-resident visit recovered as live). The real `mack.wilcox` acquisition carries no uncheckpointed WAL data, so its counts are unchanged. Suite 7/7.

### UA-5 [High]  Carve active-URL filter over-suppresses genuinely deleted URLs
**Confidence**: Confirmed (logic); Possible (real-world rate).
**Files**: `history_search/pipeline/carve.py:386` (bidirectional `prefix.startswith(ap) or ap.startswith(prefix)`).
**Forensic impact**: a single live `host/` prefix can erase every carved URL under that host → false "nothing was deleted." Worst kind of forensic error (absence inferred from a filter artifact).
**Fix**: exact-match (or full host+path) the active-URL filter; never prefix-suppress.

### UA-6 [Medium]  Transition vocabulary is an uncontrolled union — "intent" can't be cleanly filtered
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/constants.py:22-25,51-55` (Chrome emits `auto_bookmark`/`keyword_generated`, Firefox emits `embed`/`framed_link`), `enums.py:59-72` (`TransitionType` says `bookmark`/`embedded`/`link` and is imported by nobody), `index.py:45` (raw value stored).
**Forensic impact**: the transition filter shows `embed` AND `embedded`, `auto_bookmark` AND `bookmark` as distinct; "show everything they typed" is not a clean query. Also see **B-9** (raw bitmask not persisted → the decoded label is unverifiable).
**Fix**: normalize all three browser vocabularies onto `TransitionType` at ingest; persist the raw bitmask alongside.

### UA-7 [Medium]  No single-visit detail view; navigation chains can't be walked
**Confidence**: Confirmed.
**Files**: `history_search/static/index.html:225` (`api.visit` defined, never called), `:685` (`from_visit_url` rendered as plain text, not a pivot), `history_search/server.py:629-645` (`/api/visit/{id}` exists but unused by the UI).
**Forensic impact**: `from_visit` is resolved to `from_visit_url` (`ingest.py:217-235`) so the referrer graph exists, but the analyst can't click a visit to see its referrer or walk forward to its children — the edges are shown, traversal is impossible. For an investigation about navigation paths this is a core gap.
**Fix**: build a visit-detail view; make referrer/`from_visit_url` a clickable pivot both directions.

### UA-8 [Medium]  Frontend swallows backend failures — empty is indistinguishable from broken
**Confidence**: Confirmed.
**Files**: `history_search/static/index.html:224-235` (no `response.ok` check; every call is `fetch().then(r=>r.json())`), `:500,792,903` (silent `.catch(()=>{})`), `:532` (search failure only `console.error`s and leaves stale `allRows` on screen).
**Forensic impact**: a server error renders as an empty chart/table; on search failure the analyst may draw conclusions from stale results believing they're current.
**Fix**: check `response.ok`, surface a visible error state, clear stale results on failure.
**Status: FIXED + browser-validated 2026-06-21.** `doSearch` now checks `resp.ok`, handles non-JSON/5xx and network failure distinctly, clears stale rows, and sets a visible `searchError`; the empty state renders **"Search failed: <reason>"** (red) instead of "No results" when an error is set. Proven in real Chromium (shutter) via route-interception: normal search 50 rows; simulated 500 → shows the error, does NOT say "No results", clears rows; recovers to 50 after. Zero pageerrors. This is the exact defect that made a down server look like "0 dropbox results."

---

## UX polish wave (2026-06-21, all browser-validated in real Chromium via the `browser-check` skill, zero pageerrors)

- **UA-8 extended to all views.** Added an `okJson` wrapper so every `api.*` call rejects on non-2xx (preserving the JSON `{error}` message); `SearchView`, `SourceManager`, and `ExploreView` now surface a visible error instead of `.catch(()=>{})` blanking. Validated by route-injecting a 500.
- **Confidence + exclude-carved filters (SearchView).** Wired the `min_confidence` and `exclude_source` API params into UI controls. Validated: `dropbox` 3 results → **2** with "Exclude carved" (drops the carved `dropbox.comn`).
- **UA-11 heatmap timezone UI.** Added a TZ-offset picker in Explore driving `/api/heatmap?tz_offset=`; heatmap re-renders in local time. Validated: switched to UTC-5, activity shifted to a realistic Mon–Fri business-hours band, no midnight phantom spike.
- **UA-25 first/last-seen in Explore.** `/api/aggregate` already returned them; `BarChart` now shows `first seen / last seen` per item on hover. Validated (30 host bars, tooltip present). *Remaining:* a rare-first (`sort=asc`) toggle in the UI (API already supports it).
- **B-3 chain-of-custody in Source Manager.** `/api/sources` now returns `source_sha256` / `source_size_bytes` / `tool_version` / `classifier_version`, and the Source list renders `sha256…/tool/clf` per source. Validated.

### Navigation + modal + polish (2026-06-21, browser-validated via shutter)
- **Navigation (prioritized).** The visit detail now walks the chain: **"← from &lt;referrer&gt;"** finds the referring visit (contains-search, backward) and **"→ pages opened from here"** filters by a new `from_visit_url` API param (forward). Validated: forward filter returns the referred page (total=1 for the sample referrer); both links render; an `opened-from:` filter chip shows; zero pageerrors.
- **Modal Esc + focus-trap** on the FilePicker (Esc closes, Tab cycles within, focus restored on close). Validated: opens, Esc closes.
- **Rare-first toggle** in Explore (least-frequency stacking): top flips **1,133 → 1**. Validated.
- **Favicon** added (`data:,`) — kills the `/favicon.ico` 404 seen in the logs.
- **Keyboard row-expand a11y: skipped per user.** **aria-labels: not added** — Playwright locates everything by text/title/role, so they weren't needed (per "aria only if it helps automation").

- **Multi-tag boolean filtering — DONE (browser-validated).** Migrated the single `tag` to a `tags[]` array + `tags_mode` (and/or); backend `_build_where` joins per-tag `LIKE` clauses with AND/OR. Clicking a tag pill adds it; chips are individually removable; a **match-ALL/ANY** toggle appears with 2+ tags. Validated: API `cloud_storage`=4, `AND`=1, `OR`=359 (AND ≤ single ≤ OR); UI toggle flips results 1 ↔ 3 under a dropbox query; zero pageerrors.

- **Copy-row buttons — DONE.** Detail view has **URL / Row (TSV) / JSON** copy buttons via a `copyText` helper that uses `navigator.clipboard` on secure origins and falls back to a hidden-textarea `execCommand('copy')` on http. Validated: buttons render + click with zero pageerrors (clipboard read-back not verifiable over plain http — the exact reason the fallback exists).

- **SRI-pinned the CDN scripts (H-5, partial) — DONE.** Added `integrity="sha384-…" crossorigin="anonymous" referrerpolicy="no-referrer"` to the React / ReactDOM / Babel `<script>` tags (hashes computed from the actual cdnjs files). A tampered CDN file will now be refused by the browser. Validated: app still renders with the pins, zero pageerrors. (Google Fonts left unpinned — stylesheet content varies, SRI breaks it.)

**Still open (deferred, real efforts not polish):** case-id/examiner/per-visit notes (needs a backend table + endpoints + UI); kill in-browser Babel + vendor the JS locally (the remaining half of H-5 — fixes air-gap + perf, but introduces a build step that conflicts with the single-file no-build design → product decision).

### UA-9 [Medium]  Re-classify can't repair attribution; rebuilds the record from two fields
**Confidence**: Confirmed.
**Files**: `history_search/server.py:938-951` (rebuilds `VisitRecord(full_url, title)` and rewrites only `dns_host/url_path/query_string_decoded/tags/unfurl`; `decompose_url` imported but unused).
**Forensic impact**: transition, source, confidence, referrer, and time are untouched, so a mis-attribution can't be fixed without a full re-ingest (which needs the original evidence remounted).
**Fix**: re-classify from the full stored record; or add a `reclassify_in_place` that can re-derive attribution where source data is retained.

### UA-10 [Medium]  Forensic tags are noisy — triage chases false positives
**Confidence**: Confirmed.
**Files**: `classify.py:606-617` (`b64_payload` fires on any 44-char base64-ish string), `:721` (`ip_address_host` accepts `999.999.999.999`), `constants.py:156-159` + `classify.py:667` (`download_url` matches `.sh`/`.exe` anywhere incl. query strings), `:215,254,261` (`"google" in host` substring over-match), `server.py:394` (tag filter `LIKE '%"tag"%'` over-matches).
**Fix**: validate IP octets, anchor extension match to the path tail, use eTLD+1 equality for provider checks, move tags to a `visit_tags` join table.

### UA-11 [Medium]  UTC-only — device local timezone never captured
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/ingest.py:161-197`.
**Forensic impact**: most timeline arguments are "active at 2am *local*"; the device TZ is derivable from the acquisition and simply never recorded, forcing off-tool TZ math every time.
**Fix**: capture/store device timezone (or offset) and display local + UTC.

### UA-12 [Low]  CSV export is undocumentable and self-overwriting
**Confidence**: Confirmed. **Files**: `history_search/server.py:571-626` (fixed filename `export.csv`, no metadata header).
**Fix**: timestamped filename + header block recording tool/version, query, filters, export time.

### UA-13 [Low]  No case context — can't build or annotate a case in-tool
**Confidence**: Confirmed (absence). No case-id/examiner fields, notes, bookmarking, "mark relevant," or saved queries anywhere.
**Fix**: case metadata at ingest; per-visit analyst notes/flags; saved searches.

### UA-14 [Low]  Two timestamp formats coexist in the DB
**Confidence**: Confirmed. **Files**: `classify.py:278,542` emit `"%Y-%m-%d %H:%M:%S UTC"` vs ISO-8601 `…Z` everywhere else; unfurled timestamps won't sort/compare with visit times.

### UA-15 [Low]  Accessibility + large-evidence performance
**Confidence**: Confirmed. **Files**: `index.html:672` (mouse-only row expansion, no keyboard/role), `:409` (modal has no Esc/focus trap), `:9,210` (in-browser Babel), `:1133-1135` (all three views stay mounted → big DOM + running observers on large result sets).

### UA-16 [Medium]  Path-derived identity gaps misattribute "who" and "which browser"
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/ingest.py:94,108` (only macOS + Windows path patterns; no `LINUX_BROWSER_PATHS`), `:119-125` (engine→browser fallback collapses all Chromium browsers to `"chrome"`).
**Forensic impact**: Linux acquisitions yield empty `os_username`; Edge/Brave/Vivaldi/Arc/Opera get mislabeled `chrome` whenever the path doesn't match a known pattern.
**Fix**: add Linux path patterns; carry the detected browser from the path/engine instead of defaulting to `chrome`.

### UA-17 [Blocker]  Chrome sync attribution is INVERTED — synced visits reported as "local, confirmed"
**Confidence**: Confirmed (tool behavior reproduced in CT 228, see Round-trip log); Chromium enum semantics per documented `VisitSource` (Likely — from known Chromium `components/history/core/browser/history_types.h`).
**Files**: `history_search/pipeline/constants.py:42-48` (`CHROME_VISIT_SOURCE`), `history_search/pipeline/ingest.py:267` (`COALESCE(visit_source.source, 0)`), `:288,309`.
**Mechanism** — two compounding bugs:
1. **Inverted value map.** The tool maps `0:"local", 1:"synced"` (constants.py:43-44). Chromium's enum is the opposite: `SOURCE_SYNCED=0, SOURCE_BROWSED=1, SOURCE_EXTENSION=2, SOURCE_FIREFOX_IMPORTED=3, SOURCE_IE_IMPORTED=4, SOURCE_SAFARI_IMPORTED=5`. The map is also internally incoherent — the comment at `:47` labels value `4` as "BROWSED (newer Chrome)" while value `1` is already called "synced", so no single visit can be consistently classified.
2. **NULL/0 collision.** Chrome writes a `visit_source` row only for non-browsed visits; plain local browsing has **no row**. `COALESCE(visit_source.source, 0)` (ingest.py:267) folds "no row" (local) and an explicit `source=0` (SYNCED) into the same `0`, so even a corrected value map can't separate them — local-browse must be detected as a **NULL/missing row**, not as `0`.
**Forensic impact**: this is the single most dangerous error for sync analysis. A URL synced from another device (the user may never have visited it on the examined machine) is reported as `visit_source="local"`, `confidence="confirmed"`. An examiner would place activity on the device that never happened there — and the tool is *most* confident exactly where it is wrong. Reproduced: src=0 (synced) → `local/confirmed`; src=1 (local) → `synced/confirmed`.
**Fix**: (a) correct `CHROME_VISIT_SOURCE` to Chromium semantics (`0:synced, 1:local, 2:extension, 3/4/5:imported`); (b) stop `COALESCE`-ing to 0 — treat a missing `visit_source` row (NULL) as `local`, and an explicit `0` as `synced`; (c) only claim `confidence="confirmed"` for rows backed by an explicit `visit_source` entry, not for the NULL-default local case.
**Related**: Gecko sync is a weak heuristic (`frecency < 0` → `synced/likely`, `ingest.py:378-380`) and Safari uses the `origin` column + tombstones (`ingest.py:501-506`) — both `"likely"`, neither verified against real synced profiles. Add tests with real synced Chrome/Firefox/Safari profiles. **Verified 2026-06-20 — see UA-18.**

### UA-18 [High]  Firefox sync attribution is baseless; Safari is sound except the no-`origin` fallback
**Confidence**: tool behavior **Confirmed** (reproduced in CT 228, see Round-trip log); browser semantics **Likely** (frecency and Safari `origin` meanings from domain knowledge, not re-verified against live profiles this session — verify with real Firefox-Sync / iCloud-synced profiles).
**Files**: `history_search/pipeline/ingest.py:350-452` (extract_gecko; sync block `:395-407`), `:455-556` (extract_webkit; sync block `:521-530`).

**Firefox (Gecko) — not trustworthy.** `places.sqlite` has **no per-visit sync-origin column**; Firefox Sync merges remote history into the same `moz_places`/`moz_historyvisits`, indistinguishable from local. The heuristic invents a verdict from proxies that carry no provenance:
- `frecency < 0 → synced/likely` (`ingest.py:402-404`) — negative frecency means "not yet (re)calculated" (a transient ranking state for new/pending places), NOT sync. A fresh LOCAL visit with uncomputed frecency is mislabeled synced.
- `moz_meta` has no sync key → **all** visits `local/confirmed` (`ingest.py:396-398`) — absence of a key in one table doesn't confirm local origin; `moz_meta` isn't the authoritative sync-account record. Common case → falsely "confirmed local."
- Same DB yields `unknown`, `synced`, and `confirmed` for forensically identical visits.
**Fix**: Firefox per-visit sync is not determinable from `places.sqlite`. Collapse to `local/unknown` (or `unknown`); never emit `synced` from `frecency`, never `confirmed` from absence of a `moz_meta` key. Real sync-vs-local needs an external artifact (sync logs / account state), not `places.sqlite`.

**Safari (WebKit) — reasonably sound.** `history_visits.origin` is the real iCloud sync-direction signal (0=local, non-zero=synced); `origin != 0 → synced/likely` and `origin = 0 → local/confirmed` are correctly grounded and honestly labeled (`ingest.py:525-530`); the tombstone-taint downgrade (`local/likely`) is a defensible conservative choice. **One gap**: when the schema has no `origin` column (older Safari), the code falls through to `local/confirmed` (`ingest.py:529-530`) — it should be `local/unknown`, since sync can't be determined without `origin`.
**Fix**: when `has_origin` is False, emit `local/unknown` instead of `local/confirmed`.
**Status: FIXED 2026-06-20.** Gecko now emits `local/unknown` for every visit (the `frecency`/`moz_meta` heuristic and the unused `sync_enabled`/`frecency` reads were removed). Safari now emits `local/unknown` when there is no `origin` column (ordering: synced→tombstone-taint→origin=0 local/confirmed→no-origin local/unknown). Gecko/Safari tests in `test_extract_engines.py` updated to the corrected expectations; full suite 7/7 green; re-verified in CT 228.

### Found via real-data dogfooding (2026-06-20, CT 228, the `mack.wilcox` acquisition: 10 DBs, 6,385 visits)

Running a real forensic investigation across dimensions surfaced data-quality bugs the synthetic fixtures missed.

### UA-19 [High]  Carved timestamps are ~98% wrong and silently pollute the timeline
**Confidence**: Confirmed (measured on real data in CT 228).
**Files**: `history_search/pipeline/carve.py:235-263` (`_find_nearby_timestamp`), `:299-412` (`carve_deleted_records` sets `confidence="likely"`).
**Measured**: of 403 carved records, **396 (98%) carry an implausible timestamp** — 362 dumped at `2001-01` and 32 in the future (2030–2095); only 7 fell in the real activity window. The reported visit range for the whole case was `2001-01-01 → 2095-01-02` while real activity is 2023 + Mar–Jun 2026. Cause: the brute-force 8-byte window scan accepts any value in 2000–2100 (`946684800`–`4102444800`) and returns the first positional hit — almost always spurious. These are emitted as `confidence="likely"`, and the year-2100 ceiling doesn't catch the 95-year-wide junk band.
**Forensic impact**: an analyst building a timeline sees a fake 2001 spike and bogus future dates; carved evidence looks time-anchored when it isn't. Compounds UA-4 (WAL/carve mislabeled deleted) and L-2.
**Fix**: do not attach guessed timestamps as authoritative — only set `visit_time_utc` for carved rows when the value is structurally validated (correct field offset/record layout), else leave empty and mark `confidence="possible"`. Exclude carved rows from default timeline/heatmap, or render them on a separate, clearly-labeled track.

### UA-20 [Medium]  Carved URL fragments yield malformed `dns_host`, polluting host aggregation
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/carve.py:175-232` (`carve_urls_from_pages` cleaning), `history_search/pipeline/classify.py:63-93` (`decompose_url`).
**Measured**: hosts like `dropbox.comn`, `dropbox.comq=`, `chicosfas.com=`, `mailbait.infos=` appear in `/api/aggregate?group_by=dns_host` and the `cloud_storage` tag. Trailing/garbage bytes from carved slack aren't stripped, so `decompose_url` stores an invalid host, and host-based aggregations/filters/classifiers (e.g. `cloud_storage` matching `dropbox.com…`) get false members.
**Fix**: validate `dns_host` (must be a syntactically valid hostname with a real TLD) before storing; drop or quarantine carved URLs whose host fails validation.

### UA-21 [Low]  `chrome-extension://` URLs decompose to the extension ID as `dns_host` and tag `file_scheme`
**Confidence**: Confirmed.
**Files**: `history_search/pipeline/classify.py:63-93` (`decompose_url` → `urlparse` netloc = extension ID), `:652-661` (`_cls_file_scheme` groups `chrome-extension://` with `file://`/`data:`).
**Measured**: `file_scheme` drilldown shows hosts like `aeblfdkhhhdcdjpifhhbdiojplfjncoa` (a Chrome extension ID). Extension activity is real and worth surfacing, but lumping the opaque ID into `dns_host` pollutes host aggregation and merging it with `file://` under one tag loses the distinction.
**Fix**: treat `chrome-extension://` (and `moz-extension://`) as their own category/tag; don't use the extension ID as `dns_host` for aggregation (optionally resolve well-known extension IDs to names).

### UA-22 [Low]  Search-term extraction may capture non-query strings
**Confidence**: Possible (needs raw-URL confirmation — some may be legitimate searches of build-log lines).
**Files**: `history_search/pipeline/classify.py:197-204` (inline search-term extraction in `unfurl_url`), `:798-810` (`extract_search_terms`).
**Measured**: "search terms" included build/file paths like `/gettext-1.0/gettext-runtime/intl/conftest` (×15) and `/private/tmp/gettext-...conftest`. Either the user literally searched those (legit) or the extractor is pulling path-like `q=`/param values that aren't queries.
**Fix**: confirm against the raw URLs; if artifacts, tighten the search-engine match (host must be eTLD+1 of a known engine) and skip values that look like filesystem paths.

### UA-23 [High]  IOC pivoting is broken: FTS tokenizer shreds indicators; host filter is exact-only
**Confidence**: Confirmed (demonstrated on real data, CT 228).
**Files**: `history_search/pipeline/index.py:71` (`tokenize='unicode61'`), `history_search/server.py:322-333` (`_smart_to_fts5`), `:336-415` (`_build_where` — `FILTER_COLUMNS` host uses `dns_host = ?`), `:479-482` (`_get_filters`).
**Measured**: `_smart_to_fts5("evil.com")` → `evil* AND com*` (matches any row with an evil-prefixed AND com-prefixed token, not the host); `"127.0.0.1"` → `127*`; `"8.8.8.8"` → `""` (every octet <2 chars is dropped → no FTS). The `host` filter is exact equality, so filtering `upwind.io` returns **0** while the real domain+subdomains = **470 across 5 hostnames** (`snowflakecomputing.com`: 0 vs 80; `sharepoint.com`: 0 vs 245). There is no domain/subdomain match, no CIDR, no field-scoped exact search.
**Forensic impact**: the single most common threat-hunting action — pivot on a domain/IP IOC — either returns nothing (exact host) or noisy token soup (FTS). An analyst cannot reliably answer "every visit to this domain and its subdomains."
**Fix**: add a registrable-domain/`dns_host` suffix filter (`host=` matches `host` and `*.host`), an exact-IOC mode, and consider a `dns_host` column with a trigram or substring index; stop routing dotted IOCs through the prefix-AND tokenizer.
**Status: PARTIALLY FIXED 2026-06-20.** Added subdomain-aware `host=` (matches `host` + `*.host`) and strict `host_exact=` in `_build_where`. Verified on the real acquisition: `host=upwind.io` → **470** (was 0), `host=snowflakecomputing.com` → **80**, `host_exact=upwind.io` → 0. *Remaining:* indexed `etld1` column + a literal exact-IOC search mode that bypasses the `unicode61` tokenizer.

### UA-24 [High]  Heatmap & time-aggregations are polluted by carved bogus timestamps; no exclude-source filter
**Confidence**: Confirmed (measured).
**Files**: `history_search/server.py:765-783` (`/api/heatmap`), `:697-708` (time-bucket aggregates), `:479-482` (`_get_filters` — only `exclude_host`, no exclude-source/confidence), `FILTER_COLUMNS` `visit_source` is exact `=`.
**Measured**: 403 carved rows (UA-19, ~98% bogus times) feed `/api/heatmap`. The 00:00 hour shows **352** visits; with carved removed it is **2** — a phantom midnight spike. There is no filter to exclude carved/recovered rows or restrict to a confidence level (you can filter *to* one `visit_source`, not exclude one).
**Forensic impact**: the behavioral-pattern view (when is this user active) is actively wrong; an analyst would mis-state working hours.
**Fix**: exclude carved (or low-confidence) rows from heatmap/time aggregates by default; add `exclude_source`/`min_confidence` filters; fixing UA-19 also removes the worst of this.
**Status: FIXED 2026-06-20.** `/api/heatmap` and time-bucket aggregates now default-exclude `visit_source='carved'` (override with `include_carved=1`); added `exclude_source` and `min_confidence` filters in `_build_where`. Verified: heatmap 00:00 went from **352 → 2** (and back to 352 with `include_carved=1`).

### UA-25 [Medium]  No frequency stacking (first/last-seen) and a 200-row aggregation cap hide the long tail
**Confidence**: Confirmed (measured).
**Files**: `history_search/server.py:709-723` (aggregate returns `label,count` only), `:726` (no time bounds), `:663` (`limit = min(limit, 200)`).
**Measured**: 388 distinct hosts; `/api/aggregate` caps at 200 → 188 hosts unreachable via the API, silently. Aggregation returns count only — no `first_seen`/`last_seen`/min/max per group. The rare-host stack (count=1, with timestamps) — which the API cannot produce — surfaced a proxy/VPN-acquisition session on 2026-06-16 ~19:50 (`iproyal.com`, `proxy5.net`, `proxynova.com`, `hola.org`, `proxyhub.me`, `ditatompel.com`) that top-N aggregation buries.
**Forensic impact**: "least-frequency-of-occurrence" stacking is the core hunting technique; the rarest items are the most interesting and are exactly what the cap drops.
**Fix**: return `first_seen`/`last_seen`/`count` per group; support ascending-by-count to the full tail (paginate, don't hard-cap at 200); `log()` any truncation.
**Status: FIXED 2026-06-20.** `/api/aggregate` now returns `first_seen`/`last_seen` per group (computed over REAL visits — carved bogus times excluded from the bounds), and the cap was raised 200 → `MAX_AGG_LIMIT=5000`. Verified: `group_by=dns_host` returned **389** hosts with real windows (e.g. `teams.microsoft.com` 2026-03-23 → 2026-06-17); `sort=asc` surfaces the rare tail. *Remaining:* true offset pagination beyond 5000 + an explicit `truncated` flag.

### UA-26 [High]  "empty" is indistinguishable from "extraction failed" — silent evidence loss
**Confidence**: Confirmed.
**Files**: `history_search/server.py:187-192` (rows==0 → `status:"empty"`), `history_search/pipeline/ingest.py` extractors swallow `sqlite3.Error` and return `[]` (`extract_chromium` ~317-318, `extract_webkit` ~506-508 `return []`, `extract_gecko` ~427-449).
**Measured**: the real acquisition reported 2 Chrome DBs as `status:"empty"`. A DB whose extraction *failed* (lock, schema variant, corruption) is reported identically to a genuinely empty one, and the error only goes to `LOG.warning` (stderr) — never to the stats or the SPA.
**Forensic impact**: completeness is the analyst's first duty; "empty" that is really "broken" means dropped evidence the analyst will never know to chase.
**Fix**: distinguish `empty` (query ran, 0 rows) from `error` (extraction raised); carry the sqlite error into the stats/`extraction_failures` and surface it in the UI.

### UA-27 [Medium]  CSV export is a JSON-soup dump, not a report-grade artifact
**Confidence**: Confirmed.
**Files**: `history_search/server.py:571-578` (`CSV_COLUMNS` include `tags` and `unfurl` as raw JSON strings), `:605` (no metadata header row), `:625` (fixed `filename=export.csv`).
**Forensic impact**: the decoded intelligence the analyst came for (search terms, geo, embedded URLs, decoded timestamps) lands as an unparsed `unfurl` JSON cell; tags are a JSON array string. Imported to Excel/Splunk it's unusable per-field. No header records the query/filters/tool version/time, and re-exports overwrite `export.csv`, so the CSV is not court-reproducible (compounds UA-12, B-3).
**Fix**: flatten unfurl artifacts into typed columns (or a long-format companion CSV), timestamped filename, and a metadata header (tool version, query, filters, export time, source hashes).
**Status: FIXED 2026-06-20.** `/api/export` now writes a commented reproducibility header (tool_version, exported_utc, query, mode, filters), flattens `tags` to `; `-joined and `unfurl` to readable `type=value | …` pairs, and uses a timestamped filename `fmbrowser_export_<UTC>.csv`. Verified on real data (unfurl cell e.g. `embedded_url=https://console.upwind.io/onboarding`). *Remaining:* per-source SHA-256 in the header (depends on B-3) + an optional long-format artifact companion CSV.

### Usability/analysis test-coverage gaps
- No test asserting `/api/sources` `live_rows > 0` after a real ingest (would have caught UA-1/B-1).
- No test that out-of-range timestamps are flagged rather than dropped.
- No test that carved WAL rows are not mislabeled deleted.
- No test that the carve active-URL filter doesn't suppress a genuinely-deleted URL.
- No test that `/api/reingest` preserves transition/source/time.

### Round-trip validation log (2026-06-20, CT 228 `fmbrowser-val`, Alpine + py3-flask 3.0.3)

Ran the **real pipeline + real Flask endpoint** against a synthetic Windows Chrome acquisition at `Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History` (4 visits, incl. one year-2300 row). Evidence, not assertion:

- **UA-1/B-1 — reproduced and fix validated.** All extractors set `visits.source_db_path='Default'` while `ingest_log.source_db` = real path → the `/api/sources` LEFT JOIN matches nothing.
  - CURRENT code, real `/api/sources` HTTP response: `{live_rows: 0, ingested_rows: 4}`.
  - `/api/sources/delete` with the real path removed **0** visits → all 4 orphaned.
  - With fix (`source_db_path` = real path): HTTP `{live_rows: 4, ingested_rows: 4}`; delete removed **4**, 0 orphaned.
- **UA-3 — reproduced.** The year-2300 visit was ingested with `visit_time_utc=''` (silently nulled by the `4102444800` ceiling); the other 3 converted correctly. 1 of 4 rows has a blank, unflagged timestamp.
- **UA-17 — reproduced.** Fed a Chrome `visit_source` table with `source` 0/1/2 plus a no-row local visit. Tool output: `src=0 (SYNCED)` → `local/confirmed` (**wrong**), `src=1 (BROWSED/local)` → `synced/confirmed` (**wrong**), `src=2` → `extension/confirmed`, no-row → `local/confirmed`. Synced/local are inverted and both wrong cases are reported as `confirmed`.
- **UA-18 — reproduced.** Drove `extract_gecko` and `extract_webkit` across the input matrix. Gecko: sync-ON/frecency=-1 → `synced/likely` (false signal), sync-OFF/frecency=-1 → `local/confirmed` (over-claim), sync-ON/frecency>=0 → `unknown/unknown` — three verdicts for forensically identical visits. Safari: origin=0 → `local/confirmed`, origin=1 → `synced/likely`, origin=0+tombstones → `local/likely`, no-origin-column → `local/confirmed` (should be `unknown`). Safari sound; Gecko baseless.

**Recommended fix location** (single home): in `insert_visits` (`index.py:142-166`), before `_record_to_tuple`, set `r.source_db_path = source_db` for each record when `source_db` is provided; remove the `source_db_path=str(meta.browser_profile)` assignment from the three extractors (`ingest.py:298,387,510`). **Applied & re-verified 2026-06-20** (real pipeline + live `/api/sources` and `/api/sources/delete` in CT 228; suite 7/7).

---

## Sprint B + C implementation log (2026-06-21, CT 228, suite 7/7 throughout)

Driven end-to-end against the real `mack.wilcox` acquisition. Every item below is implemented + verified; working tree only, **no git**.

**Correctness (Sprint B):**
- **UA-19 — FIXED.** `_find_nearby_timestamp` (`carve.py`) now uses a ±64B window, returns the candidate CLOSEST to the URL, rejects FUTURE values (> now), and raised the floor to 2010 (`_CARVE_TS_FLOOR`); carved confidence is now `possible`. Verified: overall date range went from `2001-01-01 → 2095-01-02` to **`2021-11 → 2026-06`**; carved-with-fabricated-time dropped from 396/403 to 1/356; future/2001 clusters → 0.
- **UA-20 — FIXED (partial).** `_VALID_HOSTNAME_RE` in `carve.py` rejects carve-fragment junk hosts. Verified: `chicosfas.com=`, `dropbox.comq=`, `mailbait.infos=` gone. *Remaining:* a public-suffix check for 1-char over-reads like `dropbox.comn`.
- **UA-21 — FIXED.** `decompose_url` blanks `dns_host` for `chrome-extension://`/`moz-extension://`; new `browser_extension` classifier replaces lumping them under `file_scheme`. Verified: 3 extension rows, host blanked, tagged, ext-id gone from host aggregation.
- **UA-26 — FIXED.** New `IngestError`; extractors raise on hard failure; `run_pipeline` reports `status:"error"` (with detail in `extraction_failures`) vs `empty`. Verified: broken DB → error, valid-empty → empty; the 2 real Chrome DBs confirmed genuinely empty.

**Admissibility / chain of custody (Sprint C):**
- **B-9 — FIXED.** `raw_transition`/`raw_from_visit`/`raw_visit_id` columns added (schema + insert + `_record_to_tuple` + migration) and added to CSV export. Verified: 5,479 chromium rows carry the raw bitmask.
- **B-3 — FIXED.** `ingest_log` gains `source_sha256`, `source_size_bytes`, `tool_version`, `classifier_version`; `run_pipeline` SHA-256s each evidence DB; `classifier_version()` fingerprints the registry. Verified on real data (e.g. `sha256=1db3ff02…`, `tool=1.0.0`, `clf=be5513ac35c9`).
- **B-4 — FIXED.** Append-only `action_log` table + `log_action()`; `clear`/`delete`/`reingest`/`ingest` write audit rows. Verified: reingest wrote `('reingest', 6338, 'classifier be5513ac35c9')`.
- **UA-9 — FIXED.** `/api/reingest` reconstructs from the stored row, re-derives transition from the persisted raw bitmask (B-9) for chromium, stamps + returns `classifier_version`, and audits the action.
- **UA-11 — FIXED (heatmap).** `/api/heatmap` accepts `tz_offset` (signed minutes) and buckets in local time. Verified: busiest hour 13 UTC → 8 EST(−300) → 0 IST(+330). *Remaining:* tz on time-aggregates + auto-detecting device TZ from artifacts.

**Search/UX (Sprint A follow-on):**
- **UA-23 — effectively addressed for correctness.** Subdomain `host=` filter (Sprint A) + literal `mode=contains` already bypass the tokenizer; only the indexed `etld1` perf column remains.
- **UA-7 — DONE + browser-validated.** SearchView detail view makes **Host** and **From Visit (referrer)** clickable pivots (`static/index.html`); `/api/visit/<id>` returns full enriched detail (incl. raw_* fields). **Validated in a real Chromium** (shutter / CT 208 on `chaos`, Playwright driving `/bin/chromium`) against the live server (CT 228 bound `0.0.0.0:8899`): SPA renders with **zero pageerrors** (the in-browser-Babel JSX compiles), both pivots present in the DOM, and clicking the Host pivot populated the `host` filter and narrowed results **50 → 20** (screenshots `01_loaded`/`03_detail`/`04_pivoted`). Full round-trip confirmed.
- **UA-22 — open** (needs raw-URL confirmation whether build-path "search terms" are real or artifacts).
