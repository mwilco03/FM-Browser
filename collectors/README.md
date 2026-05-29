# FM-Browser endpoint collectors

Self-contained, single-file forensic browser-artifact collectors that produce a
ZIP ingestible by FM-Browser. One per OS:

| Script | Platform | Runtime floor |
|--------|----------|---------------|
| `collect-browserhistory.ps1` | Windows | Windows PowerShell 5.1 (ships on Win10+) |
| `collect-browserhistory.sh`  | macOS   | `/bin/bash` 3.2 (the system bash) |

Both run with no installs, intended for CrowdStrike RTR (SYSTEM / root). Originals
are only ever read — never modified, never checkpointed.

## Escalating forensic levels

The level is a **cumulative** dial — each level is a superset of the one below.
Principle: *where does the evidence live when the History DB doesn't have it.*
The level is also the size dial (L1 is RTR-`get`-friendly, L4 is the big pull).

| Level | Question answered | Adds | Size |
|-------|-------------------|------|------|
| **1** | What did they navigate to? | History / `places.sqlite` / Safari `History.db` (+ `-wal`/`-shm`) | KB–MB |
| **2** | What did the browser actually *contact*? | Cache **index** (not payload bodies), `Network/Network Persistent State`, `TransportSecurity`, `Reporting and NEL`, Cookies, Login Data, Web Data, Preferences, Bookmarks, `Local State` | MB |
| **3** | What ran / persisted client-side? | Service Worker DB + scripts, Local Storage (leveldb), Session Storage, IndexedDB, Extensions | 10s–100s MB |
| **4** | Reconstruct content bodies | full Cache payload (`f_*`, `data_#`), Code Cache, GPUCache, Service Worker CacheStorage | GB |

> The L2 "contact" tier is the answer to the classic *"EDR saw Chrome Helper hit
> domain X but it's not in history"* — subresources, preconnects, and
> service-worker traffic land in the cache index and network-state files, not the
> History DB.

**Out of scope (by design):** OS/network state, DNS / unified-log queries,
SRUM/Amcache/Prefetch/EVTX, and pre-2016 browsers (Safari `History.plist`,
Internet Explorer `WebCacheV01.dat`). Browser artifacts only.

## Usage

macOS:
```bash
# L1 (history only), all users → /tmp/fmb-collect/<host>_<utc>.zip
sudo ./collect-browserhistory.sh

# L2, specific users, custom output dir
sudo ./collect-browserhistory.sh -l 2 -u alice,bob -o /tmp/case-1234
```

Windows (PowerShell as admin / SYSTEM):
```powershell
# L1, all users → C:\Users\Public\fmb-collect\<host>_<utc>.zip
.\collect-browserhistory.ps1

# L2, specific users
.\collect-browserhistory.ps1 -Level 2 -Users alice,bob -OutRoot C:\case-1234
```

Both accept a root override (`-r ROOT` / `-UsersRoot`) for mounted images or testing.

## RTR deployment sketch

1. `put` the script to the endpoint (or paste inline via `runscript`).
2. Run it (`-l`/`-Level` for the tier). Output is `<OutRoot>\<host>_<utc>.zip`;
   the script prints the final path on stdout.
3. `get <printed-path>` to retrieve. Keep the level low for RTR `get` size limits;
   escalate only when the case needs it.
4. `rm` the zip (and the `stage_*` dir) when retrieved.

The zip is named `<hostname>_<UTC>.zip` on purpose: FM-Browser does **not** read
`metadata.json`, so the endpoint identity comes from the **zip filename** via the
ingest provenance fallback.

## Zip layout

```
<hostname>_<UTC>.zip
├── metadata.json                     endpoint info (documentation; NOT read by ingest)
├── manifest.sha256                   <relpath>\t<sha256> for every file (excludes itself)
├── collection.log                    run transcript
├── evidence/Users/<user>/...History  L1 history DBs at FM-Browser-matching paths (+ -wal/-shm)
├── files/<sha256>.bin                L2-L4 artifacts, content-addressed (flat — no subdir nav)
└── logs/<host>_<utc>.jsonl           one JSON line per blob: sha256, src_path, user, browser,
                                       profile, artifact_class, level, size, mtime
```

**Why the split:** FM-Browser ingests the small L1 history DBs straight from
`evidence/` (its path regexes are substring matches, so the `evidence/` prefix is
invisible — zero app change). The bulky L2–L4 payload lives in a flat
content-addressed store so an analyst never navigates deep browser subtrees; the
JSONL log maps every hash back to its real source path and provenance.

Content-addressing also means many endpoints can safely write into one shared
collection root: identical bytes dedup to the same `files/<sha256>.bin`, distinct
content can't collide, and each run gets its own JSONL log.

## Verification (analyst workstation)

1. **Integrity** — extract, recompute hashes, diff against `manifest.sha256`.
   Every `files/<name>.bin` filename must equal the SHA-256 of its contents.
2. **Ingest** — point FM-Browser at the zip (`/api/ingest` or CLI). The response
   `stats.ingested[]` should list each L1 DB with the right `browser` / `os_platform`
   / `os_username` / `browser_profile` and `rows > 0`. `endpoint_name` equals the
   zip basename.
3. **Pre-flight** — every path under `evidence/` matches exactly one FM-Browser
   browser-path regex; nothing under `files/` matches any (so L2–L4 never ingests
   by accident).

### Local validation without endpoints

On a Linux/macOS box you can prove the macOS collector + ingest round-trip with a
synthetic tree (no Flask needed):

```bash
# build a fake /Users tree with a real SQLite History DB under it, then:
./collect-browserhistory.sh -l 2 -o /tmp/out -r /path/to/fakeroot -u alice
# feed the staged evidence/ tree through the stdlib pipeline:
python3 -c "from history_search.pipeline.ingest import discover_databases, ingest_database; \
            from pathlib import Path; \
            [print(e, m.browser, m.os_username, len(ingest_database(p,e,m,str(p)))) \
             for p,e,m in discover_databases(Path('/tmp/out/stage_*/evidence'))]"
```

## Notes / limits

- **Discovery is structural** (glob for `History` / `places.sqlite` / Safari
  `History.db`). Electron apps (Teams, Slack, Discord, VS Code) and unknown
  Chromium browsers are captured automatically; FM-Browser engine-probes anything
  whose path doesn't match a named regex, so they still ingest.
- **Encrypted cookies/logins** (L2): `Local State` is collected so the Chrome 80+
  DPAPI-wrapped key travels with the data. Chrome ~127+ app-bound encryption is a
  later off-host parsing concern, not a collection blocker (SYSTEM-context
  collection still captures the files).
- **macOS `mtime`** in the JSONL uses BSD `stat -f`; on a non-macOS host it is
  emitted empty rather than wrong.
