---
name: browser-check
description: Render and functionally validate the FM-Browser SPA in a REAL browser to check your work. Use after any change to history_search/static/index.html, or to confirm a UI feature/fix actually works end-to-end (not just that tests pass). The SPA is a single-file React app transpiled by in-browser Babel, so a JSX error white-screens with NO Python/test failure — only a real browser catches it. Drives Chromium on the shutter LXC against a live server.
---

# browser-check — real-browser round-trip validation

The Python suite and any headless check **cannot** validate `static/index.html`: it's a single-file React SPA transpiled by **in-browser Babel**, so a JSX typo silently white-screens with zero Python error and a green suite. This skill renders it in a real Chromium, asserts it compiled (no `pageerror`), and exercises the actual UI.

## Topology (already provisioned — verify, don't assume)
- **App host:** CT 228 `fmbrowser-val` on Proxmox node `trouble`, IP `192.168.7.227`. Project mounted read-only at `/workspace`; flask installed; populated index at `/tmp/final.db` (rebuild if missing — see step 1).
- **Browser host:** CT 208 `shutter` on node `chaos`, IP `192.168.7.184`. Has `/bin/chromium` + a Playwright venv at `/root/fmbpw`. Reaches CT 228 over `vmbr0`. Its `/mnt/cephfs/shared/projects/shutter` is mounted at `/workspace`, and is writable from `trouble` at `/mnt/cephfs/shared/projects/shutter/` — drop scripts there.
- You run on `trouble`: drive CT 228 with `pct exec 228 -- …`; drive CT 208 with `ssh chaos pct exec 208 -- …`. Confirm IPs each run (`pct exec 228 -- hostname -I`) — they're DHCP and can change.

## Procedure
1. **Populated index in CT 228** (rebuild if `/tmp/final.db` is gone):
   ```
   pct exec 228 -- sh -c 'cd /workspace; PYTHONPATH=/workspace python3 -c "from pathlib import Path; from history_search.pipeline.index import init_schema; from history_search.server import run_pipeline; init_schema(\"/tmp/final.db\"); run_pipeline(\"/tmp/final.db\", Path(\"/workspace/<archive-or-dir>\"))"'
   ```
2. **Serve on 0.0.0.0** (background — GET endpoints need no `--allow-remote`):
   ```
   pct exec 228 -- sh -c 'cd /workspace; PYTHONPATH=/workspace python3 -m history_search.server --db /tmp/final.db --host 0.0.0.0 --port 8899'   # run_in_background:true
   ```
   Confirm reachable: `ssh chaos pct exec 208 -- curl -sS -m8 http://192.168.7.227:8899/api/filters | head -c 120`
3. **One-time venv** (only if `/root/fmbpw` is missing):
   `ssh chaos pct exec 208 -- bash -lc 'python3 -m venv /root/fmbpw && /root/fmbpw/bin/pip -q install playwright'`
4. **Run the validator** (template `validate.py` sits next to this SKILL.md):
   ```
   cp .claude/skills/browser-check/validate.py /mnt/cephfs/shared/projects/shutter/validate.py
   ssh chaos pct exec 208 -- /root/fmbpw/bin/python /workspace/validate.py http://192.168.7.227:8899/
   ```
   It launches `/bin/chromium` headless (`--no-sandbox`), waits for the SPA to render, captures every `pageerror`, runs a search + expands a row, and writes screenshots to `/workspace/shots/` = `/mnt/cephfs/shared/projects/shutter/shots/` on `trouble` — **Read those PNGs to eyeball the result**.
5. **Assert the JSON report:** `spa_rendered: true`, **`pageerrors: []`** (compiled), and your feature-specific checks. To validate a specific change, edit `validate.py` and locate your element by a **unique `title=` or text** (e.g. the UA-7 pivots use `title*="Pivot: visits to this host"`), then assert it's present and that clicking it changes state.
6. **Clean up:** stop the server — `pct exec 228 -- pkill -f history_search.server`. Leave CT 208 running (it's `onboot=1`). Don't leave a `0.0.0.0` server bound.

## Gotchas
- A `console error … 404` (favicon) and the Babel "precompile for production" **warning** are expected/benign. A **`pageerror`** is a real compile/runtime break — fail on it.
- Mutating POST endpoints are loopback-gated (`require_local`); browser validation only needs GETs, so binding `0.0.0.0` without `--allow-remote` is fine and safer.
- If the SPA never renders, check shutter has internet (the React/Babel come from cdnjs): `ssh chaos pct exec 208 -- curl -sI -m8 https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js | head -1`.
