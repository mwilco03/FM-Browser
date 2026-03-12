# Project Context

## What This Is
FM-Browser is a forensic browser history search tool designed for DFIR analysts.
It processes forensic acquisitions (typically password-protected 7z archives from
endpoint collections) containing browser history SQLite databases.

## Key Design Decisions
- Per-visit extraction (not summary tables) for forensic accuracy
- Browser engine-based query selection (chromium/gecko/webkit), not browser name
- Heuristic sync detection for Firefox and Safari (Chrome has explicit visit_source table)
- Tags stored as JSON arrays for FTS5 searchability
- Single `/api/aggregate` endpoint replaces multiple dashboard endpoints
- SPA uses React via CDN (no build step) for maximum portability
- Archive passwords tried in order: "infected", "dangerous", "" (no password)

## Supported Browsers
Chrome, Safari, Firefox, Edge, Brave, Vivaldi, Arc, Opera — any Chromium derivative
shares the same History schema.

## Forensic Value
- Distinguishes local vs synced visits (critical for placing user at keyboard)
- Preserves navigation chains via from_visit references
- Classifies: credentials in URLs, OAuth redirects, cloud storage, paste sites,
  suspicious TLDs, download links, internal network access, and more
- Full provenance chain from archive to individual visit
