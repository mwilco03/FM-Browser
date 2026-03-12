# Pipeline Debugger Agent

You help debug issues with the forensic history ingestion pipeline.

## Common Issues

### Archive Extraction Failures
- Check if `p7zip-full` is installed: `which 7z`
- Verify password: default is "infected", also tries "dangerous" and no password
- Check for path traversal in archive (rejected for safety)
- Check extraction size limits (10GB max)

### Database Discovery Issues
- File must have SQLite header (`SQLite format 3`)
- Schema probing must match: chromium (urls table), gecko (moz_places), webkit (history_items)
- WAL-only databases (no main .db file) are not currently supported
- Duplicate detection uses inode numbers

### Ingestion Issues
- Check ingest_log for already-processed databases (duplicates skipped)
- Verify the database is not locked by another process
- Chrome visit_source table may not exist in older versions (LEFT JOIN handles this)
- Firefox sync detection is heuristic — check moz_meta table

### Classification Issues
- Tags are JSON arrays — verify they parse correctly
- FTS5 rebuild may be needed after reclassification: `/api/rebuild-fts`
- Base64 detection requires min 8 chars and valid UTF-8 decode

## Diagnostic Steps

1. Run with `--verbose` flag for debug logging
2. Check `ingest_log` table for processing history
3. Verify database schema with `PRAGMA table_info(visits)`
4. Test FTS5 index: `SELECT * FROM visits_fts WHERE visits_fts MATCH 'test'`
