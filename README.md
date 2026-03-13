# FM-Browser - Forensic Browser History Search Engine

A forensic tool that ingests browser history from forensic acquisitions, classifies visits with forensic tags, and serves a searchable web interface. One command, zero infrastructure.

## Quick Start

```bash
pip install flask
sudo apt-get install p7zip-full    # or: brew install p7zip (macOS)

python -m history_search.server /path/to/evidence.7z --port 8888
```

Open `http://localhost:8888`. That's it.

The pipeline extracts archives (tries passwords `infected`, `dangerous`, then none), discovers browser history databases by schema probing, classifies every visit, and serves the UI.

```bash
# Point at a directory instead of an archive
python -m history_search.server /path/to/extracted/files/ --port 8888

# Run server only (data already ingested)
python -m history_search.server --port 8888
```

## What It Does

```
[Archive.7z] → Extract → Discover DBs → Per-Visit Records → Classify → FTS5 Index → Web UI
```

- Supports Chrome, Firefox, Safari, Edge, Brave, Vivaldi, Arc
- 15 forensic classifiers (credentials in URLs, OAuth flows, cloud storage, suspicious TLDs, etc.)
- Visit source detection (local vs. synced vs. extension) with confidence levels
- Three search modes: FTS5, substring, regex
- CSV export of any search result set
- Source manager to selectively remove ingested files

## CLI Options

```
python -m history_search.server [source] [options]

  source              Archive file or directory path (optional)
  --port PORT         Server port (default: 8888)
  --host HOST         Bind address (default: 127.0.0.1)
  --db DB             Index database path (default: history_index.db)
  --verbose           Debug logging
```

## Requirements

- Python 3.8+
- Flask
- p7zip-full (system package for archive extraction)
- No JavaScript build step - the SPA uses React via CDN

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/API.md) | All endpoints, parameters, and examples |
| [Web Interface Guide](docs/UI.md) | Search, Explore, and Ingest views |
| [Architecture & Code Map](docs/CODEMAP.md) | "I want to..." contributor guide |
| [Acknowledgments](docs/ACKNOWLEDGMENTS.md) | Credits to open-source projects |
