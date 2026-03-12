#!/bin/bash
# Quick ingest helper — processes an archive and starts the server
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <archive_or_directory> [port]"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/evidence.7z"
    echo "  $0 /path/to/extracted_dir 9999"
    exit 1
fi

SOURCE="$1"
PORT="${2:-8888}"

echo "=== Forensic History Ingest ==="
echo "Source: $SOURCE"
echo "Port:   $PORT"
echo ""

python3 -m history_search.server "$SOURCE" --port "$PORT" --verbose
