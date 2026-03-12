#!/bin/bash
# Setup script for FM-Browser forensic history search engine
set -e

echo "=== FM-Browser Setup ==="

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi
echo "[+] Python: $(python3 --version)"

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip install flask 2>/dev/null || pip3 install flask

# Check/install 7z
if ! command -v 7z &>/dev/null; then
    echo "[!] 7z not found. Installing p7zip-full..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y p7zip-full
    elif command -v brew &>/dev/null; then
        brew install p7zip
    else
        echo "WARNING: Could not install p7zip. Archive extraction may fail."
    fi
else
    echo "[+] 7z: $(7z --help 2>&1 | head -1)"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Usage:"
echo "  python -m history_search.server /path/to/evidence.7z --port 8888"
echo "  python -m history_search.server --port 8888  # server only"
