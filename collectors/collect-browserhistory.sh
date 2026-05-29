#!/bin/bash
#
# collect-browserhistory.sh — macOS forensic browser-artifact collector
#
# Produces a single ZIP ingestible by FM-Browser. Escalating forensic levels:
#   L1  history DBs (always)            — "what did they navigate to?"
#   L2  + contact evidence              — "what did the browser actually contact?"
#   L3  + client-side state             — "what ran / persisted client-side?"
#   L4  + full cache payload (GB tier)  — "reconstruct content bodies"
#
# Layout inside the zip:
#   evidence/Users/<user>/...History    L1 at FM-Browser-matching paths (+ -wal/-shm)
#   files/<sha256>.bin                  L2-L4 blobs (content-addressed; no subdir nav)
#   logs/<host>_<utc>.jsonl             one JSON line per blob (provenance)
#   metadata.json  manifest.sha256  collection.log
#
# Discovery is by STRUCTURE (glob for History / places.sqlite / History.db), so
# Electron apps (Slack/Discord/Code) and unknown Chromium browsers are captured.
#
# Deployment: CrowdStrike RTR as root. No installs. macOS /bin/bash (3.2-safe).
# Originals are only ever read; never modified.

set -u

# ============================================================================
# Constants
# ============================================================================
COLLECTOR_VERSION="1.0.0"
EVIDENCE_DIR="evidence"
FILES_DIR="files"
LOGS_DIR="logs"
APPSUP="Library/Application Support"

# History sidecars carried next to every SQLite DB so WAL data is consistent.
SQLITE_SIDECARS="-wal -shm"

# Defaults (overridable via flags)
OUT_ROOT="/tmp/fmb-collect"
LEVEL=1
USERS_ARG=""
ROOT_OVERRIDE=""          # --root: treat as the filesystem root (testing / mounted images)
MAX_BLOB_BYTES=$((2 * 1024 * 1024 * 1024))   # skip a single payload file above this (L4 guard)

# ============================================================================
# Usage
# ============================================================================
usage() {
  cat <<EOF
collect-browserhistory.sh ${COLLECTOR_VERSION}

Usage: $0 [-l LEVEL] [-o OUTDIR] [-u user[,user]] [-r ROOT]

  -l LEVEL   Forensic level 1-4 (default 1). Cumulative:
               1 history DBs | 2 +contact | 3 +client-state | 4 +full cache
  -o OUTDIR  Staging + zip output dir (default ${OUT_ROOT}). Keep OFF user trees.
  -u USERS   Comma-separated usernames (default: all real /Users/* accounts).
  -r ROOT    Filesystem root to collect under (default /). For mounted images/tests.
  -h         This help.
EOF
}

# ============================================================================
# Helpers
# ============================================================================
log_line() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE" >&2; }

sha256_of() {
  # Echo the hex sha256 of a file, portable across macOS (shasum) and Linux.
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  else
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  fi
}

json_escape() {
  # Escape a string for embedding in a JSON value (backslash, quote, control).
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g'
}

# Append one provenance record to the per-run JSONL log.
log_blob() {
  # args: sha src_path user browser profile artifact_class level sidecars size mtime
  printf '{"sha256":"%s","src_path":"%s","user":"%s","browser":"%s","profile":"%s","artifact_class":"%s","level":%s,"sidecars":"%s","size":%s,"mtime":"%s"}\n' \
    "$1" "$(json_escape "$2")" "$(json_escape "$3")" "$4" "$(json_escape "$5")" \
    "$6" "$7" "$(json_escape "$8")" "$9" "${10}" >> "$JSONL_FILE"
}

# Copy a file into the content-addressed store. Echoes the sha (empty on miss).
store_blob() {
  # args: src_path user browser profile artifact_class
  src="$1"
  [ -f "$src" ] || return 0
  # L4 single-file size guard
  size=$(stat -f%z "$src" 2>/dev/null || stat -c%s "$src" 2>/dev/null || echo 0)
  if [ "$size" -gt "$MAX_BLOB_BYTES" ]; then
    log_line "  SKIP (too large ${size}B): $src"
    return 0
  fi
  sha=$(sha256_of "$src")
  [ -n "$sha" ] || { log_line "  FAIL hash: $src"; return 0; }
  dest="$STAGE/$FILES_DIR/$sha.bin"
  if [ ! -f "$dest" ]; then
    tmp="$dest.tmp.$$"
    if cp "$src" "$tmp" 2>/dev/null; then
      mv -f "$tmp" "$dest"      # atomic rename; identical content dedups by name
    else
      rm -f "$tmp" 2>/dev/null
      log_line "  FAIL copy: $src"
      return 0
    fi
  fi
  # macOS stat (-f); first line only, guard against non-macOS stat output.
  mtime=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" "$src" 2>/dev/null | head -1)
  case "$mtime" in *' '*|'') mtime="" ;; esac   # reject anything non-ISO
  log_blob "$sha" "$src" "$2" "$3" "$4" "$5" "$LEVEL" "" "$size" "$mtime"
}

# Copy an L1 history DB (+ sidecars) to the regex-matching evidence/ path.
copy_evidence_db() {
  # args: src_db archive_rel_path(no leading evidence/)
  src="$1"; rel="$2"
  [ -f "$src" ] || return 1
  dest="$STAGE/$EVIDENCE_DIR/$rel"
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest" 2>/dev/null || { log_line "  FAIL evidence copy: $src"; return 1; }
  for sc in $SQLITE_SIDECARS; do
    [ -f "$src$sc" ] && cp "$src$sc" "$dest$sc" 2>/dev/null
  done
  return 0
}

# Recursively store a directory subtree into the content-addressed store.
store_tree() {
  # args: dir user browser profile artifact_class
  dir="$1"
  [ -d "$dir" ] || return 0
  find "$dir" -type f 2>/dev/null | while IFS= read -r f; do
    store_blob "$f" "$2" "$3" "$4" "$5"
  done
}

# ============================================================================
# Argument parsing
# ============================================================================
while getopts ":l:o:u:r:h" opt; do
  case "$opt" in
    l) LEVEL="$OPTARG" ;;
    o) OUT_ROOT="$OPTARG" ;;
    u) USERS_ARG="$OPTARG" ;;
    r) ROOT_OVERRIDE="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "Option -$OPTARG requires an argument" >&2; usage; exit 2 ;;
    \?) echo "Unknown option -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

case "$LEVEL" in 1|2|3|4) ;; *) echo "LEVEL must be 1-4" >&2; exit 2 ;; esac

ROOT="${ROOT_OVERRIDE%/}"          # "" means real root; paths built as $ROOT/Users/...
USERS_ROOT="$ROOT/Users"

# ============================================================================
# Stage setup
# ============================================================================
HOSTN="$(scutil --get LocalHostName 2>/dev/null || hostname -s 2>/dev/null || hostname)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ZIP_BASE="${HOSTN}_${STAMP}"
ZIP_PATH="$OUT_ROOT/$ZIP_BASE.zip"
STAGE="$OUT_ROOT/stage_$STAMP"
LOG_FILE="$STAGE/collection.log"
JSONL_FILE="$STAGE/$LOGS_DIR/${HOSTN}_${STAMP}.jsonl"

mkdir -p "$STAGE/$EVIDENCE_DIR" "$STAGE/$FILES_DIR" "$STAGE/$LOGS_DIR"
: > "$LOG_FILE"
: > "$JSONL_FILE"

log_line "=== collect-browserhistory ${COLLECTOR_VERSION} ==="
log_line "host=$HOSTN level=$LEVEL root='${ROOT:-/}' out=$OUT_ROOT"
[ "$(id -u)" -ne 0 ] && log_line "WARNING: not root; coverage limited to current user"

# ============================================================================
# User enumeration
# ============================================================================
COLLECTED_USERS=""
if [ -n "$USERS_ARG" ]; then
  USER_LIST="$(printf '%s' "$USERS_ARG" | tr ',' ' ')"
else
  USER_LIST=""
  for d in "$USERS_ROOT"/*; do
    [ -d "$d" ] || continue
    u="$(basename "$d")"
    case "$u" in Shared|Guest|.*) continue ;; esac
    USER_LIST="$USER_LIST $u"
  done
fi

# ============================================================================
# Chromium-family browser roots (relative to $HOME).
#   name|relative-root  (profiles are Default + "Profile *" dirs under it)
# Discovery is structural, but these named roots map cleanly to FM-Browser regexes.
# ============================================================================
CHROMIUM_ROOTS="
chrome|$APPSUP/Google/Chrome
edge|$APPSUP/Microsoft Edge
brave|$APPSUP/BraveSoftware/Brave-Browser
vivaldi|$APPSUP/Vivaldi
arc|$APPSUP/Arc/User Data
"

# Profile-level payload for L2/L3/L4 (relative to a profile dir).
collect_profile_payload() {
  # args: profile_dir user browser profile_name
  pdir="$1"; pu="$2"; pb="$3"; pp="$4"
  [ -d "$pdir" ] || return 0

  if [ "$LEVEL" -ge 2 ]; then
    for f in "Cookies" "Login Data" "Web Data" "Preferences" "Secure Preferences" \
             "Bookmarks" "History Provider Cache" "Network/Cookies" \
             "Network/Network Persistent State" "Network/TransportSecurity" \
             "Network/Reporting and NEL"; do
      store_blob "$pdir/$f" "$pu" "$pb" "$pp" "l2_contact"
    done
    # Cache index + small data streams (NOT the f_*/data_# payload bodies).
    store_blob "$pdir/Cache/Cache_Data/index" "$pu" "$pb" "$pp" "l2_cache_index"
    for ds in "$pdir"/Cache/Cache_Data/data_*; do
      [ -f "$ds" ] && store_blob "$ds" "$pu" "$pb" "$pp" "l2_cache_index"
    done
  fi

  if [ "$LEVEL" -ge 3 ]; then
    store_blob "$pdir/Service Worker/Database" "$pu" "$pb" "$pp" "l3_client_state"
    for t in "Local Storage/leveldb" "Session Storage" "IndexedDB" "Extensions" \
             "Extension State" "Local Extension Settings" "Service Worker/ScriptCache"; do
      store_tree "$pdir/$t" "$pu" "$pb" "$pp" "l3_client_state"
    done
  fi

  if [ "$LEVEL" -ge 4 ]; then
    # Full cache payload bodies + code/GPU caches — the GB tier.
    for f in "$pdir"/Cache/Cache_Data/f_* "$pdir"/Cache/Cache_Data/data_#*; do
      [ -f "$f" ] && store_blob "$f" "$pu" "$pb" "$pp" "l4_cache_payload"
    done
    for t in "Code Cache" "GPUCache" "Service Worker/CacheStorage"; do
      store_tree "$pdir/$t" "$pu" "$pb" "$pp" "l4_cache_payload"
    done
  fi
}

# ============================================================================
# Main collection loop
# ============================================================================
for u in $USER_LIST; do
  H="$USERS_ROOT/$u"
  [ -d "$H" ] || continue
  log_line "user: $u"
  found_any=0

  # ---- Safari (single fixed path) ----
  if copy_evidence_db "$H/Library/Safari/History.db" \
        "Users/$u/Library/Safari/History.db"; then
    found_any=1
    log_line "  safari History.db"
    [ "$LEVEL" -ge 2 ] && {
      store_blob "$H/Library/Safari/Downloads.plist" "$u" "safari" "Default" "l2_contact"
      store_blob "$H/Library/Safari/Bookmarks.plist" "$u" "safari" "Default" "l2_contact"
      store_blob "$H/Library/Cookies/Cookies.binarycookies" "$u" "safari" "Default" "l2_contact"
    }
  fi

  # ---- Chromium family (Default + "Profile *") ----
  printf '%s\n' "$CHROMIUM_ROOTS" | while IFS='|' read -r name root; do
    [ -n "$name" ] || continue
    broot="$H/$root"
    [ -d "$broot" ] || continue
    # 3.2-safe profile glob: Default and "Profile N"
    for prof in "$broot/Default" "$broot"/Profile\ *; do
      [ -d "$prof" ] || continue
      [ -f "$prof/History" ] || continue
      pname="$(basename "$prof")"
      # archive-relative path mirrors the real $root so it matches the regex
      rel="Users/$u/$root/$pname/History"
      copy_evidence_db "$prof/History" "$rel" && \
        log_line "  $name/$pname History"
      collect_profile_payload "$prof" "$u" "$name" "$pname"
    done
    # browser-root Local State (holds the DPAPI/Keychain-wrapped cookie key)
    [ "$LEVEL" -ge 2 ] && store_blob "$broot/Local State" "$u" "$name" "" "l2_contact"
  done

  # ---- Firefox (every Profiles/* with places.sqlite) ----
  ffroot="$H/$APPSUP/Firefox/Profiles"
  if [ -d "$ffroot" ]; then
    for prof in "$ffroot"/*; do
      [ -d "$prof" ] || continue
      [ -f "$prof/places.sqlite" ] || continue
      pname="$(basename "$prof")"
      copy_evidence_db "$prof/places.sqlite" \
        "Users/$u/$APPSUP/Firefox/Profiles/$pname/places.sqlite" && \
        log_line "  firefox/$pname places.sqlite"
      found_any=1
      if [ "$LEVEL" -ge 2 ]; then
        for f in "cookies.sqlite" "formhistory.sqlite" "logins.json" "key4.db"; do
          store_blob "$prof/$f" "$u" "firefox" "$pname" "l2_contact"
        done
      fi
      [ "$LEVEL" -ge 3 ] && store_tree "$prof/storage" "$u" "firefox" "$pname" "l3_client_state"
    done
  fi

  [ "$found_any" -eq 1 ] && COLLECTED_USERS="$COLLECTED_USERS $u"
done

# ============================================================================
# metadata.json  (documentation only — FM-Browser does NOT read this)
# ============================================================================
users_json=""
for u in $COLLECTED_USERS; do
  users_json="$users_json\"$(json_escape "$u")\","
done
users_json="${users_json%,}"

cat > "$STAGE/metadata.json" <<EOF
{
  "collector_version": "$COLLECTOR_VERSION",
  "collection_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "os_platform": "macos",
  "endpoint_name": "$(json_escape "$HOSTN")",
  "hostname": "$(hostname 2>/dev/null)",
  "level": $LEVEL,
  "os_usernames": [${users_json}],
  "tool_versions": {"os": "$(sw_vers -productVersion 2>/dev/null)", "bash": "$BASH_VERSION"},
  "locked_db_strategy": "cp of History + -wal + -shm; originals read-only",
  "notes": ""
}
EOF

# ============================================================================
# SHA-256 manifest (excludes itself)
# ============================================================================
log_line "Generating manifest"
(
  cd "$STAGE" || exit 0
  find . -type f ! -name 'manifest.sha256' -print0 2>/dev/null \
    | xargs -0 shasum -a 256 2>/dev/null \
    | sed 's#  \./#\t#' > manifest.sha256
)

# ============================================================================
# Zip (forward-slash entries native on macOS; no nested archives)
# ============================================================================
log_line "Creating $ZIP_PATH"
(
  cd "$STAGE" || exit 1
  zip -r -q -X "$ZIP_PATH" . 2>>"$LOG_FILE"
)
if [ -f "$ZIP_PATH" ]; then
  zsha="$(sha256_of "$ZIP_PATH")"
  log_line "DONE: $ZIP_PATH (sha256=$zsha)"
  printf '%s\n' "$ZIP_PATH"
else
  log_line "ERROR: zip not created"
  exit 1
fi
