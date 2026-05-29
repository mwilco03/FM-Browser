#requires -Version 5.1
<#
.SYNOPSIS
  collect-browserhistory.ps1 — Windows forensic browser-artifact collector.

.DESCRIPTION
  Produces a single ZIP ingestible by FM-Browser. Escalating forensic levels:
    L1  history DBs (always)            "what did they navigate to?"
    L2  + contact evidence              "what did the browser actually contact?"
    L3  + client-side state             "what ran / persisted client-side?"
    L4  + full cache payload (GB tier)  "reconstruct content bodies"

  Layout inside the zip:
    evidence\Users\<user>\...History    L1 at FM-Browser-matching paths (+ -wal/-shm)
    files\<sha256>.bin                  L2-L4 blobs (content-addressed; no subdir nav)
    logs\<host>_<utc>.jsonl             one JSON line per blob (provenance)
    metadata.json  manifest.sha256  collection.log

  Discovery is by STRUCTURE (any Chromium 'History' / Firefox 'places.sqlite'),
  so Electron apps (Teams/Slack/Discord/Code) and unknown browsers are captured.

  Deployment: CrowdStrike RTR as SYSTEM. No installs. Windows PowerShell 5.1.
  Originals are only ever read (read-share copy); never modified.
#>
[CmdletBinding()]
param(
  [ValidateRange(1,4)][int]$Level = 1,
  [string]$OutRoot = "$env:PUBLIC\fmb-collect",   # keep OFF any collected user tree
  [string[]]$Users,                                # default: all real C:\Users\* accounts
  [string]$UsersRoot = "$env:SystemDrive\Users",   # override for mounted images/tests
  [long]$MaxBlobBytes = 2GB                         # skip a single payload file above this
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# Constants
# ============================================================================
$COLLECTOR_VERSION = '1.0.0'
$EVIDENCE_DIR = 'evidence'
$FILES_DIR    = 'files'
$LOGS_DIR     = 'logs'
$SQLITE_SIDECARS = @('-wal', '-shm')

# Chromium-family browser roots relative to a user profile dir. Profiles are
# 'Default' + 'Profile *' subdirs that contain a 'History' file.
$ChromiumRoots = @(
  @{ name = 'chrome';  root = 'AppData\Local\Google\Chrome\User Data' }
  @{ name = 'edge';    root = 'AppData\Local\Microsoft\Edge\User Data' }
  @{ name = 'brave';   root = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' }
  @{ name = 'vivaldi'; root = 'AppData\Local\Vivaldi\User Data' }
  @{ name = 'teams';   root = 'AppData\Roaming\Microsoft\Teams' }   # classic Electron Teams
)

# ============================================================================
# Stage setup
# ============================================================================
$HostName = $env:COMPUTERNAME
$Stamp    = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$ZipBase  = "${HostName}_${Stamp}"
$ZipPath  = Join-Path $OutRoot "$ZipBase.zip"
$Stage    = Join-Path $OutRoot "stage_$Stamp"
$LogFile  = Join-Path $Stage 'collection.log'
$JsonlFile = Join-Path $Stage "$LOGS_DIR\${HostName}_${Stamp}.jsonl"

$null = New-Item -ItemType Directory -Force -Path (Join-Path $Stage $EVIDENCE_DIR)
$null = New-Item -ItemType Directory -Force -Path (Join-Path $Stage $FILES_DIR)
$null = New-Item -ItemType Directory -Force -Path (Join-Path $Stage $LOGS_DIR)
Set-Content -Path $LogFile -Value '' -Encoding UTF8
Set-Content -Path $JsonlFile -Value '' -Encoding ASCII

# ============================================================================
# Helpers
# ============================================================================
function Write-Log {
  param([string]$Msg)
  $line = '[{0}] {1}' -f (Get-Date).ToUniversalTime().ToString('HH:mm:ssZ'), $Msg
  Add-Content -Path $LogFile -Value $line
  Write-Host $line
}

function Copy-LockedFile {
  # Read-share copy so a running browser doesn't block us; SYSTEM has access.
  # Falls back to robocopy /b (backup semantics). Returns $true on success.
  param([string]$Src, [string]$Dest)
  if (-not (Test-Path -LiteralPath $Src)) { return $false }
  try {
    $in  = [System.IO.File]::Open($Src, [System.IO.FileMode]::Open,
             [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      $out = [System.IO.File]::Create($Dest)
      try { $in.CopyTo($out) } finally { $out.Close() }
    } finally { $in.Close() }
    return $true
  } catch {
    $rc = Start-Process robocopy -ArgumentList @(
            ('"{0}"' -f (Split-Path $Src)), ('"{0}"' -f (Split-Path $Dest)),
            ('"{0}"' -f (Split-Path $Src -Leaf)), '/b', '/r:1', '/w:1', '/nfl', '/njh', '/njs'
          ) -Wait -PassThru -WindowStyle Hidden
    return ($rc.ExitCode -lt 8 -and (Test-Path -LiteralPath $Dest))
  }
}

function Get-Sha256 {
  param([string]$Path)
  try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower() }
  catch { '' }
}

function ConvertTo-JsonValue {
  param([string]$S)
  if ($null -eq $S) { return '' }
  $S = $S -replace '\\','\\\\' -replace '"','\"' -replace "`t",'\t' -replace "`r",'' -replace "`n",'\n'
  return $S
}

$script:CollectedUsers = @{}

function Add-Blob {
  # Copy a file into the content-addressed store + write a provenance line.
  param([string]$Src, [string]$User, [string]$Browser, [string]$Profile, [string]$Class)
  if (-not (Test-Path -LiteralPath $Src -PathType Leaf)) { return }
  $size = (Get-Item -LiteralPath $Src).Length
  if ($size -gt $MaxBlobBytes) { Write-Log "  SKIP (too large ${size}B): $Src"; return }

  # Read-share copy to a temp, hash, then atomic-rename to files\<sha>.bin (dedup).
  $tmp = Join-Path $Stage "$FILES_DIR\_tmp_$([System.Guid]::NewGuid().ToString('N')).part"
  if (-not (Copy-LockedFile -Src $Src -Dest $tmp)) { Write-Log "  FAIL copy: $Src"; return }
  $sha = Get-Sha256 -Path $tmp
  if (-not $sha) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; return }
  $dest = Join-Path $Stage "$FILES_DIR\$sha.bin"
  if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
  else { Move-Item -LiteralPath $tmp -Destination $dest -Force }

  $mtime = (Get-Item -LiteralPath $Src).LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
  $line = '{{"sha256":"{0}","src_path":"{1}","user":"{2}","browser":"{3}","profile":"{4}","artifact_class":"{5}","level":{6},"sidecars":"","size":{7},"mtime":"{8}"}}' -f `
    $sha, (ConvertTo-JsonValue $Src), (ConvertTo-JsonValue $User), $Browser,
    (ConvertTo-JsonValue $Profile), $Class, $Level, $size, $mtime
  Add-Content -Path $JsonlFile -Value $line
}

function Add-BlobTree {
  param([string]$Dir, [string]$User, [string]$Browser, [string]$Profile, [string]$Class)
  if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return }
  Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    Add-Blob -Src $_.FullName -User $User -Browser $Browser -Profile $Profile -Class $Class
  }
}

function Copy-EvidenceDb {
  # Copy an L1 history DB (+ sidecars) to the regex-matching evidence\ path.
  param([string]$Src, [string]$ArchiveRel)
  if (-not (Test-Path -LiteralPath $Src -PathType Leaf)) { return $false }
  $dest = Join-Path $Stage "$EVIDENCE_DIR\$ArchiveRel"
  $null = New-Item -ItemType Directory -Force -Path (Split-Path $dest)
  if (-not (Copy-LockedFile -Src $Src -Dest $dest)) { Write-Log "  FAIL evidence copy: $Src"; return $false }
  foreach ($sc in $SQLITE_SIDECARS) {
    if (Test-Path -LiteralPath "$Src$sc") { [void](Copy-LockedFile -Src "$Src$sc" -Dest "$dest$sc") }
  }
  return $true
}

function Collect-ProfilePayload {
  param([string]$ProfileDir, [string]$User, [string]$Browser, [string]$ProfileName)
  if (-not (Test-Path -LiteralPath $ProfileDir)) { return }

  if ($Level -ge 2) {
    foreach ($f in @('Cookies','Login Data','Web Data','Preferences','Secure Preferences',
                     'Bookmarks','History Provider Cache','Network\Cookies',
                     'Network\Network Persistent State','Network\TransportSecurity',
                     'Network\Reporting and NEL')) {
      Add-Blob -Src (Join-Path $ProfileDir $f) -User $User -Browser $Browser -Profile $ProfileName -Class 'l2_contact'
    }
    Add-Blob -Src (Join-Path $ProfileDir 'Cache\Cache_Data\index') -User $User -Browser $Browser -Profile $ProfileName -Class 'l2_cache_index'
    Get-ChildItem -LiteralPath (Join-Path $ProfileDir 'Cache\Cache_Data') -Filter 'data_*' -File -ErrorAction SilentlyContinue | ForEach-Object {
      Add-Blob -Src $_.FullName -User $User -Browser $Browser -Profile $ProfileName -Class 'l2_cache_index'
    }
  }

  if ($Level -ge 3) {
    Add-Blob -Src (Join-Path $ProfileDir 'Service Worker\Database') -User $User -Browser $Browser -Profile $ProfileName -Class 'l3_client_state'
    foreach ($t in @('Local Storage\leveldb','Session Storage','IndexedDB','Extensions',
                     'Extension State','Local Extension Settings','Service Worker\ScriptCache')) {
      Add-BlobTree -Dir (Join-Path $ProfileDir $t) -User $User -Browser $Browser -Profile $ProfileName -Class 'l3_client_state'
    }
  }

  if ($Level -ge 4) {
    Get-ChildItem -LiteralPath (Join-Path $ProfileDir 'Cache\Cache_Data') -File -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -like 'f_*' -or $_.Name -like 'data_#*' } | ForEach-Object {
        Add-Blob -Src $_.FullName -User $User -Browser $Browser -Profile $ProfileName -Class 'l4_cache_payload'
      }
    foreach ($t in @('Code Cache','GPUCache','Service Worker\CacheStorage')) {
      Add-BlobTree -Dir (Join-Path $ProfileDir $t) -User $User -Browser $Browser -Profile $ProfileName -Class 'l4_cache_payload'
    }
  }
}

# ============================================================================
# Main
# ============================================================================
Write-Log "=== collect-browserhistory $COLLECTOR_VERSION ==="
Write-Log "host=$HostName level=$Level usersRoot=$UsersRoot out=$OutRoot"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Log 'WARNING: not elevated; coverage limited to current user' }

# Enumerate users
if ($Users) {
  $userDirs = $Users | ForEach-Object { Get-Item -LiteralPath (Join-Path $UsersRoot $_) -ErrorAction SilentlyContinue }
} else {
  $skip = @('Public','Default','Default User','All Users')
  $userDirs = Get-ChildItem -LiteralPath $UsersRoot -Directory -ErrorAction SilentlyContinue |
              Where-Object { $skip -notcontains $_.Name }
}

foreach ($ud in $userDirs) {
  if (-not $ud) { continue }
  $u = $ud.Name
  Write-Log "user: $u"

  # ---- Chromium family (Default + 'Profile *') ----
  foreach ($b in $ChromiumRoots) {
    $broot = Join-Path $ud.FullName $b.root
    if (-not (Test-Path -LiteralPath $broot)) { continue }
    $profiles = Get-ChildItem -LiteralPath $broot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
    foreach ($prof in $profiles) {
      $srcDb = Join-Path $prof.FullName 'History'
      if (-not (Test-Path -LiteralPath $srcDb)) { continue }
      # archive-relative path mirrors the real root so FM-Browser regex matches
      $rel = "Users\$u\$($b.root)\$($prof.Name)\History"
      if (Copy-EvidenceDb -Src $srcDb -ArchiveRel $rel) {
        Write-Log "  $($b.name)/$($prof.Name) History"
        $script:CollectedUsers[$u] = $true
      }
      Collect-ProfilePayload -ProfileDir $prof.FullName -User $u -Browser $b.name -ProfileName $prof.Name
    }
    if ($Level -ge 2) {
      Add-Blob -Src (Join-Path $broot 'Local State') -User $u -Browser $b.name -Profile '' -Class 'l2_contact'
    }
  }

  # ---- New Teams (Packages\MSTeams_*) ----
  $pkgRoot = Join-Path $ud.FullName 'AppData\Local\Packages'
  if (Test-Path -LiteralPath $pkgRoot) {
    Get-ChildItem -LiteralPath $pkgRoot -Directory -Filter 'MSTeams_*' -ErrorAction SilentlyContinue | ForEach-Object {
      $pkgName = $_.Name
      $tBase = Join-Path $_.FullName 'LocalCache\Microsoft\MSTeams'
      Get-ChildItem -LiteralPath $tBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $profName = $_.Name
        $srcDb = Join-Path $_.FullName 'History'
        if (Test-Path -LiteralPath $srcDb) {
          $rel = "Users\$u\AppData\Local\Packages\$pkgName\LocalCache\Microsoft\MSTeams\$profName\History"
          if (Copy-EvidenceDb -Src $srcDb -ArchiveRel $rel) { Write-Log "  teams(new)/$profName History"; $script:CollectedUsers[$u] = $true }
        }
      }
    }
  }

  # ---- Firefox (every Profiles\* with places.sqlite) ----
  $ffRoot = Join-Path $ud.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles'
  if (Test-Path -LiteralPath $ffRoot) {
    Get-ChildItem -LiteralPath $ffRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $srcDb = Join-Path $_.FullName 'places.sqlite'
      if (Test-Path -LiteralPath $srcDb) {
        $rel = "Users\$u\AppData\Roaming\Mozilla\Firefox\Profiles\$($_.Name)\places.sqlite"
        if (Copy-EvidenceDb -Src $srcDb -ArchiveRel $rel) { Write-Log "  firefox/$($_.Name) places.sqlite"; $script:CollectedUsers[$u] = $true }
        if ($Level -ge 2) {
          foreach ($f in @('cookies.sqlite','formhistory.sqlite','logins.json','key4.db')) {
            Add-Blob -Src (Join-Path $_.FullName $f) -User $u -Browser 'firefox' -Profile $_.Name -Class 'l2_contact'
          }
        }
        if ($Level -ge 3) { Add-BlobTree -Dir (Join-Path $_.FullName 'storage') -User $u -Browser 'firefox' -Profile $_.Name -Class 'l3_client_state' }
      }
    }
  }
}

# ============================================================================
# metadata.json (documentation only — FM-Browser does NOT read it)
# ============================================================================
$meta = [ordered]@{
  collector_version    = $COLLECTOR_VERSION
  collection_timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  os_platform          = 'windows'
  endpoint_name        = $HostName
  hostname             = [System.Net.Dns]::GetHostName()
  level                = $Level
  os_usernames         = @($script:CollectedUsers.Keys)
  tool_versions        = @{ powershell = $PSVersionTable.PSVersion.ToString();
                            os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption }
  locked_db_strategy   = 'read-share copy; robocopy /b fallback; originals read-only'
  notes                = ''
}
$meta | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $Stage 'metadata.json') -Encoding UTF8

# ============================================================================
# SHA-256 manifest (excludes itself)
# ============================================================================
Write-Log 'Generating manifest'
$manifest = Join-Path $Stage 'manifest.sha256'
$prefixLen = $Stage.Length + 1
Get-ChildItem -LiteralPath $Stage -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -ne 'manifest.sha256' } | ForEach-Object {
    $rel = $_.FullName.Substring($prefixLen) -replace '\\','/'
    '{0}{1}{2}' -f $rel, "`t", (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
  } | Set-Content -Path $manifest -Encoding ASCII

# ============================================================================
# Zip (Compress-Archive writes forward-slash entries; no nested archives)
# ============================================================================
Write-Log "Creating $ZipPath"
if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $ZipPath -Force
if (Test-Path -LiteralPath $ZipPath) {
  Write-Log ("DONE: $ZipPath (sha256={0})" -f (Get-Sha256 -Path $ZipPath))
  Write-Output $ZipPath
} else {
  Write-Log 'ERROR: zip not created'; exit 1
}
