# Install the single binary CLI on Windows from a GitHub release and check its SHA-256 first.
#
#   irm https://raw.githubusercontent.com/aniruddhaadak80/re/main/install.ps1 | iex
#   & ([scriptblock]::Create((irm .../install.ps1))) -Version 1.2.0 -Dir "$env:LOCALAPPDATA\Programs\bin"
#
# Parameters (or environment variables): -Version (INSTALL_VERSION), -Dir (INSTALL_DIR),
# -Repo (INSTALL_REPO), -Alias (INSTALL_ALIASES, space separated), -DryRun. INSTALL_BASE_URL replaces
# https://github.com/<repo>/releases. The binary name is read from the release SHA256SUMS file, whose
# entries are named <bin>-windows-<arch>.exe, so it is not fixed in this script.
[CmdletBinding()]
param(
  [string]$Version = $env:INSTALL_VERSION,
  [string]$Dir = $(if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\bin' }),
  [string]$Repo = $(if ($env:INSTALL_REPO) { $env:INSTALL_REPO } else { 'aniruddhaadak80/re' }),
  [string[]]$Alias = $(if ($env:INSTALL_ALIASES) { $env:INSTALL_ALIASES -split '\s+' | Where-Object { $_ } } else { @() }),
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

function Fail([string]$m) { throw "install failed: $m" }

if ($Repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { Fail 'Repo must look like owner/name' }
if ($Version -and $Version -notmatch '^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$') { Fail 'Version must look like 1.2.3' }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'x64' } 'ARM64' { 'arm64' } default { Fail "no binary is published for CPU $($env:PROCESSOR_ARCHITECTURE)" } }
$base = if ($env:INSTALL_BASE_URL) { $env:INSTALL_BASE_URL.TrimEnd('/') } else { "https://github.com/$Repo/releases" }
$url = if ($Version) { $tag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }; "$base/download/$tag" } else { "$base/latest/download" }

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $sums = Join-Path $tmp 'SHA256SUMS'
  Invoke-WebRequest -UseBasicParsing -Uri "$url/SHA256SUMS" -OutFile $sums
  $line = Get-Content $sums | Where-Object { $_ -match "^[0-9a-f]{64}  [A-Za-z0-9._-]+-windows-$arch\.exe$" } | Select-Object -First 1
  if (-not $line) { Fail "the release has no binary for windows-$arch" }
  $want = $line.Substring(0, 64)
  $asset = $line.Substring(66)
  $bin = $asset -replace "-windows-$arch\.exe$", ''
  if (-not $bin -or $bin.StartsWith('.')) { Fail "unexpected asset name $asset" }
  Write-Host "installing $bin ($asset) from $url into $Dir"
  if ($DryRun) { Write-Host "dry run: would download $url/$asset, check sha256 $want, and write $Dir\$bin.exe"; return }

  $file = Join-Path $tmp $asset
  Invoke-WebRequest -UseBasicParsing -Uri "$url/$asset" -OutFile $file
  $got = (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLowerInvariant()
  if ($got -ne $want) { Fail "sha256 mismatch for ${asset}: expected $want, got $got. Nothing was installed." }
  Write-Host "sha256 ok: $got"

  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $dest = Join-Path $Dir "$bin.exe"
  Move-Item -Force -Path $file -Destination $dest
  foreach ($a in $Alias) {
    if ($a -notmatch '^[A-Za-z0-9_-]+$') { Fail "bad alias name $a" }
    Copy-Item -Force -Path $dest -Destination (Join-Path $Dir "$a.exe")
  }
  $v = & $dest --version
  Write-Host "installed $bin $v at $dest"
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not ($userPath -split ';' | Where-Object { $_ -eq $Dir })) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $Dir).TrimStart(';'), 'User')
    Write-Host "added $Dir to your user PATH; open a new terminal to use $bin"
  }
} finally {
  Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
