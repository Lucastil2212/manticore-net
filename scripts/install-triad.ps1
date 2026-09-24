# Install TRIAD Soccer local client on Windows.
# Usage (PowerShell):
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\scripts\install-triad.ps1
#
# Optional:
#   $env:TRIAD_HOME = "$env:USERPROFILE\triad-soccer"
#   $env:TRIAD_CDN  = "https://glyphgrid.online"

param(
  [string]$Prefix = $(if ($env:TRIAD_HOME) { $env:TRIAD_HOME } else { Join-Path $env:USERPROFILE "triad-soccer" }),
  [string]$Base = $(if ($env:TRIAD_CDN) { $env:TRIAD_CDN } else { "https://glyphgrid.online" })
)

$ErrorActionPreference = "Stop"

$ZipName = "triad-soccer-win-x64.zip"
$Url = "$Base/downloads/triad/$ZipName"
$ManifestUrl = "$Base/downloads/triad/latest.json"

Write-Host "TRIAD Soccer · Windows install"
Write-Host "  dest=$Prefix"

try {
  $manifest = Invoke-RestMethod -Uri $ManifestUrl -TimeoutSec 15
  if ($manifest.downloads.'win-x64') {
    $rel = [string]$manifest.downloads.'win-x64'
    if ($rel -match '^https?://') { $Url = $rel }
    elseif ($rel.StartsWith('/')) { $Url = "$Base$rel" }
    else { $Url = "$Base/downloads/triad/$rel" }
  }
} catch {
  # Keep default URL
}

Write-Host "  url=$Url"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("triad-install-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $zipPath = Join-Path $tmp "triad.zip"
  Invoke-WebRequest -Uri $Url -OutFile $zipPath -UseBasicParsing

  $out = Join-Path $tmp "out"
  Expand-Archive -Path $zipPath -DestinationPath $out -Force

  $index = Get-ChildItem -Path $out -Recurse -Filter "index.html" | Select-Object -First 1
  if (-not $index) { throw "Downloaded zip has no index.html" }
  $src = $index.Directory.FullName

  if (Test-Path $Prefix) {
    Remove-Item -Path $Prefix -Recurse -Force
  }
  New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
  Copy-Item -Path (Join-Path $src "*") -Destination $Prefix -Recurse -Force

  $repoLink = Join-Path (Split-Path $PSScriptRoot -Parent) "triad-soccer"
  if (Test-Path $repoLink) { Remove-Item $repoLink -Force -Recurse -ErrorAction SilentlyContinue }
  try {
    New-Item -ItemType Junction -Path $repoLink -Target $Prefix -ErrorAction SilentlyContinue | Out-Null
  } catch { }

  Write-Host "✓ TRIAD Soccer ready at $Prefix"
  Write-Host "  Run:  $Prefix\scripts\run-windows.bat"
  Write-Host "  Online: https://glyphgrid.online/apps/triad/"
  Write-Host "  Downloads: https://glyphgrid.online/downloads/"
} finally {
  Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
