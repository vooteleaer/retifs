# Builds retifs-setup-<version>.exe: retifs for Windows in one installer.
#
#     powershell -ExecutionPolicy Bypass -File packaging\windows\build-setup.ps1 [-Out DIR]
#
# Needs Rust (MSVC), Prns 0.3.8 next to retifs (..\Prns-0.3.8, or $env:PRNS),
# and retifs-desktop next to it (..\retifs-desktop, or $env:RETIFS_DESKTOP)
# for the utility in the notification area; without it the installer has
# no utility, and nothing starts retifs at login.
param([string]$Out = "")

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$Prns = if ($env:PRNS) { $env:PRNS } else { Join-Path (Split-Path $Root) "Prns-0.3.8" }
$Desktop = if ($env:RETIFS_DESKTOP) { $env:RETIFS_DESKTOP } else { Join-Path (Split-Path $Root) "retifs-desktop" }
if (-not $Out) { $Out = Join-Path $Root "target\setup" }
$Stage = Join-Path $Root "target\setup-files"
# A target folder of its own: programs running from target\release (a test
# node) can't be overwritten, and aren't.
$env:CARGO_TARGET_DIR = Join-Path $Root "target\setup-build"
$Built = "$env:CARGO_TARGET_DIR\release"

function Step($what) { Write-Host "== $what" }
function Invoke-Cargo { & cargo.exe @args; if ($LASTEXITCODE -ne 0) { throw "cargo $args failed" } }

Step "retifs"
Invoke-Cargo build --release --locked --manifest-path "$Root\Cargo.toml" -p retifs-node -p retifs-cloudfiles
Step "prnsd (Prns, from $Prns)"
Invoke-Cargo build --release --locked --manifest-path "$Prns\prnsd\Cargo.toml" --no-default-features --features "tokio-host,observability"
$HasDesktop = Test-Path "$Desktop\windows\Cargo.toml"
if ($HasDesktop) {
    Step "retifs-desktop (from $Desktop)"
    Invoke-Cargo build --release --manifest-path "$Desktop\Cargo.toml" -p retifs-desktop-win
} else {
    Write-Warning "no retifs-desktop at ${Desktop}: the installer won't have the utility"
}

Step "files"
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Force $Stage | Out-Null
foreach ($b in "retifsd.exe", "retifs.exe", "retifs-cloudfiles.exe", "prnsd.exe") { Copy-Item "$Built\$b" $Stage }
if ($HasDesktop) { Copy-Item "$Built\retifs-desktop.exe" $Stage }
Copy-Item "$Root\LICENSE" "$Stage\LICENSE-retifs.txt"
Copy-Item "$Prns\LICENSE-MIT" "$Stage\LICENSE-prns-MIT.txt"
Copy-Item "$Prns\LICENSE-APACHE" "$Stage\LICENSE-prns-APACHE.txt"
Get-ChildItem $Stage | ForEach-Object { "   {0,-28} {1,8:N0} KB" -f $_.Name, ($_.Length / 1KB) }

Step "installer"
$env:RETIFS_SETUP_FILES = $Stage
Invoke-Cargo build --release --manifest-path "$PSScriptRoot\setup\Cargo.toml"
Remove-Item Env:RETIFS_SETUP_FILES
$Version = (Select-String -Path "$Root\crates\retifs-node\Cargo.toml" -Pattern '^version = "(.*)"').Matches[0].Groups[1].Value
$Commit = (& git -C $Root rev-parse --short HEAD)
New-Item -ItemType Directory -Force $Out | Out-Null
$Setup = Join-Path $Out "retifs-setup-$Version-$Commit.exe"
Copy-Item "$Built\retifs-setup.exe" $Setup
"== $Setup ({0:N1} MB)" -f ((Get-Item $Setup).Length / 1MB)
