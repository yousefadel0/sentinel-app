<#
  Sentinel — one-click start (Windows PowerShell 5.1+).

    .\scripts\start.ps1                       # shadow mode, UI on 127.0.0.1:8080
    .\scripts\start.ps1 -Capture D:\logs      # folder holding eve.json / conn.log ...

  First run creates the virtual environment, installs the dependencies, copies
  config.example.yaml to config.yaml and creates a local access token
  (.sentinel-token). Nothing is ever executed on the network: enforcement needs
  an explicit --no-dry-run and autonomy_level >= 1 in config.yaml.
#>
param(
    [string]$Capture = "capture",
    [string]$Config  = "config.yaml"
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

function Fail($msg) { Write-Host "`nERROR: $msg" -ForegroundColor Red; exit 1 }

# 1) Python 3.9+ ---------------------------------------------------------------
$venvPy = Join-Path (Get-Location) ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    $py = $null
    foreach ($cand in @("py -3", "python", "python3")) {
        try {
            $ver = & cmd /c "$cand -c `"import sys;print('%d.%d'%sys.version_info[:2])`" 2>nul"
            if ($LASTEXITCODE -eq 0 -and $ver) {
                $maj, $min = $ver.Trim().Split(".")
                if ([int]$maj -eq 3 -and [int]$min -ge 9) { $py = $cand; break }
            }
        } catch { }
    }
    if (-not $py) { Fail "Python 3.9 or newer was not found. Install it from python.org (tick 'Add to PATH') and run this script again." }
    Write-Host "Creating virtual environment (first run only)..." -ForegroundColor Cyan
    & cmd /c "$py -m venv .venv"
    if ($LASTEXITCODE -ne 0) { Fail "Could not create the virtual environment." }
    Write-Host "Installing dependencies (first run only)..." -ForegroundColor Cyan
    & $venvPy -m pip install --quiet -e ".[ops-ui]"
    if ($LASTEXITCODE -ne 0) { Fail "Dependency installation failed. Check the internet connection and retry." }
}

# 2) Config -----------------------------------------------------------------------
if (-not (Test-Path $Config)) {
    Copy-Item "config.example.yaml" $Config
    Write-Host "Created $Config from config.example.yaml - review the asset IPs and thresholds." -ForegroundColor Yellow
}
# cmd /c keeps PowerShell 5.1 from turning the app's stderr log lines into errors
& cmd /c "`"$venvPy`" -m sentinel ctl config validate `"$Config`" >nul 2>&1"
if ($LASTEXITCODE -ne 0) {
    & cmd /c "`"$venvPy`" -m sentinel ctl config validate `"$Config`""
    Fail "$Config is not valid (see the message above)."
}

# 3) Folders ------------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path "data" | Out-Null
if (-not (Test-Path $Capture)) {
    New-Item -ItemType Directory -Force -Path $Capture | Out-Null
    Write-Host "Created empty capture folder '$Capture'. The sensors (Suricata eve.json, Zeek *.log) must write there." -ForegroundColor Yellow
}

# 4) Access token (never committed; kept next to the project) -------------------------------
$tokenFile = ".sentinel-token"
if ($env:SENTINEL_OPS_UI_TOKEN) {
    $token = $env:SENTINEL_OPS_UI_TOKEN
} elseif (Test-Path $tokenFile) {
    $token = (Get-Content $tokenFile -Raw).Trim()
} else {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $token = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+","-").Replace("/","_")
    Set-Content -Path $tokenFile -Value $token -NoNewline
}
$env:SENTINEL_OPS_UI_TOKEN = $token

# 5) Port check ------------------------------------------------------------------------------
$uiPort = 8080    # must match ops_ui.bind in the config
$busy = $false
try {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse("127.0.0.1"), $uiPort)
    $l.Start(); $l.Stop()
} catch { $busy = $true }
if ($busy) { Fail "Port $uiPort is already in use - an old Sentinel is probably running. Close its window (Ctrl+C) and run this script again." }

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Green
Write-Host " Sentinel is starting (SHADOW mode - nothing is executed on the network)" -ForegroundColor Green
Write-Host "  Dashboard : http://127.0.0.1:$uiPort/" -ForegroundColor Green
Write-Host "  Header    : X-Sentinel-Token: $token" -ForegroundColor Green
Write-Host "  Sensors   : $Capture" -ForegroundColor Green
Write-Host "  Stop      : Ctrl+C" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Write-Host ""

$args2 = @("-m", "sentinel", "--config", $Config, "run", "--ui", "--capture-dir", $Capture)
& $venvPy @args2
