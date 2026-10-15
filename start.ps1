# SecureAudit AI — one-click UI (run: right-click -> Run with PowerShell, or: powershell -ExecutionPolicy Bypass -File .\start.ps1)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$pyLauncher = Get-Command py -ErrorAction SilentlyContinue

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment..."
    if ($pyLauncher) {
        & py -3 -m venv .venv
    } else {
        & python -m venv .venv
    }
}

Write-Host "Installing / updating SecureAudit AI..."
& .\.venv\Scripts\pip.exe install -q -e .

Write-Host ""
Write-Host "Starting dashboard at http://127.0.0.1:8750"
Write-Host "Press Ctrl+C to stop."
Write-Host ""

$p = Start-Process -FilePath ".\.venv\Scripts\python.exe" `
    -ArgumentList @(
        "-m", "uvicorn", "secureaudit.webapp:app",
        "--host", "127.0.0.1", "--port", "8750"
    ) -PassThru -NoNewWindow

Start-Sleep -Seconds 2
Start-Process "http://127.0.0.1:8750/"

Wait-Process -Id $p.Id
