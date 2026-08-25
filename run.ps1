# Log Masker launcher for Windows PowerShell.
#
# Thin wrapper around cli.py, which does the real work on every platform.
#
#   .\run.ps1 start [--open]    .\run.ps1 stop      .\run.ps1 restart
#   .\run.ps1 status            .\run.ps1 logs -f   .\run.ps1 url
#   .\run.ps1 where             # where data and secrets live on this OS
#
# $env:PORT = 9000; .\run.ps1 start   is honoured, matching run.sh.

$ErrorActionPreference = "Stop"
$AppDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $AppDir

# Prefer the project venv, then the py launcher, then python on PATH.
$VenvPython = Join-Path $AppDir ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $Python = $VenvPython
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $Python = "py"
    $PyArgs = @("-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $Python = "python"
} else {
    Write-Error "No Python found. Install Python 3.11+, then: py -3 -m venv .venv; .venv\Scripts\pip install -r requirements.lock"
    exit 1
}

$CliArgs = @($args)
if (($args.Count -gt 0) -and ($args[0] -in @("start", "restart")) -and $env:PORT) {
    $CliArgs += @("--port", $env:PORT)
}

if ($PyArgs) {
    & $Python @PyArgs cli.py @CliArgs
} else {
    & $Python cli.py @CliArgs
}
exit $LASTEXITCODE
