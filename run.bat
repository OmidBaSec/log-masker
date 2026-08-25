@echo off
rem Log Masker launcher for cmd.exe. Thin wrapper around cli.py, which does the
rem real work on every platform.
rem
rem   run.bat start [--open]    run.bat stop     run.bat restart
rem   run.bat status            run.bat logs     run.bat url
rem   run.bat where

setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    set "PYTHON=.venv\Scripts\python.exe"
) else (
    where py >nul 2>&1 && (set "PYTHON=py -3") || (set "PYTHON=python")
)

%PYTHON% cli.py %*
exit /b %ERRORLEVEL%
