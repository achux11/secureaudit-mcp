@echo off
setlocal ENABLEDELAYEDEXPANSION
cd /d "%~dp0"

where py >nul 2>&1
if %ERRORLEVEL%==0 (
  set "PY=py -3"
) else (
  set "PY=python"
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  %PY% -m venv .venv
  if errorlevel 1 goto :err
)

echo Installing / updating SecureAudit AI...
".venv\Scripts\pip.exe" install -q -e .
if errorlevel 1 goto :err

echo.
echo Opening http://127.0.0.1:8750 in your browser (wait a few seconds if the page errors, then refresh).
echo Press Ctrl+C here to stop the server.
echo.

start "" cmd /c "ping -n 4 127.0.0.1 ^>nul && start http://127.0.0.1:8750/"

".venv\Scripts\python.exe" -m uvicorn secureaudit.webapp:app --host 127.0.0.1 --port 8750
if errorlevel 1 goto :err
goto :eof

:err
echo.
echo Something went wrong. Ensure Python 3.10+ is installed and on PATH.
pause
exit /b 1
