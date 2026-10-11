@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run INSTALL_WINDOWS.bat once before starting the dashboard.
  pause
  exit /b 1
)
echo Open http://127.0.0.1:5000 in your browser after the server starts.
echo Keep this terminal open. Press Ctrl+C here to stop the server.
.venv\Scripts\python.exe run_dashboard.py
if errorlevel 1 pause
