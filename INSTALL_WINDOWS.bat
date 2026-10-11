@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Install Python 3.12 from python.org, then run this file again.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3.12 -m venv .venv
  if errorlevel 1 (
    echo Python 3.12 is required for the tested environment.
    pause
    exit /b 1
  )
)
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Check the connection and error above.
  pause
  exit /b 1
)
.venv\Scripts\python.exe main.py --train-model
if errorlevel 1 (
  echo Model setup failed. See the error above.
  pause
  exit /b 1
)
echo.
echo Setup complete. Double-click START_WINDOWS.bat to open AegisNet.
pause
