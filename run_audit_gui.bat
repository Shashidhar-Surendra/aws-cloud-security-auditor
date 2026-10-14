@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
    py launcher_gui.py
    exit /b %errorlevel%
)

where python >nul 2>&1
if %errorlevel%==0 (
    python launcher_gui.py
    exit /b %errorlevel%
)

echo Python 3.11 or newer was not found.
echo Install Python 3.11+ and run this launcher again.
pause
