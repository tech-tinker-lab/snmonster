@echo off
echo === Network Admin System - Backend ===
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH.
    pause
    exit /b 1
)

echo Starting Network Admin Backend...
echo Backend will be available at: http://localhost:8001
echo API docs will be available at: http://localhost:8001/docs
echo.
echo Press Ctrl+C to stop the server
echo.

python run_backend.py

pause 