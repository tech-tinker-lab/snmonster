@echo off
echo === Network Admin System - Full Stack Startup ===
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH.
    pause
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo Error: Node.js is not installed or not in PATH.
    pause
    exit /b 1
)

echo Starting Network Admin System...
echo This will install dependencies and start both backend and frontend.
echo.
echo Backend will be available at: http://localhost:8001
echo Frontend will be available at: http://localhost:3001
echo.
echo Press Ctrl+C to stop all services
echo.

python start_full_stack.py

pause 