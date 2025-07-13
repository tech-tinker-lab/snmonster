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
echo.
echo Backend will be available at: http://localhost:8001
echo Frontend will be available at: http://localhost:3001
echo.
echo Press Ctrl+C to stop both services
echo.

REM Start backend in background
start "Network Admin Backend" cmd /k "python start_backend.py"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend
start "Network Admin Frontend" cmd /k "start_frontend.bat"

echo Both services are starting...
echo.
echo Backend: http://localhost:8001
echo Frontend: http://localhost:3001
echo API Docs: http://localhost:8001/docs
echo.
pause 