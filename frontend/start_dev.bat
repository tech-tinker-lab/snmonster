@echo off
echo === Network Admin Frontend - Development Start ===
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo Error: Node.js is not installed or not in PATH.
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo Node.js found. Installing dependencies...
echo.

REM Install dependencies
call npm install
if errorlevel 1 (
    echo Error: Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo Dependencies installed successfully!
echo Starting React development server...
echo.
echo Frontend will be available at: http://localhost:3001
echo.
echo Press Ctrl+C to stop the server
echo.

call npm start

pause 