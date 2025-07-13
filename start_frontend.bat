@echo off
echo === Network Admin System - Frontend ===

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo Error: Node.js is not installed. Please install Node.js first.
    pause
    exit /b 1
)

REM Check if we're in the right directory
if not exist "frontend\package.json" (
    echo Error: package.json not found. Please run this script from the project root.
    pause
    exit /b 1
)

REM Change to frontend directory
cd frontend

REM Install dependencies
echo Installing frontend dependencies...
call npm install
if errorlevel 1 (
    echo Error: Failed to install dependencies.
    pause
    exit /b 1
)

REM Start the development server
echo Starting React development server...
echo Frontend will be available at: http://localhost:3001
echo.
call npm start

pause 