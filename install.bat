@echo off
echo === Network Admin System - Installation ===
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH.
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo Python found. Installing dependencies...
echo.

REM Upgrade pip first
echo Upgrading pip...
python -m pip install --upgrade pip

REM Try to install minimal requirements first
echo Installing minimal dependencies...
python -m pip install -r requirements-minimal.txt
if errorlevel 1 (
    echo.
    echo Minimal installation failed. Trying individual packages...
    echo.
    
    REM Install core packages individually
    python -m pip install fastapi
    python -m pip install "uvicorn[standard]"
    python -m pip install sqlalchemy
    python -m pip install pydantic
    python -m pip install scapy
    python -m pip install python-nmap
    python -m pip install psutil
    python -m pip install websockets
    python -m pip install python-dotenv
    python -m pip install aiofiles
    python -m pip install httpx
    python -m pip install schedule
)

echo.
echo Checking for Nmap...
nmap --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo Warning: Nmap is not installed or not in PATH.
    echo For full functionality, please install Nmap from https://nmap.org/download.html
    echo The application will work with limited scanning capabilities.
    echo.
)

echo.
echo Installation completed!
echo.
echo To start the application:
echo 1. Run: run.bat
echo 2. Or start backend: python start_backend.py
echo 3. Or start frontend: start_frontend.bat
echo.
pause 