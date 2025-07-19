@echo off
REM Start Full Stack Network Admin System with Custom Ports

REM Set environment variables
set UVICORN_PORT=8004
set REACT_APP_API_URL=http://localhost:8004
set REACT_APP_WS_URL=ws://localhost:8004/ws

echo Starting Network Admin Full Stack System...
echo Backend Port: %UVICORN_PORT%
echo Frontend API URL: %REACT_APP_API_URL%
echo Frontend WS URL: %REACT_APP_WS_URL%
echo.

REM Start backend in background
echo Starting backend server...
start "Backend Server" cmd /k "python run_backend.py %UVICORN_PORT%"

REM Wait a moment for backend to start
timeout /t 3 /nobreak > nul

REM Start frontend
echo Starting frontend server...
cd frontend
set PORT=3004
start "Frontend Server" cmd /k "npm start"

echo.
echo Full stack system starting...
echo Backend: http://localhost:%UVICORN_PORT%
echo Frontend: http://localhost:3004
echo.
echo Press any key to exit...
pause > nul
