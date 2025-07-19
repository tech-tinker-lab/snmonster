# Start Full Stack Network Admin System with Environment Variables

# Set environment variables
$env:UVICORN_PORT = "8004"
$env:REACT_APP_API_URL = "http://localhost:8004"
$env:REACT_APP_WS_URL = "ws://localhost:8004/ws"

Write-Host "Starting Network Admin Full Stack System..." -ForegroundColor Green
Write-Host "Backend Port: $($env:UVICORN_PORT)" -ForegroundColor Yellow
Write-Host "Frontend API URL: $($env:REACT_APP_API_URL)" -ForegroundColor Yellow
Write-Host "Frontend WS URL: $($env:REACT_APP_WS_URL)" -ForegroundColor Yellow
Write-Host ""

# Start backend in background
Write-Host "Starting backend server..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-Command", "python run_backend.py $($env:UVICORN_PORT)"

# Wait a moment for backend to start
Start-Sleep -Seconds 3

# Start frontend
Write-Host "Starting frontend server..." -ForegroundColor Cyan
Set-Location frontend
$env:PORT = "3004"
Start-Process powershell -ArgumentList "-Command", "npm start"

Write-Host ""
Write-Host "Full stack system starting..." -ForegroundColor Green
Write-Host "Backend: http://localhost:$($env:UVICORN_PORT)" -ForegroundColor Magenta
Write-Host "Frontend: http://localhost:3004" -ForegroundColor Magenta
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
