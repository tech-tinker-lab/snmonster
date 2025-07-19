# Environment Variable Configuration

This document explains how to configure the Network Admin System using environment variables.

## Backend Environment Variables

### Port Configuration
- `UVICORN_PORT`: Set the backend server port (default: 8001)
- `UVICORN_HOST`: Set the backend host (default: 0.0.0.0)

### Example:
```bash
# Windows Command Prompt
set UVICORN_PORT=8004
python run_backend.py

# Windows PowerShell
$env:UVICORN_PORT = "8004"
python run_backend.py

# Linux/Mac
export UVICORN_PORT=8004
python run_backend.py
```

## Frontend Environment Variables

### Configuration Files
The frontend uses `.env` files for configuration:

- `.env` - Default configuration
- `.env.development` - Development environment (used by `npm start`)
- `.env.production` - Production environment (used by `npm run build`)

### Available Variables
- `REACT_APP_API_URL`: Backend API URL (default: http://localhost:8001)
- `REACT_APP_WS_URL`: WebSocket URL (default: ws://localhost:8001/ws)
- `PORT`: Frontend development server port (default: 3000)

### Example Configuration Files

#### `.env.development`
```
REACT_APP_API_URL=http://localhost:8004
REACT_APP_WS_URL=ws://localhost:8004/ws
```

#### `.env.production`
```
REACT_APP_API_URL=https://your-production-domain.com
REACT_APP_WS_URL=wss://your-production-domain.com/ws
```

## Quick Start Scripts

### Option 1: Use the provided batch file (Windows)
```cmd
start_fullstack_env.bat
```

### Option 2: Use the provided PowerShell script (Windows)
```powershell
.\start_fullstack_env.ps1
```

### Option 3: Manual setup

#### Backend:
```bash
# Set backend port
set UVICORN_PORT=8004  # Windows CMD
# or
$env:UVICORN_PORT = "8004"  # Windows PowerShell

# Start backend
python run_backend.py
```

#### Frontend:
```bash
# Navigate to frontend directory
cd frontend

# Set frontend port
set PORT=3004  # Windows CMD
# or
$env:PORT = "3004"  # Windows PowerShell

# Start frontend
npm start
```

## Runtime Environment Variables

When you run `python run_backend.py`, the following environment variables are automatically set:

- `SERVER_URL`: Complete server URL
- `BACKEND_URL`: Backend API URL
- `API_BASE_URL`: API base URL
- `REACT_APP_API_URL`: Frontend API URL
- `REACT_APP_WS_URL`: Frontend WebSocket URL

These variables are available to any process started after the backend and can be used by other scripts or applications.

## Custom Port Configuration

To run both servers on custom ports:

```bash
# Set environment variables
set UVICORN_PORT=8004
set REACT_APP_API_URL=http://localhost:8004
set REACT_APP_WS_URL=ws://localhost:8004/ws
set PORT=3004

# Start backend
python run_backend.py

# Start frontend (in another terminal)
cd frontend
npm start
```

## Production Deployment

For production deployment, update `.env.production`:

```
REACT_APP_API_URL=https://your-production-domain.com
REACT_APP_WS_URL=wss://your-production-domain.com/ws
```

Then build the frontend:
```bash
cd frontend
npm run build
```

The built files will be in the `frontend/build` directory and can be served by any static file server.
