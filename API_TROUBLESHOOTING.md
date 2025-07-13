# API Troubleshooting Guide

## Issue: 404 Errors on API Endpoints

If you're seeing 404 errors like:
- `http://localhost:3001/api/devices` 404
- `http://localhost:3001/api/status` 404

## 🔍 Step-by-Step Debugging

### 1. Verify Backend is Running
```bash
# Check if backend is running on port 8001
curl http://localhost:8001/api/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "scanner_running": false,
  "ai_system_ready": true
}
```

### 2. Check Backend Logs
Look for any error messages in the backend console:
```bash
# Start backend and watch for errors
python run_backend.py
```

### 3. Test API Endpoints Directly
```bash
# Test devices endpoint
curl http://localhost:8001/api/devices

# Test scan status endpoint
curl http://localhost:8001/api/scan/status
```

### 4. Check Frontend API Configuration
The frontend should be using the API service with the correct base URL:

**File: `frontend/src/services/api.ts`**
```typescript
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8001',
  // ...
});
```

### 5. Verify Proxy Configuration
**File: `frontend/package.json`**
```json
{
  "proxy": "http://localhost:8001"
}
```

## 🛠️ Common Solutions

### Solution 1: Restart Both Services
```bash
# Terminal 1: Backend
python run_backend.py

# Terminal 2: Frontend
cd frontend
start_port_3001.bat
```

### Solution 2: Clear Browser Cache
- Open browser in incognito mode
- Or clear browser cache and reload

### Solution 3: Check Port Conflicts
```bash
# Windows
netstat -an | findstr :8001
netstat -an | findstr :3001

# Linux/macOS
netstat -an | grep :8001
netstat -an | grep :3001
```

### Solution 4: Use Direct API Calls
If proxy isn't working, the frontend will use the full URL:
```typescript
// This should work even if proxy fails
baseURL: 'http://localhost:8001'
```

## 🔧 Manual Testing

### Test Backend API
```bash
# Health check
curl http://localhost:8001/api/health

# Get devices
curl http://localhost:8001/api/devices

# Get scan status
curl http://localhost:8001/api/scan/status

# Start scan
curl -X POST http://localhost:8001/api/scan/start
```

### Test Frontend API Service
Open browser console (F12) and run:
```javascript
// Test the API service directly
fetch('http://localhost:8001/api/health')
  .then(response => response.json())
  .then(data => console.log('Health:', data))
  .catch(error => console.error('Error:', error));
```

## 📋 Expected API Endpoints

The backend should provide these endpoints:

- `GET /api/health` - System health check
- `GET /api/devices` - List all devices
- `GET /api/devices/{id}` - Get specific device
- `GET /api/scan/status` - Get scan status
- `POST /api/scan/start` - Start network scan
- `POST /api/scan/stop` - Stop network scan
- `POST /api/ai/analyze` - AI network analysis
- `POST /api/ai/recommendations` - AI recommendations

## 🚨 If Backend Won't Start

1. **Check Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Check for port conflicts**:
   ```bash
   # Kill process on port 8001
   netstat -ano | findstr :8001
   taskkill /PID <PID> /F
   ```

3. **Check database initialization**:
   ```bash
   # The backend should create the database automatically
   # Look for any database errors in the logs
   ```

## 📞 Next Steps

If you're still having issues:

1. **Check the browser console** (F12) for detailed error messages
2. **Check the backend console** for any startup errors
3. **Use the API test component** in the dashboard to debug
4. **Try accessing the API directly** at http://localhost:8001/docs

The API documentation will be available at: http://localhost:8001/docs 