# Network Admin System - Startup Guide

## 🚀 Quick Start

### Step 1: Start the Backend
```bash
# Option A: Use the simple runner
python run_backend.py

# Option B: Use the batch file (Windows)
start_backend_simple.bat
```

**Expected Output:**
```
Starting Network Admin Backend...
Backend will be available at: http://localhost:8001
API docs will be available at: http://localhost:8001/docs
```

### Step 2: Start the Frontend
```bash
# Option A: Use the new port-specific script (Windows)
cd frontend
start_port_3001.bat

# Option B: Manual start with environment variable
cd frontend
set PORT=3001 && npm start

# Option C: Use the regular script (may need to set PORT manually)
cd frontend
start_dev.bat
```

**Expected Output:**
```
Starting React development server on port 3001...
Frontend will be available at: http://localhost:3001
```

### Step 3: Access the Application
- **Frontend Dashboard**: http://localhost:3001
- **Backend API**: http://localhost:8001
- **API Documentation**: http://localhost:8001/docs

## 🎯 What You Should See

### Full Dashboard Features
- **Navigation Sidebar** with menu items:
  - Dashboard
  - Devices
  - Network Scan
  - Security Analysis
  - AI Recommendations
  - Settings

- **Dashboard Page** with:
  - Network statistics cards
  - Device overview
  - Security status
  - Recent activity
  - Scan controls

- **Dark Theme** with professional styling

## 🔧 Troubleshooting

### If you still see "🎉 React is Working!"
1. **Stop the frontend** (Ctrl+C)
2. **Clear browser cache** or open in incognito mode
3. **Restart the frontend** using the port-specific script:
   ```bash
   cd frontend
   start_port_3001.bat
   ```

### If the backend fails to start
1. **Check if port 8001 is available**:
   ```bash
   netstat -an | findstr :8001
   ```
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### If the frontend fails to start
1. **Check if port 3001 is available**:
   ```bash
   netstat -an | findstr :3001
   ```
2. **Install dependencies**:
   ```bash
   cd frontend
   npm install
   ```

### If you see API errors
1. **Make sure the backend is running** on port 8001
2. **Check the browser console** (F12) for error messages
3. **Verify the API proxy** in `frontend/package.json` points to `http://localhost:8001`

## 📱 Alternative Startup Methods

### Full Stack Startup (Recommended)
```bash
python start_full_stack.py
```
This will start both backend and frontend automatically.

### Windows Batch Files
```bash
# Start both services
run.bat

# Or start individually
start_backend_simple.bat
start_frontend.bat
```

## 🎨 Features Available

Once running, you'll have access to:

1. **Dashboard**: Network overview and statistics
2. **Device Management**: View and manage network devices
3. **Network Scanning**: Start/stop network discovery
4. **Security Analysis**: View security reports and vulnerabilities
5. **AI Recommendations**: Get intelligent suggestions
6. **Settings**: Configure system preferences

## 🔄 Next Steps

After the system is running:
1. **Start a network scan** from the Dashboard
2. **Explore the Devices page** to see discovered devices
3. **Check Security Analysis** for vulnerability reports
4. **Review AI Recommendations** for optimization suggestions

The system will automatically discover devices on your network and provide real-time monitoring and analysis! 