# 🚀 Network Admin System - Startup Guide

## 🔧 **Quick Fix for API Issues**

### **Problem**: API not responding on http://localhost:8001/api/devices

### **Solution Steps**:

1. **Install Dependencies**:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

2. **Set Correct Network Range**:
   ```bash
   cd backend
   python set_network_range.py
   ```
   This will help you select the correct network interface (not VirtualBox/Hyper-V).

3. **Start the Backend**:
   ```bash
   # From project root
   python run_backend.py
   ```
   Or use the startup script:
   ```bash
   python start_backend.py
   ```

4. **Test the API**:
   ```bash
   cd backend
   python test_api.py
   ```

## 📋 **Complete Setup Instructions**

### **Step 1: Environment Setup**
```bash
# Navigate to project directory
cd C:\projects\snmonster

# Install Python dependencies
pip install -r backend/requirements.txt
```

### **Step 2: Configure Network Scanning**
```bash
# Run network configuration tool
cd backend
python set_network_range.py
```
This will:
- Show all available network interfaces
- Help you select the correct local network
- Skip virtual machine networks (VirtualBox/Hyper-V)
- Save the configuration

### **Step 3: Initialize Database**
```bash
# Add sample devices (optional)
cd backend
python add_sample_devices.py

# Add sample registry data (optional)
python add_sample_registry_data.py
```

### **Step 4: Start the Backend Server**
```bash
# From project root
python run_backend.py
```

**Expected Output**:
```
Starting Network Admin Backend...
Backend will be available at: http://localhost:8001
API docs will be available at: http://localhost:8001/docs
Press Ctrl+C to stop the server

INFO:     Started server process [1234]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
```

### **Step 5: Test the API**
```bash
# Test all endpoints
cd backend
python test_api.py
```

**Or test manually**:
- **Health Check**: http://localhost:8001/api/health
- **Devices**: http://localhost:8001/api/devices
- **Registry Overview**: http://localhost:8001/api/registry/overview
- **API Documentation**: http://localhost:8001/docs

## 🔍 **Troubleshooting**

### **Issue 1: "No response at all" from API**
**Causes**:
- Server not running
- Wrong port
- Dependencies not installed
- Database initialization failed

**Solutions**:
1. Check if server is running: `netstat -an | findstr 8001`
2. Install dependencies: `pip install -r backend/requirements.txt`
3. Check logs for errors
4. Restart the server

### **Issue 2: Wrong Network Range (192.168.56.0/24)**
**Cause**: Detecting VirtualBox/Hyper-V network instead of local network

**Solution**:
```bash
cd backend
python set_network_range.py
# Select your actual local network (e.g., 192.168.1.0/24)
```

### **Issue 3: Database Errors**
**Solution**:
```bash
cd backend
# Reinitialize database
python -c "from database import init_db; import asyncio; asyncio.run(init_db())"
```

### **Issue 4: Import Errors**
**Solution**:
```bash
# Make sure you're in the backend directory
cd backend
# Or add backend to Python path
set PYTHONPATH=%PYTHONPATH%;C:\projects\snmonster\backend
```

## 🌐 **API Endpoints Reference**

### **Core Endpoints**
- `GET /` - Root endpoint with API info
- `GET /api/health` - Health check and system status
- `GET /api/devices` - List all discovered devices
- `GET /api/devices/{id}` - Get specific device details

### **Registry Endpoints**
- `GET /api/registry/overview` - Complete registry overview
- `GET /api/registry/boundaries` - List virtual boundaries
- `GET /api/registry/namespaces` - List namespaces
- `GET /api/registry/nodes` - List nodes
- `GET /api/registry/pods` - List service pods

### **Network Management**
- `POST /api/scan/start` - Start network scan
- `POST /api/scan/stop` - Stop network scan
- `GET /api/scan/status` - Get scan status

### **AI Features**
- `POST /api/ai/analyze` - AI network analysis
- `POST /api/ai/recommendations` - Get AI recommendations

## 📊 **System Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend API   │    │   Database      │
│   (React)       │◄──►│   (FastAPI)     │◄──►│   (SQLite)      │
│   Port 3000     │    │   Port 8001     │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Network       │
                       │   Scanner       │
                       │   (Discovery)   │
                       └─────────────────┘
```

## 🎯 **Quick Start Commands**

```bash
# 1. Install dependencies
pip install -r backend/requirements.txt

# 2. Configure network
cd backend && python set_network_range.py

# 3. Start server
python run_backend.py

# 4. Test API
cd backend && python test_api.py

# 5. Open in browser
start http://localhost:8001/docs
```

## 📝 **Configuration Files**

- **`.env`** - Environment variables (auto-created by set_network_range.py)
- **`backend/config.py`** - Application configuration
- **`backend/requirements.txt`** - Python dependencies
- **`network_admin.db`** - SQLite database (auto-created)

## 🆘 **Getting Help**

If you encounter issues:

1. **Check the logs** in `network_admin.log`
2. **Run the test script**: `python backend/test_api.py`
3. **Verify network configuration**: `python backend/set_network_range.py`
4. **Check server status**: http://localhost:8001/api/health

## ✅ **Success Indicators**

When everything is working correctly, you should see:

- ✅ Server running on port 8001
- ✅ Health check returns "healthy" status
- ✅ Network scanner detecting correct network range
- ✅ API endpoints responding with data
- ✅ Database initialized with tables
- ✅ CORS working for frontend integration 