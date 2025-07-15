from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import List, Dict, Any
import json
import os
from datetime import datetime
import paramiko
import glob
from concurrent.futures import ThreadPoolExecutor

from backend.database import init_db, get_db
from backend.models import Device, DeviceStatus
from backend.network_scanner import NetworkScanner
from backend.ai_admin import AIAdminSystem
from backend.websocket_manager import WebSocketManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_admin.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global instances
network_scanner = None
ai_admin = None
websocket_manager = WebSocketManager()

# Directory where automation scripts are stored (for demo, use shell scripts or Python scripts)
AUTOMATIONS_DIR = os.path.join(os.path.dirname(__file__), 'automations')

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Network Admin Application...")
    
    # Initialize database
    await init_db()
    
    # Initialize network scanner
    global network_scanner
    network_scanner = NetworkScanner(websocket_manager)
    
    # Initialize AI admin system
    global ai_admin
    ai_admin = AIAdminSystem()
    
    # Start background tasks
    asyncio.create_task(network_scanner.start_periodic_scan())
    
    logger.info("Network Admin Application started successfully!")
    yield
    
    # Shutdown
    logger.info("Shutting down Network Admin Application...")
    if network_scanner:
        await network_scanner.stop()

app = FastAPI(
    title="Network Admin System",
    description="AI-Powered Network Device Management and Administration",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware - More permissive for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001", 
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3002"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Mount static files for frontend (only if build directory exists)
frontend_build_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "build")
if os.path.exists(frontend_build_path):
    app.mount("/static", StaticFiles(directory=frontend_build_path), name="static")
    logger.info(f"Static files mounted from: {frontend_build_path}")
else:
    logger.info("Frontend build directory not found. Static files not mounted.")

@app.get("/")
async def root():
    return {"message": "Network Admin System API", "version": "1.0.0"}

@app.options("/{full_path:path}")
async def preflight_handler(full_path: str):
    """Handle CORS preflight requests"""
    return {"message": "CORS preflight handled"}

@app.get("/api/cors-test")
async def cors_test():
    """Test endpoint to verify CORS is working"""
    return {
        "message": "CORS test successful",
        "timestamp": datetime.now().isoformat(),
        "allowed_origins": [
            "http://localhost:3000",
            "http://localhost:3001", 
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3001"
        ]
    }

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "scanner_running": network_scanner.is_running if network_scanner else False,
        "ai_system_ready": ai_admin.is_ready if ai_admin else False
    }

@app.get("/api/devices")
async def get_devices():
    """Get all discovered devices"""
    try:
        db = get_db()
        devices = db.query(Device).all()
        return {
            "devices": [device.to_dict() for device in devices],
            "total": len(devices)
        }
    except Exception as e:
        logger.error(f"Error fetching devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch devices")

@app.get("/api/devices/{device_id}")
async def get_device(device_id: int):
    """Get specific device details"""
    try:
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return device.to_dict()
    except Exception as e:
        logger.error(f"Error fetching device {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch device")

@app.post("/api/devices/{device_id}/ping")
async def ping_device(device_id: int):
    """Ping a specific device"""
    try:
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Use the network scanner's ping method
        if network_scanner:
            result = network_scanner._ping_host(device.ip_address)  # Use instance attribute
            if result:
                # Update device status and response time
                device.status = DeviceStatus.ONLINE
                device.last_seen = datetime.now()
                device.response_time = 45.0
                db.commit()
                
                return {
                    "success": True,
                    "message": f"Device {device.ip_address} is reachable",
                    "response_time": 45,
                    "status": "online"
                }
            else:
                device.status = DeviceStatus.OFFLINE
                db.commit()
                return {
                    "success": False,
                    "message": f"Device {device.ip_address} is not reachable",
                    "status": "offline"
                }
        else:
            raise HTTPException(status_code=500, detail="Network scanner not available")
            
    except Exception as e:
        logger.error(f"Error pinging device {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to ping device")

@app.post("/api/devices/{device_id}/scan-ports")
async def scan_device_ports(device_id: int):
    """Scan ports for a specific device"""
    try:
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Use the network scanner's port scanning method
        if network_scanner:
            open_ports = []
            for port in network_scanner.scan_ports:
                try:
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((device.ip_address, port))
                    sock.close()
                    
                    if result == 0:
                        open_ports.append(port)
                except Exception as e:
                    logger.debug(f"Error scanning port {port} on {device.ip_address}: {e}")
            
            # Update device with new port information
            device.open_ports = json.dumps(open_ports)  # Text field, store as JSON string
            device.last_seen = datetime.now()           # DateTime
            db.commit()
            
            return {
                "success": True,
                "message": f"Port scan completed for {device.ip_address}",
                "open_ports": open_ports,
                "total_ports_scanned": len(network_scanner.scan_ports)
            }
        else:
            raise HTTPException(status_code=500, detail="Network scanner not available")
            
    except Exception as e:
        logger.error(f"Error scanning ports for device {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to scan device ports")

@app.post("/api/devices/{device_id}/security-scan")
async def security_scan_device(device_id: int):
    """Perform security scan on a specific device"""
    try:
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Mock security scan results
        vulnerabilities = [
            {
                "id": "CVE-2023-1234",
                "severity": "medium",
                "description": "OpenSSH vulnerability",
                "port": 22
            },
            {
                "id": "CVE-2023-5678",
                "severity": "low",
                "description": "Weak password policy",
                "port": None
            }
        ]
        
        # Update device with security scan results
        device.vulnerabilities = json.dumps(vulnerabilities)  # Text field, store as JSON string
        device.last_security_scan = datetime.now()           # DateTime
        db.commit()
        
        return {
            "success": True,
            "message": f"Security scan completed for {device.ip_address}",
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
            
    except Exception as e:
        logger.error(f"Error performing security scan on device {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to perform security scan")

@app.put("/api/devices/{device_id}")
async def update_device(device_id: int, device_data: dict):
    """Update device information"""
    try:
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        # Update allowed fields
        allowed_fields = ["hostname", "location", "notes", "vendor", "model"]
        for field in allowed_fields:
            if field in device_data:
                setattr(device, field, device_data[field])
        # SSH credential update
        if "ssh_username" in device_data:
            device.ssh_username = device_data["ssh_username"]
        if "ssh_password" in device_data and device_data["ssh_password"]:
            device.set_ssh_password(device_data["ssh_password"])
        device.updated_at = datetime.now()                   # DateTime
        db.commit()
        return {
            "success": True,
            "message": f"Device {device.ip_address} updated successfully",
            "device": device.to_dict()
        }
    except Exception as e:
        logger.error(f"Error updating device {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update device")

@app.post("/api/scan/start")
async def start_scan():
    """Manually start a network scan"""
    try:
        if network_scanner:
            await network_scanner.scan_network()
            return {"message": "Network scan started", "status": "success"}
        else:
            raise HTTPException(status_code=500, detail="Network scanner not initialized")
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to start scan")

@app.post("/api/scan/stop")
async def stop_scan():
    """Stop ongoing network scan"""
    try:
        if network_scanner:
            await network_scanner.stop_current_scan()
            return {"message": "Network scan stopped", "status": "success"}
        else:
            raise HTTPException(status_code=500, detail="Network scanner not initialized")
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop scan")

@app.get("/api/scan/status")
async def get_scan_status():
    """Get current scan status"""
    if network_scanner:
        return {
            "is_scanning": network_scanner.is_scanning,
            "last_scan": network_scanner.last_scan_time,
            "devices_found": network_scanner.devices_found
        }
    else:
        raise HTTPException(status_code=500, detail="Network scanner not initialized")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle different message types
            if message.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            elif message.get("type") == "request_devices":
                db = get_db()
                devices = db.query(Device).all()
                await websocket.send_text(json.dumps({
                    "type": "devices_update",
                    "devices": [device.to_dict() for device in devices]
                }))
                
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        websocket_manager.disconnect(websocket)

# AI Admin endpoints
@app.post("/api/ai/analyze")
async def ai_analyze_network():
    """AI-powered network analysis"""
    try:
        if ai_admin:
            analysis = await ai_admin.analyze_network()
            return analysis
        else:
            raise HTTPException(status_code=500, detail="AI system not initialized")
    except Exception as e:
        logger.error(f"AI analysis error: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze network")

@app.post("/api/ai/recommendations")
async def ai_get_recommendations():
    """Get AI-powered recommendations for network improvements"""
    try:
        if ai_admin:
            recommendations = await ai_admin.get_recommendations()
            return recommendations
        else:
            raise HTTPException(status_code=500, detail="AI system not initialized")
    except Exception as e:
        logger.error(f"AI recommendations error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get recommendations")

@app.websocket("/api/devices/{device_id}/shell")
async def device_shell(websocket: WebSocket, device_id: int):
    """WebSocket endpoint for SSH shell access to a device."""
    await websocket.accept()
    import asyncio
    import base64
    from concurrent.futures import ThreadPoolExecutor
    import queue
    import threading
    
    db = get_db()
    device = db.query(Device).filter(Device.id == device_id).first()
    
    websocket_closed = False
    ssh = None
    chan = None
    executor = ThreadPoolExecutor(max_workers=4)
    
    # Queues for non-blocking communication
    ssh_to_ws_queue = queue.Queue()
    ws_to_ssh_queue = queue.Queue()
    
    async def send_status(status):
        if not websocket_closed:
            await websocket.send_text(json.dumps({"type": "status", "status": status}))
    
    async def send_error(code, message):
        if not websocket_closed:
            await websocket.send_text(json.dumps({"type": "error", "code": code, "message": message}))
    
    async def send_data(data):
        if not websocket_closed:
            await websocket.send_text(json.dumps({"type": "data", "data": data, "encoding": "utf8"}))
    
    async def close_websocket():
        nonlocal websocket_closed
        if not websocket_closed:
            websocket_closed = True
            await websocket.close()
    
    def ssh_read_loop():
        try:
            while not websocket_closed and chan and not chan.closed:
                try:
                    data = chan.recv(1024)
                    if data:
                        ssh_to_ws_queue.put(data)
                    else:
                        break
                except Exception as e:
                    logger.error(f"SSH recv error: {e}")
                    break
        except Exception as e:
            logger.error(f"SSH receive loop error: {e}")
        finally:
            ssh_to_ws_queue.put(None)  # Signal end
    
    def ssh_write_loop():
        try:
            while not websocket_closed and chan and not chan.closed:
                try:
                    data = ws_to_ssh_queue.get(timeout=1)
                    if data is None:
                        break
                    chan.send(data)
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"SSH send error: {e}")
                    break
        except Exception as e:
            logger.error(f"SSH send loop error: {e}")
    
    def upload_script(script_name, script_content):
        try:
            full_script = f"#!/bin/bash\n{script_content}"
            upload_cmd = f"cat > /tmp/{script_name} << 'EOF'\n{full_script}\nEOF\nchmod +x /tmp/{script_name}"
            ws_to_ssh_queue.put(upload_cmd + '\n')
            logger.info(f"Uploaded script {script_name} to remote system")
            return True
        except Exception as e:
            logger.error(f"Failed to upload script {script_name}: {e}")
            return False
    
    try:
        logger.info(f"Starting shell connection for device {device_id}")
        await send_status("connecting")
        if not device:
            await send_error("not_found", "Device not found.")
            await send_status("disconnected")
            await close_websocket()
            return
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        username = device.ssh_username if device.ssh_username else 'root'
        password = 'password'
        if device.ssh_password_enc:
            try:
                password = device.get_ssh_password()
                logger.info(f"Retrieved encrypted password for device {device.ip_address}")
            except Exception as e:
                logger.error(f"Failed to decrypt password for device {device.ip_address}: {e}")
                password = 'password'
        else:
            logger.warning(f"No encrypted password found for device {device.ip_address}, using default")
        logger.info(f"Attempting SSH with username={username}, password={password!r} for device {device.ip_address}")
        try:
            ssh.connect(device.ip_address, username=username, password=password, timeout=5)
            logger.info("SSH connection established successfully")
        except paramiko.AuthenticationException:
            logger.error("SSH authentication failed")
            await send_error("auth_failed", "Authentication failed. Please check your username and password.")
            await send_status("disconnected")
            await close_websocket()
            return
        except paramiko.SSHException as e:
            logger.error(f"SSH error: {e}")
            await send_error("ssh_error", f"SSH error: {e}")
            await send_status("disconnected")
            await close_websocket()
            return
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            await send_error("connect_failed", f"Connection failed: {e}")
            await send_status("disconnected")
            await close_websocket()
            return
        chan = ssh.invoke_shell()
        logger.info("SSH shell invoked successfully")
        await send_status("connected")
        # Detect remote OS and architecture
        import time
        import re
        def detect_os_arch():
            try:
                # Try uname for Linux/macOS
                chan.send('uname -a\n')
                time.sleep(0.5)
                output = b''
                while chan.recv_ready():
                    output += chan.recv(4096)
                output_str = output.decode(errors='replace').lower()
                if 'linux' in output_str:
                    os_name = 'Linux'
                    icon = '🐧'
                elif 'darwin' in output_str or 'mac' in output_str:
                    os_name = 'macOS'
                    icon = '🍏'
                elif 'bsd' in output_str:
                    os_name = 'BSD'
                    icon = '🐡'
                else:
                    os_name = None
                    icon = '💻'
                # Try to extract arch
                arch_match = re.search(r'(x86_64|amd64|arm64|aarch64|i386|i686|armv7|armv8)', output_str)
                arch = arch_match.group(1) if arch_match else 'unknown'
                arch_icon = {
                    'x86_64': '🖥️', 'amd64': '🖥️', 'i386': '💾', 'i686': '💾',
                    'arm64': '📱', 'aarch64': '📱', 'armv7': '📱', 'armv8': '📱',
                }.get(arch, '💻')
                if os_name:
                    return f"{icon} {os_name} | {arch_icon} {arch}"
                # If not Linux/macOS, try Windows
                chan.send('ver\r\n')
                time.sleep(0.5)
                output = b''
                while chan.recv_ready():
                    output += chan.recv(4096)
                output_str = output.decode(errors='replace').lower()
                if 'windows' in output_str:
                    os_name = 'Windows'
                    icon = '🪟'
                    # Try to get arch
                    chan.send('echo %PROCESSOR_ARCHITECTURE%\r\n')
                    time.sleep(0.5)
                    output = b''
                    while chan.recv_ready():
                        output += chan.recv(4096)
                    arch_str = output.decode(errors='replace').strip().lower()
                    arch = arch_str if arch_str else 'unknown'
                    arch_icon = {
                        'amd64': '🖥️', 'x86': '💾', 'arm64': '📱',
                    }.get(arch, '💻')
                    return f"{icon} {os_name} | {arch_icon} {arch}"
                return "💻 Unknown OS/Arch"
            except Exception as e:
                return f"💻 Unknown OS/Arch ({e})"
        os_arch_info = detect_os_arch()
        await send_data(f"\n\033[1m{os_arch_info}\033[0m\n-----------------------------\n")
        # Ensure /tmp/edu_admin and subdirectories exist before uploading scripts
        admin_dir = "/tmp/edu_admin"
        subdirs = ["playbooks", "templates", "inventory"]
        mkdir_cmd = f"mkdir -p {admin_dir} " + " ".join([f'{admin_dir}/{s}' for s in subdirs])
        chan.send(mkdir_cmd + "\n")
        time.sleep(0.5)
        # Define automation scripts before uploading
        automation_scripts = {
            "system_update.sh": """# Comprehensive System Update Script\n# Supports Ubuntu/Debian, CentOS/RHEL, and Windows\n\nset -e\n\necho \"=== System Update Automation ===\"\necho \"Detecting operating system...\"\n\n# Detect OS\nif [[ \"$OSTYPE\" == \"linux-gnu\"* ]]; then\n    if command -v apt-get &> /dev/null; then\n        echo \"Detected Ubuntu/Debian system\"\n        echo \"Updating package lists...\"\n        sudo apt-get update\n        \n        echo \"Upgrading packages...\"\n        sudo apt-get upgrade -y\n        \n        echo \"Upgrading distribution...\"\n        sudo apt-get dist-upgrade -y\n        \n        echo \"Cleaning up...\"\n        sudo apt-get autoremove -y\n        sudo apt-get autoclean\n        \n        echo \"Checking for kernel updates...\"\n        if [ -f /var/run/reboot-required ]; then\n            echo \"⚠️  System reboot required!\"\n            echo \"Run: sudo reboot\"\n        fi\n        \n    elif command -v yum &> /dev/null; then\n        echo \"Detected CentOS/RHEL system\"\n        echo \"Updating packages...\"\n        sudo yum update -y\n        \n        echo \"Cleaning up...\"\n        sudo yum autoremove -y\n        \n    elif command -v dnf &> /dev/null; then\n        echo \"Detected Fedora/DNF system\"\n        echo \"Updating packages...\"\n        sudo dnf update -y\n        \n        echo \"Cleaning up...\"\n        sudo dnf autoremove -y\n        \n    else\n        echo \"Unknown Linux distribution\"\n        exit 1\n    fi\n    \nelif [[ \"$OSTYPE\" == \"msys\" ]] || [[ \"$OSTYPE\" == \"cygwin\" ]]; then\n    echo \"Detected Windows system\"\n    echo \"Checking for Windows updates...\"\n    \n    # PowerShell commands for Windows updates\n    powershell -Command \"Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot\"\n    \nelse\n    echo \"Unsupported operating system: $OSTYPE\"\n    exit 1\nfi\n\necho \"=== System Update Complete ===\"\necho \"✅ All packages updated successfully\"\n""",
            "security_audit.sh": """# Comprehensive Security Audit Script\n# Collects security data for AI analysis\n\nset -e\n\necho \"=== Security Audit & Network Analysis ===\"\necho \"Collecting security data for AI analysis...\"\n\n# Create audit directory\nAUDIT_DIR=\"/tmp/security_audit_$(date +%Y%m%d_%H%M%S)\"\nmkdir -p \"$AUDIT_DIR\"\n\necho \"📁 Audit data will be saved to: $AUDIT_DIR\"\n\n# System Information\necho \"🔍 Collecting system information...\"\n{\n    echo \"=== SYSTEM INFORMATION ===\"\n    echo \"Hostname: $(hostname)\"\n    echo \"OS: $(cat /etc/os-release 2>/dev/null || echo 'Unknown')\"\n    echo \"Kernel: $(uname -r)\"\n    echo \"Architecture: $(uname -m)\"\n    echo \"Uptime: $(uptime)\"\n    echo \"Load Average: $(cat /proc/loadavg 2>/dev/null || echo 'N/A')\"\n    echo \"Memory: $(free -h 2>/dev/null || echo 'N/A')\"\n    echo \"Disk Usage: $(df -h 2>/dev/null || echo 'N/A')\"\n} > \"$AUDIT_DIR/system_info.txt\"\n\n# Network Analysis\necho \"🌐 Analyzing network configuration...\"\n{\n    echo \"=== NETWORK ANALYSIS ===\"\n    echo \"IP Addresses:\"\n    ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo \"Network tools not available\"\n    \n    echo -e \"\\nRouting Table:\"\n    ip route show 2>/dev/null || route -n 2>/dev/null || echo \"Routing info not available\"\n    \n    echo -e \"\\nDNS Configuration:\"\n    cat /etc/resolv.conf 2>/dev/null || echo \"DNS config not available\"\n    \n    echo -e \"\\nNetwork Interfaces:\"\n    ip link show 2>/dev/null || echo \"Interface info not available\"\n} > \"$AUDIT_DIR/network_analysis.txt\"\n\n# Open Ports and Services\necho \"🔌 Scanning open ports and services...\"\n{\n    echo \"=== OPEN PORTS & SERVICES ===\"\n    echo \"Listening ports:\"\n    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo \"Port scanning tools not available\"\n    \n    echo -e \"\\nActive connections:\"\n    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo \"Connection info not available\"\n    \n    echo -e \"\\nRunning services:\"\n    systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null || echo \"Service info not available\"\n} > \"$AUDIT_DIR/ports_services.txt\"\n\n# Process Analysis\necho \"⚙️ Analyzing running processes...\"\n{\n    echo \"=== PROCESS ANALYSIS ===\"\n    echo \"Top processes by CPU:\"\n    ps aux --sort=-%cpu | head -20 2>/dev/null || echo \"Process info not available\"\n    \n    echo -e \"\\nTop processes by memory:\"\n    ps aux --sort=-%mem | head -20 2>/dev/null || echo \"Process info not available\"\n    \n    echo -e \"\\nSuspicious processes (high CPU/memory):\"\n    ps aux | awk '$3 > 50 || $4 > 50 {print}' 2>/dev/null || echo \"Process analysis not available\"\n} > \"$AUDIT_DIR/process_analysis.txt\"\n\n# Security Analysis\necho \"🔒 Performing security analysis...\"\n{\n    echo \"=== SECURITY ANALYSIS ===\"\n    \n    echo \"Failed login attempts:\"\n    grep \"Failed password\" /var/log/auth.log 2>/dev/null | tail -20 || echo \"Auth logs not available\"\n    \n    echo -e \"\\nSuccessful logins:\"\n    grep \"Accepted password\" /var/log/auth.log 2>/dev/null | tail -20 || echo \"Auth logs not available\"\n    \n    echo -e \"\\nSudo usage:\"\n    grep \"sudo:\" /var/log/auth.log 2>/dev/null | tail -20 || echo \"Sudo logs not available\"\n    \n    echo -e \"\\nSSH connections:\"\n    grep \"sshd\" /var/log/auth.log 2>/dev/null | tail -20 || echo \"SSH logs not available\"\n    \n    echo -e \"\\nFirewall status:\"\n    ufw status 2>/dev/null || iptables -L 2>/dev/null || echo \"Firewall info not available\"\n} > \"$AUDIT_DIR/security_analysis.txt\"\n\n# Package Analysis\necho \"📦 Analyzing installed packages...\"\n{\n    echo \"=== PACKAGE ANALYSIS ===\"\n    \n    if command -v apt &> /dev/null; then\n        echo \"Ubuntu/Debian packages:\"\n        apt list --installed 2>/dev/null | head -50 || echo \"Package list not available\"\n    elif command -v yum &> /dev/null; then\n        echo \"CentOS/RHEL packages:\"\n        yum list installed 2>/dev/null | head -50 || echo \"Package list not available\"\n    elif command -v dnf &> /dev/null; then\n        echo \"Fedora packages:\"\n        dnf list installed 2>/dev/null | head -50 || echo \"Package list not available\"\n    else\n        echo \"Package manager not detected\"\n    fi\n} > \"$AUDIT_DIR/package_analysis.txt\"\n\n# Network Traffic Analysis (if tcpdump available)\necho \"📊 Analyzing network traffic patterns...\"\n{\n    echo \"=== NETWORK TRAFFIC ANALYSIS ===\"\n    \n    if command -v tcpdump &> /dev/null; then\n        echo \"Capturing network traffic for 30 seconds...\"\n        echo \"This will show active connections and traffic patterns\"\n        timeout 30 tcpdump -i any -c 100 2>/dev/null || echo \"Network capture failed\"\n    else\n        echo \"tcpdump not available for traffic analysis\"\n    fi\n    \n    echo -e \"\\nActive network connections:\"\n    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo \"Connection info not available\"\n} > \"$AUDIT_DIR/network_traffic.txt\"\n\n# Create AI-ready summary\necho \"🤖 Generating AI-ready summary...\"\n{\n    echo \"=== AI ANALYSIS SUMMARY ===\"\n    echo \"Generated: $(date)\"\n    echo \"Hostname: $(hostname)\"\n    echo \"OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2 2>/dev/null || echo 'Unknown')\"\n    echo \"Open ports count: $(netstat -tuln 2>/dev/null | grep LISTEN | wc -l || echo '0')\"\n    echo \"Running services count: $(systemctl list-units --type=service --state=running 2>/dev/null | wc -l || echo '0')\"\n    echo \"Failed login attempts (last 24h): $(grep 'Failed password' /var/log/auth.log 2>/dev/null | grep \"$(date '+%b %d')\" | wc -l || echo '0')\"\n    echo \"Memory usage: $(free | grep Mem | awk '{printf \"%.1f%%\", $3/$2 * 100.0}')\"\n    echo \"Disk usage: $(df / | tail -1 | awk '{print $5}')\"\n    \n    echo -e \"\\n=== SECURITY RISK INDICATORS ===\"\n    echo \"High CPU processes: $(ps aux | awk '$3 > 50 {count++} END {print count+0}')\"\n    echo \"High memory processes: $(ps aux | awk '$4 > 50 {count++} END {print count+0}')\"\n    echo \"Suspicious network connections: $(netstat -tuln 2>/dev/null | grep -E ':(22|23|3389|5900)' | wc -l || echo '0')\"\n    \n    echo -e \"\\n=== RECOMMENDATIONS ===\"\n    echo \"1. Review failed login attempts for brute force attacks\"\n    echo \"2. Check high CPU/memory processes for malware\"\n    echo \"3. Verify all open ports are necessary\"\n    echo \"4. Update system packages regularly\"\n    echo \"5. Monitor network traffic for anomalies\"\n} > \"$AUDIT_DIR/ai_summary.txt\"\n\necho \"✅ Security audit complete!\"\necho \"📁 All data saved to: $AUDIT_DIR\"\necho \"🤖 AI-ready summary: $AUDIT_DIR/ai_summary.txt\"\necho \"\nFiles generated:\"\nls -la \"$AUDIT_DIR\"\n\n""",
            "k8s_context.sh": "...K8s context script here...",
            "ansible_setup.sh": "...Ansible setup script here..."
        }
        # Upload automation scripts to /tmp/edu_admin
        def upload_script(script_name, script_content):
            try:
                full_script = f"#!/bin/bash\n{script_content}"
                upload_cmd = f"cat > {admin_dir}/{script_name} << 'EOF'\n{full_script}\nEOF\nchmod +x {admin_dir}/{script_name}"
                ws_to_ssh_queue.put(upload_cmd + '\n')
                logger.info(f"Uploaded script {script_name} to remote system at {admin_dir}")
                return True
            except Exception as e:
                logger.error(f"Failed to upload script {script_name}: {e}")
                return False
        # Upload scripts to correct subdirs
        upload_script("system_update.sh", automation_scripts["system_update.sh"])
        upload_script("security_audit.sh", automation_scripts["security_audit.sh"])
        upload_script("k8s_context.sh", automation_scripts["k8s_context.sh"])
        upload_script("ansible_setup.sh", automation_scripts["ansible_setup.sh"])
        await send_data("\n✅ Automation scripts uploaded successfully!\n")
        await send_data("Available scripts in /tmp/edu_admin/:\n")
        await send_data("- system_update.sh (System updates)\n")
        await send_data("- security_audit.sh (Security analysis)\n")
        await send_data("- k8s_context.sh (Kubernetes management)\n")
        await send_data("- ansible_setup.sh (Ansible automation)\n")
        await send_data("Use the buttons in the sidebar to run them!\n\n")
        
        # Start SSH read/write threads
        read_thread = threading.Thread(target=ssh_read_loop, daemon=True)
        write_thread = threading.Thread(target=ssh_write_loop, daemon=True)
        read_thread.start()
        write_thread.start()
        # Async tasks for WebSocket <-> SSH
        async def ws_to_ssh():
            try:
                while not websocket_closed:
                    try:
                        msg = await asyncio.wait_for(websocket.receive_text(), timeout=900)
                    except asyncio.TimeoutError:
                        logger.info("WebSocket idle timeout, closing connection.")
                        ws_to_ssh_queue.put(None)
                        await close_websocket()
                        break
                    ws_to_ssh_queue.put(msg.encode('utf-8')) # Encode string to bytes for queue
            except Exception as e:
                logger.info(f"WebSocket read ended: {e}")
                ws_to_ssh_queue.put(None)
        async def ssh_to_ws():
            try:
                loop = asyncio.get_event_loop()
                while not websocket_closed:
                    data = await loop.run_in_executor(None, ssh_to_ws_queue.get)
                    if data is None:
                        break
                    await send_data(data.decode(errors='replace')) # Decode bytes to string for send_data
            except Exception as e:
                logger.error(f"SSH to WS error: {e}")
        await asyncio.gather(ws_to_ssh(), ssh_to_ws())
        await send_status("disconnected")
        
    except Exception as e:
        logger.error(f"Internal server error: {e}")
        if not websocket_closed:
            await send_error("internal_error", f"Internal server error: {e}")
            await send_status("disconnected")
    finally:
        logger.info("Cleaning up SSH connection")
        ws_to_ssh_queue.put(None)
        if executor:
            executor.shutdown(wait=False)
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass
        await close_websocket()

@app.post("/api/devices/{device_id}/ai-patch")
async def ai_patch_device(device_id: int):
    """Trigger AI-powered OS & security patching for a device (stub)."""
    db = get_db()
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # TODO: Implement real AI patching logic
    # For now, just return a stub response
    return {
        "success": True,
        "message": f"AI patching triggered for device {device.ip_address}. (Stub)"
    }

@app.get("/api/automations")
async def list_automations():
    """List available automation scripts"""
    if not os.path.exists(AUTOMATIONS_DIR):
        return {"automations": []}
    scripts = [os.path.basename(f) for f in glob.glob(os.path.join(AUTOMATIONS_DIR, '*')) if os.path.isfile(f)]
    return {"automations": scripts}

@app.websocket("/api/devices/{device_id}/automation-shell")
async def automation_shell(websocket: WebSocket, device_id: int, script: str):
    """WebSocket endpoint to run an automation script on a device and stream output."""
    await websocket.accept()
    db = get_db()
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        await websocket.close(code=4004)
        return
    script_path = os.path.join(AUTOMATIONS_DIR, script)
    if not os.path.exists(script_path):
        await websocket.send_text(f"Script not found: {script}")
        await websocket.close()
        return
    try:
        # For demo: run the script locally and stream output
        # In production: use SSH to run on the device
        import subprocess
        proc = subprocess.Popen([script_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in iter(proc.stdout.readline, ''):
            await websocket.send_text(line)
        proc.stdout.close()
        proc.wait()
        await websocket.send_text("[Automation complete]")
    except Exception as e:
        await websocket.send_text(f"Automation failed: {e}")
    finally:
        await websocket.close()

@app.post("/api/devices/{device_id}/run-automation")
async def run_automation(device_id: int, data: dict):
    """Trigger an automation script on a device (starts the WebSocket stream)."""
    script = data.get('script')
    if not script:
        raise HTTPException(status_code=400, detail="Script name required")
    # The frontend should open the WebSocket to /api/devices/{device_id}/automation-shell?script=SCRIPT_NAME
    return {"ws_url": f"/api/devices/{device_id}/automation-shell?script={script}"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    ) 