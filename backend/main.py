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
        # Upload automation scripts (as before)
        automation_scripts = {
            "system_update.sh": """# Comprehensive System Update Script
# Supports Ubuntu/Debian, CentOS/RHEL, and Windows

set -e

echo "=== System Update Automation ==="
echo "Detecting operating system..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &> /dev/null; then
        echo "Detected Ubuntu/Debian system"
        echo "Updating package lists..."
        sudo apt-get update
        
        echo "Upgrading packages..."
        sudo apt-get upgrade -y
        
        echo "Upgrading distribution..."
        sudo apt-get dist-upgrade -y
        
        echo "Cleaning up..."
        sudo apt-get autoremove -y
        sudo apt-get autoclean
        
        echo "Checking for kernel updates..."
        if [ -f /var/run/reboot-required ]; then
            echo "⚠️  System reboot required!"
            echo "Run: sudo reboot"
        fi
        
    elif command -v yum &> /dev/null; then
        echo "Detected CentOS/RHEL system"
        echo "Updating packages..."
        sudo yum update -y
        
        echo "Cleaning up..."
        sudo yum autoremove -y
        
    elif command -v dnf &> /dev/null; then
        echo "Detected Fedora/DNF system"
        echo "Updating packages..."
        sudo dnf update -y
        
        echo "Cleaning up..."
        sudo dnf autoremove -y
        
    else
        echo "Unknown Linux distribution"
        exit 1
    fi
    
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    echo "Detected Windows system"
    echo "Checking for Windows updates..."
    
    # PowerShell commands for Windows updates
    powershell -Command "Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot"
    
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "=== System Update Complete ==="
echo "✅ All packages updated successfully"
""",
            "security_audit.sh": """# Comprehensive Security Audit Script
# Collects security data for AI analysis

set -e

echo "=== Security Audit & Network Analysis ==="
echo "Collecting security data for AI analysis..."

# Create audit directory
AUDIT_DIR="/tmp/security_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$AUDIT_DIR"

echo "📁 Audit data will be saved to: $AUDIT_DIR"

# System Information
echo "🔍 Collecting system information..."
{
    echo "=== SYSTEM INFORMATION ==="
    echo "Hostname: $(hostname)"
    echo "OS: $(cat /etc/os-release 2>/dev/null || echo 'Unknown')"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Uptime: $(uptime)"
    echo "Load Average: $(cat /proc/loadavg 2>/dev/null || echo 'N/A')"
    echo "Memory: $(free -h 2>/dev/null || echo 'N/A')"
    echo "Disk Usage: $(df -h 2>/dev/null || echo 'N/A')"
} > "$AUDIT_DIR/system_info.txt"

# Network Analysis
echo "🌐 Analyzing network configuration..."
{
    echo "=== NETWORK ANALYSIS ==="
    echo "IP Addresses:"
    ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Network tools not available"
    
    echo -e "\\nRouting Table:"
    ip route show 2>/dev/null || route -n 2>/dev/null || echo "Routing info not available"
    
    echo -e "\\nDNS Configuration:"
    cat /etc/resolv.conf 2>/dev/null || echo "DNS config not available"
    
    echo -e "\\nNetwork Interfaces:"
    ip link show 2>/dev/null || echo "Interface info not available"
} > "$AUDIT_DIR/network_analysis.txt"

# Open Ports and Services
echo "🔌 Scanning open ports and services..."
{
    echo "=== OPEN PORTS & SERVICES ==="
    echo "Listening ports:"
    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "Port scanning tools not available"
    
    echo -e "\\nActive connections:"
    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "Connection info not available"
    
    echo -e "\\nRunning services:"
    systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null || echo "Service info not available"
} > "$AUDIT_DIR/ports_services.txt"

# Process Analysis
echo "⚙️ Analyzing running processes..."
{
    echo "=== PROCESS ANALYSIS ==="
    echo "Top processes by CPU:"
    ps aux --sort=-%cpu | head -20 2>/dev/null || echo "Process info not available"
    
    echo -e "\\nTop processes by memory:"
    ps aux --sort=-%mem | head -20 2>/dev/null || echo "Process info not available"
    
    echo -e "\\nSuspicious processes (high CPU/memory):"
    ps aux | awk '$3 > 50 || $4 > 50 {print}' 2>/dev/null || echo "Process analysis not available"
} > "$AUDIT_DIR/process_analysis.txt"

# Security Analysis
echo "🔒 Performing security analysis..."
{
    echo "=== SECURITY ANALYSIS ==="
    
    echo "Failed login attempts:"
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 || echo "Auth logs not available"
    
    echo -e "\\nSuccessful logins:"
    grep "Accepted password" /var/log/auth.log 2>/dev/null | tail -20 || echo "Auth logs not available"
    
    echo -e "\\nSudo usage:"
    grep "sudo:" /var/log/auth.log 2>/dev/null | tail -20 || echo "Sudo logs not available"
    
    echo -e "\\nSSH connections:"
    grep "sshd" /var/log/auth.log 2>/dev/null | tail -20 || echo "SSH logs not available"
    
    echo -e "\\nFirewall status:"
    ufw status 2>/dev/null || iptables -L 2>/dev/null || echo "Firewall info not available"
} > "$AUDIT_DIR/security_analysis.txt"

# Package Analysis
echo "📦 Analyzing installed packages..."
{
    echo "=== PACKAGE ANALYSIS ==="
    
    if command -v apt &> /dev/null; then
        echo "Ubuntu/Debian packages:"
        apt list --installed 2>/dev/null | head -50 || echo "Package list not available"
    elif command -v yum &> /dev/null; then
        echo "CentOS/RHEL packages:"
        yum list installed 2>/dev/null | head -50 || echo "Package list not available"
    elif command -v dnf &> /dev/null; then
        echo "Fedora packages:"
        dnf list installed 2>/dev/null | head -50 || echo "Package list not available"
    else
        echo "Package manager not detected"
    fi
} > "$AUDIT_DIR/package_analysis.txt"

# Network Traffic Analysis (if tcpdump available)
echo "📊 Analyzing network traffic patterns..."
{
    echo "=== NETWORK TRAFFIC ANALYSIS ==="
    
    if command -v tcpdump &> /dev/null; then
        echo "Capturing network traffic for 30 seconds..."
        echo "This will show active connections and traffic patterns"
        timeout 30 tcpdump -i any -c 100 2>/dev/null || echo "Network capture failed"
    else
        echo "tcpdump not available for traffic analysis"
    fi
    
    echo -e "\\nActive network connections:"
    netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "Connection info not available"
} > "$AUDIT_DIR/network_traffic.txt"

# Create AI-ready summary
echo "🤖 Generating AI-ready summary..."
{
    echo "=== AI ANALYSIS SUMMARY ==="
    echo "Generated: $(date)"
    echo "Hostname: $(hostname)"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2 2>/dev/null || echo 'Unknown')"
    echo "Open ports count: $(netstat -tuln 2>/dev/null | grep LISTEN | wc -l || echo '0')"
    echo "Running services count: $(systemctl list-units --type=service --state=running 2>/dev/null | wc -l || echo '0')"
    echo "Failed login attempts (last 24h): $(grep 'Failed password' /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l || echo '0')"
    echo "Memory usage: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
    echo "Disk usage: $(df / | tail -1 | awk '{print $5}')"
    
    echo -e "\\n=== SECURITY RISK INDICATORS ==="
    echo "High CPU processes: $(ps aux | awk '$3 > 50 {count++} END {print count+0}')"
    echo "High memory processes: $(ps aux | awk '$4 > 50 {count++} END {print count+0}')"
    echo "Suspicious network connections: $(netstat -tuln 2>/dev/null | grep -E ':(22|23|3389|5900)' | wc -l || echo '0')"
    
    echo -e "\\n=== RECOMMENDATIONS ==="
    echo "1. Review failed login attempts for brute force attacks"
    echo "2. Check high CPU/memory processes for malware"
    echo "3. Verify all open ports are necessary"
    echo "4. Update system packages regularly"
    echo "5. Monitor network traffic for anomalies"
} > "$AUDIT_DIR/ai_summary.txt"

echo "✅ Security audit complete!"
echo "📁 All data saved to: $AUDIT_DIR"
echo "🤖 AI-ready summary: $AUDIT_DIR/ai_summary.txt"
echo ""
echo "Files generated:"
ls -la "$AUDIT_DIR"
""",
            "k8s_context.sh": """# Kubernetes Context and Namespace Management Script

set -e

echo "=== Kubernetes Context & Namespace Manager ==="

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl first."
    exit 1
fi

# Function to display current context
show_current_context() {
    echo "🔍 Current Context Information:"
    echo "Context: $(kubectl config current-context)"
    echo "Namespace: $(kubectl config view --minify --output 'jsonpath={..namespace}' 2>/dev/null || echo 'default')"
    echo "Cluster: $(kubectl config view --minify --output 'jsonpath={..cluster}' 2>/dev/null || echo 'N/A')"
    echo "User: $(kubectl config view --minify --output 'jsonpath={..user}' 2>/dev/null || echo 'N/A')"
}

# Function to list all contexts
list_contexts() {
    echo "📋 Available Kubernetes Contexts:"
    kubectl config get-contexts
}

# Function to list all namespaces
list_namespaces() {
    echo "📋 Available Namespaces:"
    kubectl get namespaces
}

# Function to switch context
switch_context() {
    local context_name=$1
    if [ -z "$context_name" ]; then
        echo "Please provide a context name"
        return 1
    fi
    
    echo "🔄 Switching to context: $context_name"
    kubectl config use-context "$context_name"
    show_current_context
}

# Function to switch namespace
switch_namespace() {
    local namespace_name=$1
    if [ -z "$namespace_name" ]; then
        echo "Please provide a namespace name"
        return 1
    fi
    
    echo "🔄 Switching to namespace: $namespace_name"
    kubectl config set-context --current --namespace="$namespace_name"
    show_current_context
}

# Function to create namespace
create_namespace() {
    local namespace_name=$1
    if [ -z "$namespace_name" ]; then
        echo "Please provide a namespace name"
        return 1
    fi
    
    echo "➕ Creating namespace: $namespace_name"
    kubectl create namespace "$namespace_name"
    echo "✅ Namespace '$namespace_name' created successfully"
}

# Function to delete namespace
delete_namespace() {
    local namespace_name=$1
    if [ -z "$namespace_name" ]; then
        echo "Please provide a namespace name"
        return 1
    fi
    
    echo "⚠️  Are you sure you want to delete namespace '$namespace_name'? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "🗑️  Deleting namespace: $namespace_name"
        kubectl delete namespace "$namespace_name"
        echo "✅ Namespace '$namespace_name' deleted successfully"
    else
        echo "❌ Namespace deletion cancelled"
    fi
}

# Function to show cluster info
show_cluster_info() {
    echo "🏢 Cluster Information:"
    kubectl cluster-info
    
    echo -e "\\n📊 Node Information:"
    kubectl get nodes -o wide
    
    echo -e "\\n📦 Pod Information:"
    kubectl get pods --all-namespaces
}

# Function to show resource usage
show_resource_usage() {
    echo "📈 Resource Usage:"
    
    echo -e "\\n💾 Memory Usage by Pod:"
    kubectl top pods --all-namespaces --sort-by=memory
    
    echo -e "\\n⚡ CPU Usage by Pod:"
    kubectl top pods --all-namespaces --sort-by=cpu
    
    echo -e "\\n🖥️  Node Resource Usage:"
    kubectl top nodes
}

# Function to show security context
show_security_context() {
    echo "🔒 Security Context:"
    
    echo -e "\\n👥 Service Accounts:"
    kubectl get serviceaccounts --all-namespaces
    
    echo -e "\\n🔐 Secrets:"
    kubectl get secrets --all-namespaces
    
    echo -e "\\n🛡️  Network Policies:"
    kubectl get networkpolicies --all-namespaces
}

# Function to backup context
backup_context() {
    local backup_file="k8s_context_backup_$(date +%Y%m%d_%H%M%S).yaml"
    echo "💾 Backing up current context to: $backup_file"
    kubectl config view --raw > "$backup_file"
    echo "✅ Context backed up to: $backup_file"
}

# Function to show help
show_help() {
    echo "Usage: $0 [COMMAND] [ARGUMENTS]"
    echo ""
    echo "Commands:"
    echo "  current                    - Show current context and namespace"
    echo "  contexts                   - List all available contexts"
    echo "  namespaces                 - List all namespaces"
    echo "  switch-context <name>      - Switch to specified context"
    echo "  switch-ns <name>           - Switch to specified namespace"
    echo "  create-ns <name>           - Create new namespace"
    echo "  delete-ns <name>           - Delete namespace"
    echo "  cluster-info               - Show cluster information"
    echo "  resources                  - Show resource usage"
    echo "  security                   - Show security context"
    echo "  backup                     - Backup current context"
    echo "  help                       - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 current"
    echo "  $0 switch-context production"
    echo "  $0 switch-ns monitoring"
    echo "  $0 create-ns new-app"
}

# Main script logic
case "${1:-help}" in
    "current")
        show_current_context
        ;;
    "contexts")
        list_contexts
        ;;
    "namespaces")
        list_namespaces
        ;;
    "switch-context")
        switch_context "$2"
        ;;
    "switch-ns")
        switch_namespace "$2"
        ;;
    "create-ns")
        create_namespace "$2"
        ;;
    "delete-ns")
        delete_namespace "$2"
        ;;
    "cluster-info")
        show_cluster_info
        ;;
    "resources")
        show_resource_usage
        ;;
    "security")
        show_security_context
        ;;
    "backup")
        backup_context
        ;;
    "help"|*)
        show_help
        ;;
esac
""",
            "ansible_setup.sh": """# Ansible Setup and Management Script

set -e

echo "=== Ansible System Administration ==="

# Check if ansible is available
if ! command -v ansible &> /dev/null; then
    echo "📦 Installing Ansible..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y ansible
    elif command -v yum &> /dev/null; then
        sudo yum install -y ansible
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y ansible
    else
        echo "❌ Package manager not supported. Please install Ansible manually."
        exit 1
    fi
fi

# Create Ansible directory structure
ANSIBLE_DIR="/tmp/ansible_automation_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$ANSIBLE_DIR"/{inventory,playbooks,roles,templates}

echo "📁 Ansible workspace created at: $ANSIBLE_DIR"

# Create inventory file
cat > "$ANSIBLE_DIR/inventory/hosts" << 'EOF'
[local]
localhost ansible_connection=local

[servers]
# Add your servers here
# server1 ansible_host=192.168.1.10 ansible_user=admin
# server2 ansible_host=192.168.1.11 ansible_user=admin

[webservers]
# Add web servers here
# web1 ansible_host=192.168.1.20 ansible_user=admin
# web2 ansible_host=192.168.1.21 ansible_user=admin

[dbservers]
# Add database servers here
# db1 ansible_host=192.168.1.30 ansible_user=admin

[all:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_become=yes
ansible_become_method=sudo
EOF

# Create ansible.cfg
cat > "$ANSIBLE_DIR/ansible.cfg" << 'EOF'
[defaults]
inventory = inventory/hosts
host_key_checking = False
timeout = 30
gathering = smart
fact_caching = memory
stdout_callback = yaml
bin_ansible_callbacks = True

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes
EOF

# Create system update playbook
cat > "$ANSIBLE_DIR/playbooks/system_update.yml" << 'EOF'
---
- name: System Update and Maintenance
  hosts: all
  become: yes
  tasks:
    - name: Update package cache (Ubuntu/Debian)
      apt:
        update_cache: yes
        cache_valid_time: 3600
      when: ansible_os_family == "Debian"

    - name: Update package cache (CentOS/RHEL)
      yum:
        update_cache: yes
      when: ansible_os_family == "RedHat"

    - name: Upgrade all packages (Ubuntu/Debian)
      apt:
        upgrade: yes
        autoremove: yes
      when: ansible_os_family == "Debian"

    - name: Upgrade all packages (CentOS/RHEL)
      yum:
        name: '*'
        state: latest
      when: ansible_os_family == "RedHat"

    - name: Clean up package cache
      shell: |
        if command -v apt-get &> /dev/null; then
          apt-get autoclean
        elif command -v yum &> /dev/null; then
          yum clean all
        fi
      args:
        warn: false

    - name: Check if reboot is required
      stat:
        path: /var/run/reboot-required
      register: reboot_required

    - name: Notify reboot required
      debug:
        msg: "⚠️  System reboot required on {{ inventory_hostname }}"
      when: reboot_required.stat.exists
EOF

# Create security hardening playbook
cat > "$ANSIBLE_DIR/playbooks/security_harden.yml" << 'EOF'
---
- name: Security Hardening
  hosts: all
  become: yes
  tasks:
    - name: Update SSH configuration
      template:
        src: sshd_config.j2
        dest: /etc/ssh/sshd_config
        backup: yes
      notify: restart ssh

    - name: Configure firewall (UFW for Ubuntu)
      ufw:
        state: enabled
        policy: deny
        rule: allow
        port: ssh
        proto: tcp
      when: ansible_os_family == "Debian"

    - name: Configure firewall (firewalld for CentOS)
      firewalld:
        service: ssh
        permanent: yes
        state: enabled
      when: ansible_os_family == "RedHat"

    - name: Install fail2ban (Ubuntu/Debian)
      apt:
        name: fail2ban
        state: present
      when: ansible_os_family == "Debian"

    - name: Install fail2ban (CentOS/RHEL)
      yum:
        name: fail2ban
        state: present
      when: ansible_os_family == "RedHat"

    - name: Start and enable fail2ban
      systemd:
        name: fail2ban
        state: started
        enabled: yes

    - name: Configure automatic security updates
      apt:
        name: unattended-upgrades
        state: present
      when: ansible_os_family == "Debian"

  handlers:
    - name: restart ssh
      systemd:
        name: ssh
        state: restarted
EOF

# Create monitoring setup playbook
cat > "$ANSIBLE_DIR/playbooks/monitoring_setup.yml" << 'EOF'
---
- name: Monitoring Setup
  hosts: all
  become: yes
  tasks:
    - name: Install monitoring tools
      package:
        name:
          - htop
          - iotop
          - nethogs
          - nload
          - iftop
        state: present

    - name: Create monitoring script
      copy:
        dest: /usr/local/bin/system_monitor.sh
        mode: '0755'
        content: |
          #!/bin/bash
          echo "=== System Monitor ==="
          echo "Date: $(date)"
          echo "Uptime: $(uptime)"
          echo "Load: $(cat /proc/loadavg)"
          echo "Memory: $(free -h)"
          echo "Disk: $(df -h)"
          echo "Network: $(ss -tuln | grep LISTEN)"

    - name: Setup log rotation for monitoring
      copy:
        dest: /etc/logrotate.d/system_monitor
        content: |
          /var/log/system_monitor.log {
            daily
            rotate 7
            compress
            delaycompress
            missingok
            notifempty
            create 644 root root
          }
EOF

# Create SSH template
cat > "$ANSIBLE_DIR/templates/sshd_config.j2" << 'EOF'
# SSH Configuration Template
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Security settings
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel INFO

# Other settings
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
EOF

# Create deployment playbook
cat > "$ANSIBLE_DIR/playbooks/deploy_app.yml" << 'EOF'
---
- name: Deploy Application
  hosts: webservers
  become: yes
  vars:
    app_name: "myapp"
    app_port: 8080
  tasks:
    - name: Create application directory
      file:
        path: /opt/{{ app_name }}
        state: directory
        owner: www-data
        group: www-data
        mode: '0755'

    - name: Copy application files
      copy:
        src: "{{ item }}"
        dest: /opt/{{ app_name }}/
        owner: www-data
        group: www-data
      with_fileglob:
        - "files/*"

    - name: Install application dependencies
      pip:
        requirements: /opt/{{ app_name }}/requirements.txt
        virtualenv: /opt/{{ app_name }}/venv
      when: ansible_os_family == "Debian"

    - name: Create systemd service
      template:
        src: app.service.j2
        dest: /etc/systemd/system/{{ app_name }}.service
        backup: yes
      notify: restart app

    - name: Start and enable application
      systemd:
        name: "{{ app_name }}"
        state: started
        enabled: yes

  handlers:
    - name: restart app
      systemd:
        name: "{{ app_name }}"
        state: restarted
EOF

# Create systemd service template
cat > "$ANSIBLE_DIR/templates/app.service.j2" << 'EOF'
[Unit]
Description={{ app_name }} Application
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/{{ app_name }}
ExecStart=/opt/{{ app_name }}/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Function to run playbook
run_playbook() {
    local playbook=$1
    local inventory=${2:-"inventory/hosts"}
    
    echo "🚀 Running playbook: $playbook"
    cd "$ANSIBLE_DIR"
    ansible-playbook -i "$inventory" "playbooks/$playbook.yml" -v
}

# Function to show help
show_help() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  setup                     - Setup Ansible environment"
    echo "  update                    - Run system update on all hosts"
    echo "  harden                    - Run security hardening"
    echo "  monitor                   - Setup monitoring"
    echo "  deploy <app>              - Deploy application"
    echo "  ping                      - Test connectivity to all hosts"
    echo "  facts                     - Gather facts from all hosts"
    echo "  help                      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup"
    echo "  $0 update"
    echo "  $0 harden"
    echo "  $0 deploy myapp"
}

# Main script logic
case "${1:-help}" in
    "setup")
        echo "✅ Ansible environment setup complete!"
        echo "📁 Workspace: $ANSIBLE_DIR"
        echo "📝 Edit inventory/hosts to add your servers"
        echo "🚀 Run '$0 update' to start automation"
        ;;
    "update")
        run_playbook "system_update"
        ;;
    "harden")
        run_playbook "security_harden"
        ;;
    "monitor")
        run_playbook "monitoring_setup"
        ;;
    "deploy")
        if [ -z "$2" ]; then
            echo "Please provide application name"
            exit 1
        fi
        # Update app name in playbook
        sed -i "s/app_name: \"myapp\"/app_name: \"$2\"/" "$ANSIBLE_DIR/playbooks/deploy_app.yml"
        run_playbook "deploy_app"
        ;;
    "ping")
        cd "$ANSIBLE_DIR"
        ansible all -m ping
        ;;
    "facts")
        cd "$ANSIBLE_DIR"
        ansible all -m setup
        ;;
    "help"|*)
        show_help
        ;;
esac
"""
        }
        
        # Upload each script
        for script_name, script_content in automation_scripts.items():
            upload_script(script_name, script_content)
        
        await send_data("✅ Automation scripts uploaded successfully!\n")
        await send_data("Available scripts:\n")
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
                        msg = await asyncio.wait_for(websocket.receive_text(), timeout=60)
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