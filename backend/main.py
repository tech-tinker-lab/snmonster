from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional
import json
import os
from datetime import datetime
import paramiko
import glob
from concurrent.futures import ThreadPoolExecutor

from database import init_db, get_db
from models import Device, DeviceStatus, BoundaryType, NamespaceStatus, PodStatus, NodeStatus
from network_scanner import NetworkScanner
from ai_admin import AIAdminSystem
from websocket_manager import WebSocketManager
from registry_manager import RegistryManager
from config import Config

# Configure logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global instances
network_scanner = None
ai_admin = None
websocket_manager = WebSocketManager()
registry_manager = RegistryManager()

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
    
    logger.info("Network Admin Application started successfully")
    yield
    
    # Shutdown
    logger.info("Shutting down Network Admin Application...")
    if network_scanner:
        await network_scanner.stop()

app = FastAPI(
    title="Network Admin System",
    description="AI-Powered Network Device Management and Administration with Virtual Boundaries and Container Orchestration",
    version="2.0.0",
    lifespan=lifespan
)

# CORS middleware - More permissive for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.CORS_ORIGINS,
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
    return {
        "message": "Network Admin System API", 
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/api/health"
    }

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
        "allowed_origins": Config.CORS_ORIGINS
    }

# Health check endpoint
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "scanner_running": network_scanner.is_running if network_scanner else False,
        "ai_system_ready": ai_admin.is_ready if ai_admin else False,
        "registry_ready": True,
        "network_range": network_scanner.network_range if network_scanner else None
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

# Registry API Endpoints

# Virtual Boundaries
@app.post("/api/registry/boundaries")
async def create_virtual_boundary(boundary_data: dict):
    """Create a new virtual boundary"""
    try:
        boundary = await registry_manager.create_virtual_boundary(boundary_data)
        return {
            "success": True,
            "message": f"Virtual boundary '{boundary.name}' created successfully",
            "boundary": boundary.to_dict()
        }
    except Exception as e:
        logger.error(f"Error creating virtual boundary: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/registry/boundaries")
async def get_virtual_boundaries():
    """Get all virtual boundaries"""
    try:
        boundaries = await registry_manager.get_virtual_boundaries()
        return {
            "boundaries": boundaries,
            "total": len(boundaries)
        }
    except Exception as e:
        logger.error(f"Error fetching virtual boundaries: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch virtual boundaries")

@app.get("/api/registry/boundaries/{boundary_id}")
async def get_virtual_boundary(boundary_id: int):
    """Get a specific virtual boundary"""
    try:
        boundary = await registry_manager.get_virtual_boundary(boundary_id)
        if not boundary:
            raise HTTPException(status_code=404, detail="Virtual boundary not found")
        return boundary
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching virtual boundary {boundary_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch virtual boundary")

@app.put("/api/registry/boundaries/{boundary_id}")
async def update_virtual_boundary(boundary_id: int, boundary_data: dict):
    """Update a virtual boundary"""
    try:
        boundary = await registry_manager.update_virtual_boundary(boundary_id, boundary_data)
        return {
            "success": True,
            "message": f"Virtual boundary '{boundary.name}' updated successfully",
            "boundary": boundary.to_dict()
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating virtual boundary {boundary_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update virtual boundary")

@app.delete("/api/registry/boundaries/{boundary_id}")
async def delete_virtual_boundary(boundary_id: int):
    """Delete a virtual boundary"""
    try:
        success = await registry_manager.delete_virtual_boundary(boundary_id)
        return {
            "success": success,
            "message": "Virtual boundary deleted successfully"
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting virtual boundary {boundary_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete virtual boundary")

@app.post("/api/registry/boundaries/{boundary_id}/devices/{device_id}")
async def add_device_to_boundary(boundary_id: int, device_id: int):
    """Add a device to a virtual boundary"""
    try:
        success = await registry_manager.add_device_to_boundary(boundary_id, device_id)
        return {
            "success": success,
            "message": "Device added to boundary successfully" if success else "Device already in boundary"
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding device to boundary: {e}")
        raise HTTPException(status_code=500, detail="Failed to add device to boundary")

@app.get("/api/registry/boundaries/{boundary_id}/summary")
async def get_boundary_summary(boundary_id: int):
    """Get comprehensive summary of a virtual boundary"""
    try:
        summary = await registry_manager.get_boundary_summary(boundary_id)
        return summary
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting boundary summary {boundary_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get boundary summary")

# Namespaces
@app.post("/api/registry/namespaces")
async def create_namespace(namespace_data: dict):
    """Create a new namespace"""
    try:
        namespace = await registry_manager.create_namespace(namespace_data)
        return {
            "success": True,
            "message": f"Namespace '{namespace.name}' created successfully",
            "namespace": namespace.to_dict()
        }
    except Exception as e:
        logger.error(f"Error creating namespace: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/registry/namespaces")
async def get_namespaces():
    """Get all namespaces"""
    try:
        namespaces = await registry_manager.get_namespaces()
        return {
            "namespaces": namespaces,
            "total": len(namespaces)
        }
    except Exception as e:
        logger.error(f"Error fetching namespaces: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch namespaces")

@app.get("/api/registry/namespaces/{namespace_id}")
async def get_namespace(namespace_id: int):
    """Get a specific namespace"""
    try:
        namespace = await registry_manager.get_namespace(namespace_id)
        if not namespace:
            raise HTTPException(status_code=404, detail="Namespace not found")
        return namespace
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching namespace {namespace_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch namespace")

@app.put("/api/registry/namespaces/{namespace_id}")
async def update_namespace(namespace_id: int, namespace_data: dict):
    """Update a namespace"""
    try:
        namespace = await registry_manager.update_namespace(namespace_id, namespace_data)
        return {
            "success": True,
            "message": f"Namespace '{namespace.name}' updated successfully",
            "namespace": namespace.to_dict()
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating namespace {namespace_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update namespace")

@app.delete("/api/registry/namespaces/{namespace_id}")
async def delete_namespace(namespace_id: int):
    """Delete a namespace"""
    try:
        success = await registry_manager.delete_namespace(namespace_id)
        return {
            "success": success,
            "message": "Namespace deleted successfully"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting namespace {namespace_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete namespace")

@app.get("/api/registry/namespaces/{namespace_id}/summary")
async def get_namespace_summary(namespace_id: int):
    """Get comprehensive summary of a namespace"""
    try:
        summary = await registry_manager.get_namespace_summary(namespace_id)
        return summary
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting namespace summary {namespace_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get namespace summary")

# Nodes
@app.post("/api/registry/nodes")
async def create_node(node_data: dict):
    """Create a new node"""
    try:
        node = await registry_manager.create_node(node_data)
        return {
            "success": True,
            "message": f"Node '{node.name}' created successfully",
            "node": node.to_dict()
        }
    except Exception as e:
        logger.error(f"Error creating node: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/registry/nodes")
async def get_nodes():
    """Get all nodes"""
    try:
        nodes = await registry_manager.get_nodes()
        return {
            "nodes": nodes,
            "total": len(nodes)
        }
    except Exception as e:
        logger.error(f"Error fetching nodes: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch nodes")

@app.get("/api/registry/nodes/{node_id}")
async def get_node(node_id: int):
    """Get a specific node"""
    try:
        node = await registry_manager.get_node(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")
        return node
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching node {node_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch node")

@app.put("/api/registry/nodes/{node_id}/status")
async def update_node_status(node_id: int, status: str):
    """Update node status"""
    try:
        node_status = NodeStatus(status)
        node = await registry_manager.update_node_status(node_id, node_status)
        return {
            "success": True,
            "message": f"Node '{node.name}' status updated to {status}",
            "node": node.to_dict()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating node status {node_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update node status")

@app.get("/api/registry/nodes/{node_id}/summary")
async def get_node_summary(node_id: int):
    """Get comprehensive summary of a node"""
    try:
        summary = await registry_manager.get_node_summary(node_id)
        return summary
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting node summary {node_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get node summary")

# Service Pods
@app.post("/api/registry/pods")
async def create_service_pod(pod_data: dict):
    """Create a new service pod"""
    try:
        pod = await registry_manager.create_service_pod(pod_data)
        return {
            "success": True,
            "message": f"Service pod '{pod.name}' created successfully",
            "pod": pod.to_dict()
        }
    except Exception as e:
        logger.error(f"Error creating service pod: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/registry/pods")
async def get_service_pods(namespace_id: Optional[int] = None):
    """Get all service pods, optionally filtered by namespace"""
    try:
        pods = await registry_manager.get_service_pods(namespace_id)
        return {
            "pods": pods,
            "total": len(pods)
        }
    except Exception as e:
        logger.error(f"Error fetching service pods: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch service pods")

@app.get("/api/registry/pods/{pod_id}")
async def get_service_pod(pod_id: int):
    """Get a specific service pod"""
    try:
        pod = await registry_manager.get_service_pod(pod_id)
        if not pod:
            raise HTTPException(status_code=404, detail="Service pod not found")
        return pod
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching service pod {pod_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch service pod")

@app.put("/api/registry/pods/{pod_id}/status")
async def update_pod_status(pod_id: int, status: str):
    """Update pod status"""
    try:
        pod_status = PodStatus(status)
        pod = await registry_manager.update_pod_status(pod_id, pod_status)
        return {
            "success": True,
            "message": f"Pod '{pod.name}' status updated to {status}",
            "pod": pod.to_dict()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating pod status {pod_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update pod status")

@app.delete("/api/registry/pods/{pod_id}")
async def delete_service_pod(pod_id: int):
    """Delete a service pod"""
    try:
        success = await registry_manager.delete_service_pod(pod_id)
        return {
            "success": success,
            "message": "Service pod deleted successfully"
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error deleting service pod {pod_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete service pod")

# Registry Overview
@app.get("/api/registry/overview")
async def get_registry_overview():
    """Get overview of the entire registry"""
    try:
        boundaries = await registry_manager.get_virtual_boundaries()
        namespaces = await registry_manager.get_namespaces()
        nodes = await registry_manager.get_nodes()
        pods = await registry_manager.get_service_pods()
        
        return {
            "summary": {
                "total_boundaries": len(boundaries),
                "total_namespaces": len(namespaces),
                "total_nodes": len(nodes),
                "total_pods": len(pods),
                "active_pods": len([pod for pod in pods if pod.get('status') == 'running']),
                "ready_nodes": len([node for node in nodes if node.get('status') == 'ready'])
            },
            "boundaries": boundaries,
            "namespaces": namespaces,
            "nodes": nodes,
            "pods": pods
        }
    except Exception as e:
        logger.error(f"Error getting registry overview: {e}")
        raise HTTPException(status_code=500, detail="Failed to get registry overview")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001) 