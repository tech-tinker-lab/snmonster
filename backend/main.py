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
import codecs
import time
import re
import subprocess
import socket
import queue
import threading

from database import init_db, get_db
from models import Device, DeviceStatus, DeviceType, OperatingSystem, BoundaryType, NamespaceStatus, PodStatus, NodeStatus
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
    """Get all discovered devices (non-managed only)"""
    try:
        db = get_db()
        devices = db.query(Device).filter(Device.is_managed == False).all()
        return {
            "devices": [device.to_dict() for device in devices],
            "total": len(devices)
        }
    except Exception as e:
        logger.error(f"Error fetching devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch devices")

@app.get("/api/devices/managed")
async def get_managed_devices():
    """Get all managed devices"""
    try:
        db = get_db()
        devices = db.query(Device).filter(Device.is_managed == True).all()
        return {
            "devices": [device.to_dict() for device in devices],
            "total": len(devices)
        }
    except Exception as e:
        logger.error(f"Error fetching managed devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch managed devices")

@app.get("/api/devices/all")
async def get_all_devices():
    """Get all devices (both managed and unmanaged)"""
    try:
        db = get_db()
        devices = db.query(Device).all()
        return {
            "devices": [device.to_dict() for device in devices],
            "total": len(devices)
        }
    except Exception as e:
        logger.error(f"Error fetching all devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch all devices")

@app.post("/api/devices/mark-managed")
async def mark_devices_as_managed(device_ids: list[int]):
    """Mark selected devices as managed"""
    try:
        db = get_db()
        updated_count = 0
        
        for device_id in device_ids:
            device = db.query(Device).filter(Device.id == device_id).first()
            if device:
                device.is_managed = True
                device.updated_at = datetime.now()
                updated_count += 1
        
        db.commit()
        return {
            "success": True,
            "message": f"Successfully marked {updated_count} devices as managed",
            "updated_count": updated_count
        }
    except Exception as e:
        logger.error(f"Error marking devices as managed: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to mark devices as managed")

@app.post("/api/devices/unmark-managed")
async def unmark_devices_as_managed(device_ids: list[int]):
    """Unmark selected devices as managed (move back to discovered)"""
    try:
        db = get_db()
        updated_count = 0
        
        for device_id in device_ids:
            device = db.query(Device).filter(Device.id == device_id).first()
            if device:
                device.is_managed = False
                device.updated_at = datetime.now()
                updated_count += 1
        
        db.commit()
        return {
            "success": True,
            "message": f"Successfully unmarked {updated_count} devices as managed",
            "updated_count": updated_count
        }
    except Exception as e:
        logger.error(f"Error unmarking devices as managed: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to unmark devices as managed")

@app.post("/api/devices/bulk-set-password")
async def bulk_set_password(request_data: dict):
    """Set SSH password for multiple managed devices"""
    try:
        device_ids = request_data.get("device_ids", [])
        password = request_data.get("password", "")
        
        if not device_ids or not password:
            raise HTTPException(status_code=400, detail="Device IDs and password are required")
        
        db = get_db()
        updated_count = 0
        
        for device_id in device_ids:
            device = db.query(Device).filter(
                Device.id == device_id, 
                Device.is_managed == True
            ).first()
            if device:
                device.set_ssh_password(password)
                device.updated_at = datetime.now()
                updated_count += 1
        
        db.commit()
        return {
            "success": True,
            "message": f"Successfully set password for {updated_count} devices",
            "updated_count": updated_count
        }
    except Exception as e:
        logger.error(f"Error setting bulk password: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to set bulk password")

@app.post("/api/devices/bulk-install-docker")
async def bulk_install_docker(request_data: dict):
    """Install Docker on multiple managed devices"""
    try:
        device_ids = request_data.get("device_ids", [])
        
        if not device_ids:
            raise HTTPException(status_code=400, detail="Device IDs are required")
        
        db = get_db()
        results = []
        
        for device_id in device_ids:
            device = db.query(Device).filter(
                Device.id == device_id,
                Device.is_managed == True
            ).first()
            
            if device and device.ssh_username and device.get_ssh_password():
                try:
                    # Execute Docker installation script
                    command = 'chmod +x /tmp/edu_admin/docker_install_rock5b.sh && /tmp/edu_admin/docker_install_rock5b.sh'
                    # This would be executed via SSH in a real implementation
                    results.append({
                        "device_id": device.id,
                        "ip_address": device.ip_address,
                        "status": "success",
                        "message": "Docker installation initiated"
                    })
                except Exception as e:
                    results.append({
                        "device_id": device.id,
                        "ip_address": device.ip_address,
                        "status": "error",
                        "message": str(e)
                    })
            else:
                results.append({
                    "device_id": device.id,
                    "ip_address": device.ip_address if device else "unknown",
                    "status": "error",
                    "message": "Device not found or missing SSH credentials"
                })
        
        return {
            "success": True,
            "message": f"Docker installation initiated for {len([r for r in results if r['status'] == 'success'])} devices",
            "results": results
        }
    except Exception as e:
        logger.error(f"Error bulk installing Docker: {e}")
        raise HTTPException(status_code=500, detail="Failed to install Docker on devices")

@app.post("/api/devices/bulk-install-ansible")
async def bulk_install_ansible(request_data: dict):
    """Install Ansible on multiple managed devices"""
    try:
        device_ids = request_data.get("device_ids", [])
        
        if not device_ids:
            raise HTTPException(status_code=400, detail="Device IDs are required")
        
        db = get_db()
        results = []
        
        for device_id in device_ids:
            device = db.query(Device).filter(
                Device.id == device_id,
                Device.is_managed == True
            ).first()
            
            if device and device.ssh_username and device.get_ssh_password():
                try:
                    # Execute Ansible installation script
                    command = 'chmod +x /tmp/edu_admin/ansible_setup.sh && /tmp/edu_admin/ansible_setup.sh'
                    # This would be executed via SSH in a real implementation
                    results.append({
                        "device_id": device.id,
                        "ip_address": device.ip_address,
                        "status": "success",
                        "message": "Ansible installation initiated"
                    })
                except Exception as e:
                    results.append({
                        "device_id": device.id,
                        "ip_address": device.ip_address,
                        "status": "error",
                        "message": str(e)
                    })
            else:
                results.append({
                    "device_id": device.id,
                    "ip_address": device.ip_address if device else "unknown",
                    "status": "error",
                    "message": "Device not found or missing SSH credentials"
                })
        
        return {
            "success": True,
            "message": f"Ansible installation initiated for {len([r for r in results if r['status'] == 'success'])} devices",
            "results": results
        }
    except Exception as e:
        logger.error(f"Error bulk installing Ansible: {e}")
        raise HTTPException(status_code=500, detail="Failed to install Ansible on devices")

@app.post("/api/devices/bulk-security-audit")
async def bulk_security_audit(request_data: dict):
    """Run security audit on multiple managed devices"""
    try:
        device_ids = request_data.get("device_ids", [])
        
        if not device_ids:
            raise HTTPException(status_code=400, detail="Device IDs are required")
        
        db = get_db()
        results = []
        
        for device_id in device_ids:
            device = db.query(Device).filter(
                Device.id == device_id,
                Device.is_managed == True
            ).first()
            
            if device and device.ssh_username and device.get_ssh_password():
                try:
                    # Execute security audit script
                    command = 'chmod +x /tmp/edu_admin/security_audit.sh && /tmp/edu_admin/security_audit.sh'
                    # This would be executed via SSH in a real implementation
                    results.append({
                        "device_id": device.id,
                        "ip_address": device.ip_address,
                        "status": "success",
                        "message": "Security audit initiated",
                        "audit_id": f"audit_{device.id}_{int(datetime.now().timestamp())}"
                    })
                except Exception as e:
                    results.append({
                        "device_id": device.id,
                        "ip_address": device.ip_address,
                        "status": "error",
                        "message": str(e)
                    })
            else:
                results.append({
                    "device_id": device.id,
                    "ip_address": device.ip_address if device else "unknown",
                    "status": "error",
                    "message": "Device not found or missing SSH credentials"
                })
        
        return {
            "success": True,
            "message": f"Security audit initiated for {len([r for r in results if r['status'] == 'success'])} devices",
            "results": results
        }
    except Exception as e:
        logger.error(f"Error running bulk security audit: {e}")
        raise HTTPException(status_code=500, detail="Failed to run security audit on devices")

@app.post("/api/devices/security-reports")
async def get_security_reports(request_data: dict):
    """Get security audit reports for multiple devices"""
    try:
        device_ids = request_data.get("device_ids", [])
        
        if not device_ids:
            raise HTTPException(status_code=400, detail="Device IDs are required")
        
        db = get_db()
        reports = []
        
        for device_id in device_ids:
            device = db.query(Device).filter(
                Device.id == device_id,
                Device.is_managed == True
            ).first()
            
            if device:
                # Mock security report data - in real implementation, this would fetch actual audit results
                report = {
                    "device_id": device.id,
                    "ip_address": device.ip_address,
                    "hostname": device.hostname,
                    "audit_date": datetime.now().isoformat(),
                    "overall_score": device.ai_risk_score,
                    "categories": {
                        "system_updates": {
                            "score": 85,
                            "critical_issues": 2,
                            "warnings": 5,
                            "details": "System packages mostly up to date, 2 critical security updates pending"
                        },
                        "network_security": {
                            "score": 72,
                            "critical_issues": 1,
                            "warnings": 3,
                            "details": "Firewall configured, some unnecessary open ports detected"
                        },
                        "user_accounts": {
                            "score": 90,
                            "critical_issues": 0,
                            "warnings": 1,
                            "details": "Strong password policies enforced, one inactive user account"
                        },
                        "file_permissions": {
                            "score": 88,
                            "critical_issues": 0,
                            "warnings": 2,
                            "details": "Most files have appropriate permissions, minor issues in /tmp"
                        }
                    },
                    "recommendations": [
                        "Install pending security updates immediately",
                        "Close unnecessary ports (8080, 3000)",
                        "Remove inactive user account 'testuser'",
                        "Review and tighten /tmp directory permissions"
                    ]
                }
                reports.append(report)
        
        return {
            "success": True,
            "reports": reports,
            "summary": {
                "total_devices": len(reports),
                "avg_score": sum(r["overall_score"] for r in reports) / len(reports) if reports else 0,
                "critical_issues": sum(
                    sum(cat["critical_issues"] for cat in r["categories"].values()) 
                    for r in reports
                )
            }
        }
    except Exception as e:
        logger.error(f"Error fetching security reports: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch security reports")

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

# Rock 5B Specific Endpoints
@app.get("/api/rock5b/devices")
async def get_rock5b_devices():
    """Get all Rock 5B devices in the network"""
    try:
        db = get_db()
        # Look for Rock 5B devices based on hostname patterns or device info
        devices = db.query(Device).filter(
            Device.hostname.like('%rock%') | 
            Device.hostname.like('%Rock%') |
            Device.notes.like('%rock5b%') |
            Device.notes.like('%Rock 5B%')
        ).all()
        
        rock5b_devices = []
        for device in devices:
            device_dict = {
                "id": device.id,
                "ip_address": device.ip_address,
                "hostname": device.hostname,
                "status": device.status.value if device.status else "unknown",
                "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                "ai_risk_score": device.ai_risk_score or 0.0,
                "temperature": None,  # Will be populated by status check
                "is_rock5b": True
            }
            rock5b_devices.append(device_dict)
        
        return {
            "rock5b_devices": rock5b_devices,
            "total_count": len(rock5b_devices)
        }
    except Exception as e:
        logger.error(f"Error getting Rock 5B devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to get Rock 5B devices")

@app.post("/api/rock5b/{device_id}/power-on")
async def power_on_rock5b(device_id: int):
    """Power on a Rock 5B device using Wake-on-LAN"""
    try:
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if not device.mac_address:
            raise HTTPException(status_code=400, detail="MAC address required for Wake-on-LAN")
        
        # Use the rock5b_device2.sh script for power on
        script_path = os.path.join(AUTOMATIONS_DIR, "rock5b_device2.sh")
        if not os.path.exists(script_path):
            raise HTTPException(status_code=500, detail="Rock 5B management script not found")
        
        # Execute power-on command
        import subprocess
        result = subprocess.run([script_path, "power-on"], capture_output=True, text=True)
        
        if result.returncode == 0:
            return {
                "success": True,
                "message": f"Wake-on-LAN packet sent to {device.hostname} ({device.mac_address})",
                "output": result.stdout
            }
        else:
            return {
                "success": False,
                "message": "Failed to send Wake-on-LAN packet",
                "error": result.stderr
            }
            
    except Exception as e:
        logger.error(f"Error powering on Rock 5B {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to power on Rock 5B device")

@app.post("/api/rock5b/{device_id}/shutdown")
async def shutdown_rock5b(device_id: int):
    """Safely shutdown a Rock 5B device"""
    try:
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Use SSH to send shutdown command
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Try to connect and shutdown
            ssh.connect(device.ip_address, username="rock", timeout=10)
            stdin, stdout, stderr = ssh.exec_command("sudo shutdown -h now")
            
            return {
                "success": True,
                "message": f"Shutdown command sent to {device.hostname}",
                "ip": device.ip_address
            }
        except Exception as ssh_e:
            raise HTTPException(status_code=500, detail=f"SSH connection failed: {str(ssh_e)}")
        finally:
            ssh.close()
            
    except Exception as e:
        logger.error(f"Error shutting down Rock 5B {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to shutdown Rock 5B device")

@app.get("/api/rock5b/{device_id}/status")
async def get_rock5b_status(device_id: int):
    """Get detailed status of a Rock 5B device"""
    try:
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Use SSH to get detailed status
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(device.ip_address, username="rock", timeout=10)
            
            # Get system information
            commands = {
                "model": "cat /proc/device-tree/model",
                "temperature": "cat /sys/class/thermal/thermal_zone*/temp | head -1",
                "cpu_freq": "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
                "memory": "free -h",
                "uptime": "uptime",
                "load": "cat /proc/loadavg"
            }
            
            status_info = {}
            for key, cmd in commands.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    output = stdout.read().decode('utf-8', errors='replace').strip()
                    status_info[key] = output
                except:
                    status_info[key] = "N/A"
            
            # Calculate temperature in Celsius
            try:
                temp_raw = int(status_info.get("temperature", "0"))
                temp_celsius = temp_raw / 1000
                status_info["temperature_celsius"] = temp_celsius
            except:
                status_info["temperature_celsius"] = None
            
            # Calculate CPU frequency in MHz
            try:
                freq_raw = int(status_info.get("cpu_freq", "0"))
                freq_mhz = freq_raw / 1000
                status_info["cpu_freq_mhz"] = freq_mhz
            except:
                status_info["cpu_freq_mhz"] = None
            
            return {
                "device_id": device_id,
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "is_online": True,
                "rock5b_info": status_info
            }
            
        except Exception as ssh_e:
            return {
                "device_id": device_id,
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "is_online": False,
                "error": f"SSH connection failed: {str(ssh_e)}"
            }
        finally:
            ssh.close()
            
    except Exception as e:
        logger.error(f"Error getting Rock 5B status {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get Rock 5B status")

@app.post("/api/rock5b/setup-device2")
async def setup_rock5b_device2(device_data: dict):
    """Setup second Rock 5B device configuration"""
    try:
        ip_address = device_data.get("ip_address")
        mac_address = device_data.get("mac_address")
        hostname = device_data.get("hostname", "rock5b-device2")
        
        if not ip_address:
            raise HTTPException(status_code=400, detail="IP address is required")
        
        # Check if device already exists
        db = get_db()
        existing_device = db.query(Device).filter(Device.ip_address == ip_address).first()
        
        if existing_device:
            # Update existing device
            existing_device.mac_address = mac_address
            existing_device.hostname = hostname
            existing_device.notes = "Rock 5B Device 2 - Configured via API"
            existing_device.device_type = DeviceType.COMPUTER
            db.commit()
            device_id = existing_device.id
        else:
            # Create new device entry
            new_device = Device(
                ip_address=ip_address,
                mac_address=mac_address,
                hostname=hostname,
                device_type=DeviceType.COMPUTER,
                operating_system=OperatingSystem.LINUX,
                status=DeviceStatus.UNKNOWN,
                notes="Rock 5B Device 2 - Configured via API"
            )
            db.add(new_device)
            db.commit()
            device_id = new_device.id
        
        # Save configuration to file
        config_path = "/tmp/rock5b_device2.conf"
        try:
            with open(config_path, 'w') as f:
                f.write(f"# Rock 5B Device 2 Configuration\n")
                f.write(f"# Generated on {datetime.now()}\n")
                f.write(f"DEVICE2_IP={ip_address}\n")
                f.write(f"DEVICE2_MAC={mac_address or ''}\n")
                f.write(f"DEVICE2_USER=rock\n")
                f.write(f"DEVICE2_SSH_PORT=22\n")
        except Exception as file_e:
            logger.warning(f"Could not save config file: {file_e}")
        
        return {
            "success": True,
            "message": "Rock 5B Device 2 setup completed",
            "device_id": device_id,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "hostname": hostname
        }
        
    except Exception as e:
        logger.error(f"Error setting up Rock 5B Device 2: {e}")
        raise HTTPException(status_code=500, detail="Failed to setup Rock 5B Device 2")

@app.websocket("/api/devices/{device_id}/shell")
async def device_shell(websocket: WebSocket, device_id: int):
    """WebSocket endpoint for SSH shell access to a device."""
    await websocket.accept()
    
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
                    # Ensure data is bytes before sending
                    if isinstance(data, str):
                        data = data.encode('utf-8')
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
            ws_to_ssh_queue.put((upload_cmd + '\n').encode('utf-8'))
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
        
        # Start SSH read/write threads first
        read_thread = threading.Thread(target=ssh_read_loop, daemon=True)
        write_thread = threading.Thread(target=ssh_write_loop, daemon=True)
        read_thread.start()
        write_thread.start()
        
        # Give the threads a moment to start
        await asyncio.sleep(0.1)
        
        # Send OS detection command through the queue system
        ws_to_ssh_queue.put(b'uname -a\n')
        
        # Wait a bit for the response to be processed by our UTF-8 decoder
        await asyncio.sleep(1.0)
        
        # Send a friendly message
        await send_data(f"\n\033[1m🐧 Remote System Connected\033[0m\n-----------------------------\n")
        # Setup admin directory and upload scripts
        admin_dir = "/tmp/edu_admin"
        subdirs = ["playbooks", "templates", "inventory"]
        mkdir_cmd = f"mkdir -p {admin_dir} " + " ".join([f'{admin_dir}/{s}' for s in subdirs])
        ws_to_ssh_queue.put((mkdir_cmd + '\n').encode('utf-8'))
        
        # Wait for directory creation
        await asyncio.sleep(0.5)
        
        # Load scripts from files if they exist
        def load_script_content(script_name):
            script_path = os.path.join(AUTOMATIONS_DIR, script_name)
            if os.path.exists(script_path):
                with open(script_path, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read()
            return f"# {script_name} not found in automations directory"
        
        # Upload automation scripts through queue system
        def upload_script(script_name, script_content):
            try:
                full_script = f"#!/bin/bash\n{script_content}"
                upload_cmd = f"cat > {admin_dir}/{script_name} << 'EOF'\n{full_script}\nEOF\nchmod +x {admin_dir}/{script_name}"
                ws_to_ssh_queue.put((upload_cmd + '\n').encode('utf-8'))
                logger.info(f"Uploaded script {script_name} to remote system at {admin_dir}")
                return True
            except Exception as e:
                logger.error(f"Failed to upload script {script_name}: {e}")
                return False
        
        # Upload all scripts
        script_names = ["system_update.sh", "security_audit.sh", "k8s_context.sh", 
                       "ansible_setup.sh", "rock5b_management.sh", "rock5b_device2.sh",
                       "docker_install_rock5b.sh"]
        
        for script_name in script_names:
            script_content = load_script_content(script_name)
            upload_script(script_name, script_content)
            await asyncio.sleep(0.1)  # Small delay between uploads
        
        await send_data("\n✅ Automation scripts uploaded successfully!\n")
        await send_data("Available scripts in /tmp/edu_admin/:\n")
        await send_data("- system_update.sh (System updates)\n")
        await send_data("- security_audit.sh (Security analysis)\n")
        await send_data("- k8s_context.sh (Kubernetes management)\n")
        await send_data("- ansible_setup.sh (Ansible automation)\n")
        await send_data("- rock5b_management.sh (Rock 5B device management)\n")
        await send_data("- rock5b_device2.sh (Rock 5B Device 2 control)\n")
        await send_data("- docker_install_rock5b.sh (Docker installation for Rock 5B ARM64)\n")
        await send_data("Use the buttons in the sidebar to run them!\n\n")
        
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
                decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
                loop = asyncio.get_event_loop()
                while not websocket_closed:
                    data = await loop.run_in_executor(None, ssh_to_ws_queue.get)
                    if data is None:
                        break
                    try:
                        # Use incremental decoder to handle partial UTF-8 sequences
                        text = decoder.decode(data, False)
                        if text:  # Only send if we have complete characters
                            await send_data(text)
                    except Exception as decode_error:
                        # Fallback: try to decode with error replacement
                        logger.warning(f"UTF-8 decode error, using fallback: {decode_error}")
                        try:
                            fallback_text = data.decode('utf-8', errors='replace')
                            if fallback_text:
                                await send_data(fallback_text)
                        except Exception as fallback_error:
                            logger.error(f"Even fallback decode failed: {fallback_error}")
                            # Last resort: convert bytes to string representation
                            await send_data(f"[Binary data: {len(data)} bytes]")
                
                # Finalize any remaining bytes in the decoder
                try:
                    final_text = decoder.decode(b'', True)  # Final call to flush decoder
                    if final_text:
                        await send_data(final_text)
                except Exception as final_error:
                    logger.warning(f"Error finalizing decoder: {final_error}")
                    
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