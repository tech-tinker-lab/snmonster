# ...existing code...


from fastapi import FastAPI, HTTPException

# ...existing code...

# FastAPI app initialization (after lifespan is defined)


from fastapi import FastAPI, HTTPException

# FastAPI app initialization (after lifespan is defined)

# (app = FastAPI and register_category_endpoints(app) are defined after lifespan)
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
from models import Device, DeviceStatus, DeviceType, OperatingSystem, BoundaryType, NamespaceStatus, PodStatus, NodeStatus, SecurityAuditReport
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

# Security Audit Helper Functions
async def run_security_audit_on_device(device: Device, audit_id: str) -> dict:
    """Run security audit script on a device via SSH and collect results"""
    import paramiko
    import json
    import tempfile
    
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to device
        logger.info(f"Connecting to device {device.ip_address} for security audit")
        ssh.connect(
            hostname=device.ip_address,
            username=device.ssh_username,
            password=device.get_ssh_password(),
            timeout=30
        )
        
        # Transfer security audit script
        script_path = os.path.join(AUTOMATIONS_DIR, 'security_audit.sh')
        remote_script_path = f'/tmp/security_audit_{audit_id}.sh'
        
        # Copy script to remote device
        sftp = ssh.open_sftp()
        sftp.put(script_path, remote_script_path)
        sftp.close()
        
        # Make script executable and run it
        logger.info(f"Running security audit on device {device.ip_address}")
        commands = [
            f'chmod +x {remote_script_path}',
            f'{remote_script_path}'
        ]
        
        audit_results = {}
        for command in commands:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=300)  # 5 minute timeout
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error_msg = stderr.read().decode()
                logger.error(f"Command failed on {device.ip_address}: {error_msg}")
                continue
        
        # Collect audit results
        logger.info(f"Collecting audit results from device {device.ip_address}")
        
        # Find the audit directory created by the script
        stdin, stdout, stderr = ssh.exec_command("ls -1t /tmp/security_audit_* | head -1")
        audit_dir = stdout.read().decode().strip()
        
        if audit_dir:
            # Collect all audit files
            audit_files = [
                'system_info.txt',
                'network_analysis.txt', 
                'ports_services.txt',
                'process_analysis.txt',
                'security_analysis.txt',
                'package_analysis.txt',
                'network_traffic.txt',
                'ai_summary.txt'
            ]
            
            raw_files = {}
            for file_name in audit_files:
                file_path = f"{audit_dir}/{file_name}"
                stdin, stdout, stderr = ssh.exec_command(f"cat {file_path}")
                file_content = stdout.read().decode()
                
                if file_content:
                    audit_results[file_name.replace('.txt', '')] = file_content
                    raw_files[file_name] = file_content
            
            audit_results['raw_files'] = json.dumps(raw_files)
            
            # Clean up remote files
            ssh.exec_command(f"rm -rf {audit_dir} {remote_script_path}")
        
        ssh.close()
        
        logger.info(f"Security audit completed successfully for device {device.ip_address}")
        return {
            "success": True,
            **audit_results
        }
        
    except Exception as e:
        logger.error(f"Security audit failed for device {device.ip_address}: {e}")
        return {
            "success": False,
            "error": str(e)
        }

def calculate_security_scores(audit_result: dict) -> dict:
    """Calculate security scores based on audit results"""
    scores = {
        "overall": 75.0,
        "system_updates": 80.0,
        "network_security": 70.0,
        "user_accounts": 85.0,
        "file_permissions": 90.0,
        "critical_issues": 0,
        "warnings": 0
    }
    
    try:
        # Parse AI summary for specific metrics
        ai_summary = audit_result.get('ai_summary', '')
        
        if ai_summary:
            # Count open ports (affects network security score)
            if 'Open ports count:' in ai_summary:
                open_ports = int(ai_summary.split('Open ports count: ')[1].split('\n')[0])
                if open_ports > 10:
                    scores["network_security"] -= 20
                    scores["warnings"] += 1
                elif open_ports > 5:
                    scores["network_security"] -= 10
            
            # Check failed login attempts (affects user accounts score)
            if 'Failed login attempts' in ai_summary:
                failed_logins = int(ai_summary.split('Failed login attempts (last 24h): ')[1].split('\n')[0])
                if failed_logins > 10:
                    scores["user_accounts"] -= 30
                    scores["critical_issues"] += 1
                elif failed_logins > 0:
                    scores["user_accounts"] -= 10
                    scores["warnings"] += 1
            
            # Check high CPU/memory processes
            if 'High CPU processes:' in ai_summary:
                high_cpu = int(ai_summary.split('High CPU processes: ')[1].split('\n')[0])
                if high_cpu > 0:
                    scores["overall"] -= 10
                    scores["warnings"] += high_cpu
            
            # Check memory usage
            if 'Memory usage:' in ai_summary:
                memory_usage = float(ai_summary.split('Memory usage: ')[1].split('%')[0])
                if memory_usage > 90:
                    scores["overall"] -= 15
                    scores["critical_issues"] += 1
                elif memory_usage > 80:
                    scores["overall"] -= 5
                    scores["warnings"] += 1
            
            # Check disk usage
            if 'Disk usage:' in ai_summary:
                disk_usage = float(ai_summary.split('Disk usage: ')[1].split('%')[0])
                if disk_usage > 95:
                    scores["overall"] -= 20
                    scores["critical_issues"] += 1
                elif disk_usage > 85:
                    scores["overall"] -= 10
                    scores["warnings"] += 1
        
        # Calculate overall score as average of category scores
        category_scores = [
            scores["system_updates"],
            scores["network_security"], 
            scores["user_accounts"],
            scores["file_permissions"]
        ]
        scores["overall"] = sum(category_scores) / len(category_scores)
        
        # Ensure scores don't go below 0
        for key in scores:
            if isinstance(scores[key], float) and scores[key] < 0:
                scores[key] = 0.0
                
    except Exception as e:
        logger.error(f"Error calculating security scores: {e}")
    
    return scores

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



from api import devices_router, device_shell_router, rock5b_router, categories_router, device_category_router, device_bulk_router, device_scan_router, websocket_router, ai_admin_router, registry_router


app = FastAPI(
    title="Network Admin System",
    description="AI-Powered Network Device Management and Administration with Virtual Boundaries and Container Orchestration",
    version="2.0.0",
    lifespan=lifespan
)

# Register routers
app.include_router(devices_router)
app.include_router(device_shell_router)
app.include_router(rock5b_router)
app.include_router(categories_router)
app.include_router(device_category_router)
app.include_router(device_bulk_router)
app.include_router(device_scan_router)
app.include_router(websocket_router)
app.include_router(ai_admin_router)
app.include_router(registry_router)

# CORS middleware - Allow all origins for development and flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
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

@app.post("/api/devices/system-update")
async def run_bulk_system_update(request_data: dict):
    """Run system update on a group of devices"""
    try:
        device_ids = request_data.get("device_ids", [])
        
        if not device_ids:
            raise HTTPException(status_code=400, detail="Device IDs are required")
        
        db = get_db()
        success_count = 0
        
        for device_id in device_ids:
            device = db.query(Device).filter(
                Device.id == device_id,
                Device.is_managed == True
            ).first()
            
            if device and device.ssh_username and device.get_ssh_password():
                try:
                    # Run system update script via SSH
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    ssh.connect(
                        hostname=device.ip_address,
                        username=device.ssh_username,
                        password=device.get_ssh_password(),
                        timeout=30
                    )
                    
                    # Execute update commands (example for Debian/Ubuntu)
                    update_commands = [
                        "apt-get update -y",
                        "apt-get upgrade -y",
                        "apt-get dist-upgrade -y",
                        "apt-get autoremove -y",
                        "apt-get clean"
                    ]
                    
                    for command in update_commands:
                        stdin, stdout, stderr = ssh.exec_command(command, timeout=300)
                        exit_status = stdout.channel.recv_exit_status()
                        
                        if exit_status != 0:
                            error_msg = stderr.read().decode()
                            logger.error(f"Command failed on {device.ip_address}: {error_msg}")
                            break
                    else:
                        success_count += 1
                    
                    ssh.close()
                    
                except Exception as e:
                    logger.error(f"Error updating device {device.id}: {e}")
        
        return {
            "success": True,
            "summary": {
                "total_devices": len(device_ids),
                "successful_updates": success_count,
                "failed_updates": len(device_ids) - success_count
            }
        }
    except Exception as e:
        logger.error(f"Error running bulk system update: {e}")
        raise HTTPException(status_code=500, detail="Failed to run system updates on devices")

@app.post("/api/devices/system-update-status")
async def get_system_update_status(request_data: dict):
    """Get system update status and information for devices"""
    try:
        device_ids = request_data.get("device_ids", [])
        
        if not device_ids:
            raise HTTPException(status_code=400, detail="Device IDs are required")
        
        db = get_db()
        status_results = []
        
        for device_id in device_ids:
            device = db.query(Device).filter(
                Device.id == device_id,
                Device.is_managed == True
            ).first()
            
            if device and device.ssh_username and device.get_ssh_password():
                try:
                    # Check current system status via SSH
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    ssh.connect(
                        hostname=device.ip_address,
                        username=device.ssh_username,
                        password=device.get_ssh_password(),
                        timeout=30
                    )
                    
                    # Quick system status check
                    status_commands = {
                        "os_info": "cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2",
                        "kernel": "uname -r",
                        "architecture": "uname -m",
                        "uptime": "uptime -s",
                        "package_manager": "which apt || which yum || which dnf || which pacman || echo 'unknown'",
                        "updates_available": "apt list --upgradable 2>/dev/null | grep -c upgradable || echo '0'",
                        "disk_usage": "df / | tail -1 | awk '{print $5}'",
                        "memory_usage": "free | grep Mem | awk '{printf \"%.1f%%\", $3/$2 * 100.0}'"
                    }
                    
                    system_info = {}
                    for key, command in status_commands.items():
                        try:
                            stdin, stdout, stderr = ssh.exec_command(command, timeout=10)
                            output = stdout.read().decode().strip()
                            system_info[key] = output if output else "unknown"
                        except:
                            system_info[key] = "unknown"
                    
                    ssh.close()
                    
                    # Determine if updates are needed
                    updates_available = 0
                    try:
                        updates_available = int(system_info.get("updates_available", "0"))
                    except:
                        pass
                    
                    update_status = "up_to_date" if updates_available == 0 else "updates_available"
                    
                    status_results.append({
                        "device_id": device.id,
                        "ip_address": device.ip_address,
                        "hostname": device.hostname,
                        "status": "online",
                        "update_status": update_status,
                        "updates_available": updates_available,
                        "system_info": system_info,
                        "last_checked": datetime.now().isoformat()
                    })
                    
                except Exception as e:
                    logger.error(f"Error checking system status for device {device.id}: {e}")
                    status_results.append({
                        "device_id": device.id,
                        "ip_address": device.ip_address,
                        "hostname": device.hostname,
                        "status": "offline",
                        "update_status": "unknown",
                        "error": str(e),
                        "last_checked": datetime.now().isoformat()
                    })
            else:
                status_results.append({
                    "device_id": device.id,
                    "ip_address": device.ip_address if device else "unknown",
                    "hostname": device.hostname if device else "unknown",
                    "status": "unavailable",
                    "update_status": "unknown",
                    "message": "Device not found or missing SSH credentials"
                })
        
        return {
            "success": True,
            "status_results": status_results,
            "summary": {
                "total_devices": len(device_ids),
                "online_devices": len([r for r in status_results if r['status'] == 'online']),
                "devices_needing_updates": len([r for r in status_results if r.get('update_status') == 'updates_available'])
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting system update status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system update status")

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



if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8004))
    uvicorn.run(app, host="0.0.0.0", port=port)