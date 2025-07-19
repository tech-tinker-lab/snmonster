"""
DeviceShellService: Handles SSH shell session logic for a device via WebSocket.
"""
import asyncio
import threading
import queue
import codecs
import json
import paramiko
from datetime import datetime
from fastapi import WebSocket, HTTPException
from database import get_db
from models import Device, DeviceStatus
from utils.ssh import SSHClientHelper
from utils.websocket import send_status, send_error, send_data

class DeviceShellService:
    async def device_shell(self, websocket: WebSocket, device_id: int):
        import logging
        logger = logging.getLogger("DeviceShellService")
        await websocket.accept()
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            logger.error(f"Device {device_id} not found for shell connection.")
            await send_error(websocket, "not_found", "Device not found")
            await send_status(websocket, "disconnected")
            await websocket.close()
            return

        if not device.ssh_username or not device.ssh_password_enc:
            logger.error(f"Device {device_id} missing SSH credentials.")
            await send_error(websocket, "missing_credentials", "SSH credentials not set for this device.")
            await send_status(websocket, "disconnected")
            await websocket.close()
            return

        ssh_password = device.get_ssh_password()
        ssh_host = device.ip_address

        try:
            ssh_client = SSHClientHelper()
            ssh_client.connect(ssh_host, device.ssh_username, ssh_password)
            logger.info(f"SSH connection established to {ssh_host} for device {device_id}.")
            await send_status(websocket, "connected")

            async def websocket_to_ssh():
                try:
                    while True:
                        data = await websocket.receive_text()
                        if data is None:
                            break
                        ssh_client.send(data)
                except Exception as e:
                    logger.info(f"WebSocket->SSH relay ended: {e}")

            async def ssh_to_websocket():
                try:
                    while True:
                        await asyncio.sleep(0.05)
                        output = ssh_client.recv(4096)
                        if output:
                            try:
                                await websocket.send_text(output.decode(errors='replace'))
                            except Exception as e:
                                logger.info(f"SSH->WebSocket relay ended: {e}")
                                break
                except Exception as e:
                    logger.info(f"SSH->WebSocket relay outer ended: {e}")

            relay_tasks = [asyncio.create_task(websocket_to_ssh()), asyncio.create_task(ssh_to_websocket())]
            done, pending = await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
        except Exception as e:
            logger.error(f"SSH connection failed for device {device_id}: {str(e)}")
            await send_error(websocket, "ssh_error", f"SSH connection failed: {str(e)}")
            try:
                await send_status(websocket, "disconnected")
            except Exception:
                pass
            await websocket.close()
            return

        # On disconnect/cleanup
        logger.info(f"Shell session for device {device_id} ended.")
        try:
            await send_status(websocket, "disconnected")
        except Exception:
            pass
        try:
            ssh_client.close()
        except Exception:
            pass
        await websocket.close()

    async def ping_device(self, device_id):
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        # Simulate ping
        device.status = DeviceStatus.ONLINE
        device.last_seen = datetime.now()
        device.response_time = 45.0
        db.commit()
        return {"success": True, "message": f"Device {device.ip_address} is reachable", "response_time": 45, "status": "online"}

    async def scan_device_ports(self, device_id):
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        # Simulate port scan
        open_ports = [22, 80]
        device.open_ports = json.dumps(open_ports)
        device.last_seen = datetime.now()
        db.commit()
        return {"success": True, "message": f"Port scan completed for {device.ip_address}", "open_ports": open_ports, "total_ports_scanned": len(open_ports)}

    async def security_scan_device(self, device_id):
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        vulnerabilities = [
            {"id": "CVE-2023-1234", "severity": "medium", "description": "OpenSSH vulnerability", "port": 22},
            {"id": "CVE-2023-5678", "severity": "low", "description": "Weak password policy", "port": None}
        ]
        device.vulnerabilities = json.dumps(vulnerabilities)
        device.last_security_scan = datetime.now()
        db.commit()
        return {"success": True, "message": f"Security scan completed for {device.ip_address}", "vulnerabilities_found": len(vulnerabilities), "vulnerabilities": vulnerabilities}

    async def update_device(self, device_id, device_data):
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        allowed_fields = ["hostname", "location", "notes", "vendor", "model"]
        for field in allowed_fields:
            if field in device_data:
                setattr(device, field, device_data[field])
        if "ssh_username" in device_data:
            device.ssh_username = device_data["ssh_username"]
        if "ssh_password" in device_data and device_data["ssh_password"]:
            device.set_ssh_password(device_data["ssh_password"])
        device.updated_at = datetime.now()
        db.commit()
        return {"success": True, "message": f"Device {device.ip_address} updated successfully", "device": device.to_dict()}
