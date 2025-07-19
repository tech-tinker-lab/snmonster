"""
WebSocket endpoint for SSH shell access to a device (modularized).
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from services.device_service import DeviceService
from fastapi import Body
from services.device_shell_service import DeviceShellService

router = APIRouter(prefix="/api/devices", tags=["devices"])

device_service = DeviceService()
device_shell_service = DeviceShellService()

@router.websocket("/{device_id}/shell")
async def device_shell(websocket: WebSocket, device_id: int):
    await device_service.device_shell(websocket, device_id)

@router.post("/{device_id}/ping")
async def ping_device(device_id: int):
    return await device_shell_service.ping_device(device_id)

@router.post("/{device_id}/scan-ports")
async def scan_device_ports(device_id: int):
    return await device_shell_service.scan_device_ports(device_id)

@router.post("/{device_id}/security-scan")
async def security_scan_device(device_id: int):
    return await device_shell_service.security_scan_device(device_id)

@router.put("/{device_id}")
async def update_device(device_id: int, device_data: dict = Body(...)):
    return await device_shell_service.update_device(device_id, device_data)
