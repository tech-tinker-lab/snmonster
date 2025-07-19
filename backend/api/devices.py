"""
Device-related API endpoints (router).
"""
from fastapi import APIRouter, WebSocket, HTTPException, Depends
from services.device_service import DeviceService
from schemas.device import DeviceSchema

router = APIRouter(prefix="/api/devices", tags=["devices"])

device_service = DeviceService()

# Example endpoint (to be expanded)
@router.get("/all")
async def get_all_devices():
    return await device_service.get_all_devices()

# ...other device endpoints (to be refactored from main.py)

# WebSocket shell endpoint (to be refactored)
# @router.websocket("/{device_id}/shell")
# async def device_shell(websocket: WebSocket, device_id: int):
#     await device_service.device_shell(websocket, device_id)
