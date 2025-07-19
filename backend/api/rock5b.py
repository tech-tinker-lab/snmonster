"""
API endpoints for Rock 5B device management.
"""
from fastapi import APIRouter, HTTPException, Body
from services.rock5b_service import Rock5BService

router = APIRouter(prefix="/api/rock5b", tags=["rock5b"])
rock5b_service = Rock5BService()

@router.get("/devices")
async def get_rock5b_devices():
    return await rock5b_service.get_rock5b_devices()

@router.post("/{device_id}/power-on")
async def power_on_rock5b(device_id: int):
    return await rock5b_service.power_on(device_id)

@router.post("/{device_id}/shutdown")
async def shutdown_rock5b(device_id: int):
    return await rock5b_service.shutdown(device_id)

@router.get("/{device_id}/status")
async def get_rock5b_status(device_id: int):
    return await rock5b_service.get_status(device_id)

@router.post("/setup-device2")
async def setup_rock5b_device2(device_data: dict = Body(...)):
    return await rock5b_service.setup_device2(device_data)
