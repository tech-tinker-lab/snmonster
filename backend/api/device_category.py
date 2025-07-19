"""
API endpoints for assigning/removing categories to/from devices.
"""
from fastapi import APIRouter, HTTPException, Body
from services.device_category_service import DeviceCategoryService

router = APIRouter(prefix="/api/devices", tags=["device-category"])
device_category_service = DeviceCategoryService()

@router.put("/{device_id}/category")
async def assign_category(device_id: int, category_id: int = Body(...)):
    return await device_category_service.assign_category(device_id, category_id)

@router.delete("/{device_id}/category")
async def remove_category(device_id: int):
    return await device_category_service.remove_category(device_id)
