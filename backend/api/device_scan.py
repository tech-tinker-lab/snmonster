from fastapi import APIRouter, HTTPException, Body
from services.device_scan_service import DeviceScanService
from models import Device
from database import get_db
from typing import List

router = APIRouter(prefix="/api/devices/scan", tags=["Device Scan"])

@router.post("")
async def scan_devices(device_ids: List[int] = Body(...)):
    """Scan multiple devices for open ports and vulnerabilities"""
    try:
        db = get_db()
        devices = db.query(Device).filter(Device.id.in_(device_ids)).all()
        if not devices:
            raise HTTPException(status_code=404, detail="No devices found")
        results = DeviceScanService.scan_devices(devices)
        return {"success": True, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
