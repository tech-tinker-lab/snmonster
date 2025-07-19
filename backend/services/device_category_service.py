"""
Business logic for assigning/removing categories to/from devices.
"""
from database import get_db
from models import Device, Category
from fastapi import HTTPException

class DeviceCategoryService:
    async def assign_category(self, device_id: int, category_id: int):
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        category = db.query(Category).filter(Category.id == category_id).first()
        if not category:
            raise HTTPException(status_code=404, detail="Category not found")
        device.category_id = category_id
        db.commit()
        return {"success": True, "device_id": device_id, "category_id": category_id}

    async def remove_category(self, device_id: int):
        db = get_db()
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        device.category_id = None
        db.commit()
        return {"success": True, "device_id": device_id, "category_id": None}
