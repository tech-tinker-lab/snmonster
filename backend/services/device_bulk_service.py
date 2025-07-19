from fastapi import HTTPException
from database import get_db
from models import Device, SecurityAuditReport
from datetime import datetime
import json

class DeviceBulkService:
    @staticmethod
    async def mark_devices_as_managed(device_ids):
        db = get_db()
        updated_count = 0
        for device_id in device_ids:
            device = db.query(Device).filter(Device.id == device_id).first()
            if device:
                device.is_managed = True
                device.updated_at = datetime.now()
                updated_count += 1
        db.commit()
        return {"success": True, "message": f"Successfully marked {updated_count} devices as managed", "updated_count": updated_count}

    @staticmethod
    async def unmark_devices_as_managed(device_ids):
        db = get_db()
        updated_count = 0
        for device_id in device_ids:
            device = db.query(Device).filter(Device.id == device_id).first()
            if device:
                device.is_managed = False
                device.updated_at = datetime.now()
                updated_count += 1
        db.commit()
        return {"success": True, "message": f"Successfully unmarked {updated_count} devices as managed", "updated_count": updated_count}

    @staticmethod
    async def bulk_set_password(request_data):
        device_ids = request_data.get("device_ids", [])
        password = request_data.get("password", "")
        if not device_ids or not password:
            raise HTTPException(status_code=400, detail="Device IDs and password are required")
        db = get_db()
        updated_count = 0
        for device_id in device_ids:
            device = db.query(Device).filter(Device.id == device_id, Device.is_managed == True).first()
            if device:
                device.set_ssh_password(password)
                device.updated_at = datetime.now()
                updated_count += 1
        db.commit()
        return {"success": True, "message": f"Successfully set password for {updated_count} devices", "updated_count": updated_count}

    @staticmethod
    async def bulk_install_docker(request_data):
        # Placeholder for Docker install logic
        return {"success": True, "message": "Docker installation initiated (mock)", "results": []}

    @staticmethod
    async def bulk_install_ansible(request_data):
        # Placeholder for Ansible install logic
        return {"success": True, "message": "Ansible installation initiated (mock)", "results": []}

    @staticmethod
    async def bulk_security_audit(request_data):
        # Placeholder for security audit logic
        return {"success": True, "message": "Security audit initiated (mock)", "results": []}

    @staticmethod
    async def get_security_reports(request_data):
        # Placeholder for security reports logic
        return {"success": True, "reports": [], "summary": {}}

    @staticmethod
    async def bulk_system_update(request_data):
        # Placeholder for system update logic
        return {"success": True, "message": "System update completed (mock)", "results": [], "summary": {}}

    @staticmethod
    async def get_system_update_status(request_data):
        # Placeholder for system update status logic
        return {"success": True, "status_results": [], "summary": {}}
