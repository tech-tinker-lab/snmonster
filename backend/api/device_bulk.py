from fastapi import APIRouter, HTTPException, Body
from services.device_bulk_service import DeviceBulkService

router = APIRouter(prefix="/api/devices", tags=["Device Bulk Operations"])

@router.post("/mark-managed")
async def mark_devices_as_managed(device_ids: list[int] = Body(...)):
    return await DeviceBulkService.mark_devices_as_managed(device_ids)

@router.post("/unmark-managed")
async def unmark_devices_as_managed(device_ids: list[int] = Body(...)):
    return await DeviceBulkService.unmark_devices_as_managed(device_ids)

@router.post("/bulk-set-password")
async def bulk_set_password(request_data: dict = Body(...)):
    return await DeviceBulkService.bulk_set_password(request_data)

@router.post("/bulk-install-docker")
async def bulk_install_docker(request_data: dict = Body(...)):
    return await DeviceBulkService.bulk_install_docker(request_data)

@router.post("/bulk-install-ansible")
async def bulk_install_ansible(request_data: dict = Body(...)):
    return await DeviceBulkService.bulk_install_ansible(request_data)

@router.post("/bulk-security-audit")
async def bulk_security_audit(request_data: dict = Body(...)):
    return await DeviceBulkService.bulk_security_audit(request_data)

@router.post("/security-reports")
async def get_security_reports(request_data: dict = Body(...)):
    return await DeviceBulkService.get_security_reports(request_data)

@router.post("/bulk-system-update")
async def bulk_system_update(request_data: dict = Body(...)):
    return await DeviceBulkService.bulk_system_update(request_data)

@router.post("/system-update-status")
async def get_system_update_status(request_data: dict = Body(...)):
    return await DeviceBulkService.get_system_update_status(request_data)
