from fastapi import APIRouter, HTTPException, Body
from services.registry_service import RegistryService
from typing import Dict, Any

router = APIRouter(prefix="/api/registry", tags=["Registry"])

@router.post("/run-automation")
async def run_automation(request: Dict[str, Any] = Body(...)):
    """Run a registry automation script"""
    try:
        result = RegistryService.run_automation(request)
        return {"success": True, "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
