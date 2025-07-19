from fastapi import APIRouter, HTTPException, Body
from services.ai_admin_service import AIAdminService
from typing import Dict, Any

router = APIRouter(prefix="/api/ai-admin", tags=["AI Admin"])

@router.post("/run-task")
async def run_ai_task(request: Dict[str, Any] = Body(...)):
    """Run an AI admin task"""
    try:
        result = AIAdminService.run_task(request)
        return {"success": True, "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
