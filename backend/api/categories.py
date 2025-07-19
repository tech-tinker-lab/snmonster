"""
API endpoints for device category management.
"""
from fastapi import APIRouter, HTTPException, Body
from services.categories_service import CategoriesService

router = APIRouter(prefix="/api/categories", tags=["categories"])
categories_service = CategoriesService()

@router.post("")
async def create_category(name: str = Body(...), description: str = Body("")):
    return await categories_service.create_category(name, description)

@router.get("")
async def list_categories():
    return await categories_service.list_categories()

@router.delete("/{category_id}")
async def delete_category(category_id: int):
    return await categories_service.delete_category(category_id)
