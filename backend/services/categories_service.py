"""
Business logic for device category management.
"""
from database import get_db
from models import Category, Device
from fastapi import HTTPException

class CategoriesService:
    async def create_category(self, name: str, description: str):
        db = get_db()
        if db.query(Category).filter(Category.name == name).first():
            raise HTTPException(status_code=400, detail="Category already exists")
        category = Category(name=name, description=description)
        db.add(category)
        db.commit()
        db.refresh(category)
        return {"success": True, "category": {"id": category.id, "name": category.name, "description": category.description}}

    async def list_categories(self):
        db = get_db()
        categories = db.query(Category).all()
        return {"categories": [{"id": c.id, "name": c.name, "description": c.description} for c in categories]}

    async def delete_category(self, category_id: int):
        db = get_db()
        category = db.query(Category).filter(Category.id == category_id).first()
        if not category:
            raise HTTPException(status_code=404, detail="Category not found")
        for device in category.devices:
            device.category_id = None
        db.delete(category)
        db.commit()
        return {"success": True, "deleted_category_id": category_id}
