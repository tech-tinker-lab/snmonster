"""
Pydantic schemas for device API.
"""
from pydantic import BaseModel

class DeviceSchema(BaseModel):
    id: int
    ip_address: str
    hostname: str
    # ...add other fields as needed

    class Config:
        orm_mode = True
