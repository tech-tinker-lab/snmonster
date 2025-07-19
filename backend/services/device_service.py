"""
Device service: business logic for device operations.
"""

from .device_shell_service import DeviceShellService

class DeviceService:
    def __init__(self):
        self.shell_service = DeviceShellService()

    async def get_all_devices(self):
        # TODO: Implement actual DB logic
        return []

    async def device_shell(self, websocket, device_id):
        await self.shell_service.device_shell(websocket, device_id)
