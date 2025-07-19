# API routers package

# API routers package

from .devices import router as devices_router
from .device_shell import router as device_shell_router
from .device_category import router as device_category_router
from .categories import router as categories_router
from .device_bulk import router as device_bulk_router
from .device_scan import router as device_scan_router
from .websocket import router as websocket_router
from .ai_admin import router as ai_admin_router
from .registry import router as registry_router
from .rock5b import router as rock5b_router
# ...import other routers as needed
