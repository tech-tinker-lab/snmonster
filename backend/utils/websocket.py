"""
WebSocket utility functions and helpers.
"""
# Place WebSocket helpers here (e.g., send_status, send_error, send_data)

async def send_status(websocket, status):
    await websocket.send_text(status)

async def send_error(websocket, error_type, message):
    await websocket.send_json({"type": "error", "error_type": error_type, "message": message})

async def send_data(websocket, data):
    await websocket.send_json({"type": "data", "data": data})

# ...other helpers
