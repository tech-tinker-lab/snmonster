from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from websocket_manager import WebSocketManager

router = APIRouter()

websocket_manager = WebSocketManager()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket_manager.send_message(websocket, f"Message received: {data}")
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
