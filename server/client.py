import asyncio
import websockets
import ssl
import sys

async def connect():
    uri = "wss://127.0.0.1:443/v1/websocket"  # Server WebSocket URI
    
    # Create SSL context and load the root CA certificate
    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile="cert/rootCA.crt")
    
    async with websockets.connect(uri, ssl=ssl_context, ) as websocket: #extra_headers={"Authorization": sys.argv[1]}
        await websocket.send("Hello from Python Client")
        res = await websocket.recv()
        print(res)

# Run the event loop
asyncio.get_event_loop().run_until_complete(connect())