import asyncio
import websockets
import ssl
import sys

async def connect():
    uri = "wss://0d76041e-54ce-4cea-a128-ebfa32171c29:password@127.0.0.1:443/v1/websocket"  # Server WebSocket URI

    # Create SSL context and load the root CA certificate
    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile="cert/rootCA.crt")



    async with websockets.connect(uri, ssl=ssl_context) as websocket:
        await websocket.send("Hello from Python Client")  # Send message to server
        res = await websocket.recv()
        print("Server Response: ", res)

        await websocket.send("Another Hello from Python Client")  # Send message to server
        res = await websocket.recv()
        print("Server Response: ", res)


# Run the event loop
asyncio.run(connect())