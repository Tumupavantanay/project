import asyncio
import os
import sys
import websockets
from websockets.exceptions import ConnectionClosed

GATEWAY_URL = os.environ.get("GATEWAY_URL", "ws://localhost:8765/backend/gateway")

async def main():
    print(f"Connecting to Aegis WebSocket Gateway at {GATEWAY_URL}...")
    try:
        async with websockets.connect(GATEWAY_URL) as websocket:
            print("Connected successfully! Waiting for messages...")
            try:
                async for message in websocket:
                    print(f"\n[Received Event]: {message}")
            except ConnectionClosed as e:
                print(f"\nConnection closed by server. Code: {e.code}, Reason: {e.reason}")
    except Exception as e:
        print(f"Failed to connect or maintain connection: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClient stopped.")
