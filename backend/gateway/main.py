import asyncio
import logging
import os
import sys
from redis.asyncio import Redis
import websockets
from websockets.exceptions import ConnectionClosed

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Configuration from Environment Variables
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8765"))
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
REDIS_CHANNEL = os.environ.get("REDIS_CHANNEL", "aegis-alerts")
HEARTBEAT_INTERVAL = float(os.environ.get("HEARTBEAT_INTERVAL", "30.0"))
GATEWAY_PATH = "/backend/gateway"

# Active WebSocket connections
active_clients = set()


async def send_message(client, data: str):
    """Send message to a single websocket client with error handling."""
    try:
        await client.send(data)
    except ConnectionClosed:
        pass
    except Exception as e:
        logging.warning(f"Error sending message to {client.remote_address}: {e}")


async def redis_listener():
    """Background task to listen to Upstash Redis and broadcast messages."""
    while True:
        try:
            logging.info(f"Connecting to Redis at {REDIS_URL}...")
            # For Upstash Redis, SSL is default, so rediss:// is expected
            redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
            
            async with redis_client.pubsub() as pubsub:
                await pubsub.subscribe(REDIS_CHANNEL)
                logging.info(f"Successfully subscribed to Redis channel: '{REDIS_CHANNEL}'")
                
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        data = message["data"]
                        logging.info(f"Received message from Redis: {data}")
                        
                        if active_clients:
                            logging.info(f"Broadcasting to {len(active_clients)} active client(s)")
                            # Broadcast concurrently to all connected clients
                            await asyncio.gather(
                                *[send_message(client, data) for client in active_clients],
                                return_exceptions=True
                            )
                        else:
                            logging.debug("No active client connections. Message dropped.")
        except Exception as e:
            logging.error(f"Redis connection or pubsub error: {e}. Retrying in 5 seconds...")
            await asyncio.sleep(5)


async def mock_redis_listener():
    """Fallback generator to simulate Redis pub/sub events when REDIS_URL='mock'."""
    logging.info("Starting in MOCK Redis mode. Simulating alert events...")
    ACCOUNTS = ["acc_alpha", "acc_beta", "acc_gamma", "acc_delta", "acc_epsilon", "acc_omega"]
    LOCATIONS = ["New York, USA", "London, UK", "Berlin, Germany", "Tokyo, Japan", "Unknown IP"]
    import json
    import random
    
    while True:
        try:
            # Broadcast a mock fraud alert event every 3 to 8 seconds
            await asyncio.sleep(random.uniform(3.0, 8.0))
            if active_clients:
                alert = {
                    "event_id": f"evt_{random.randint(100000, 999999)}",
                    "type": random.choice(["transfer", "withdrawal", "login_attempt"]),
                    "status": "flagged",
                    "amount": round(random.uniform(10.0, 15000.0), 2),
                    "account_from": random.choice(ACCOUNTS),
                    "account_to": random.choice(ACCOUNTS),
                    "risk_score": random.randint(55, 99),
                    "location": random.choice(LOCATIONS),
                }
                alert_str = json.dumps(alert)
                logging.info(f"[MOCK Redis Pub] Broadcasting mock event: {alert_str}")
                await asyncio.gather(
                    *[send_message(client, alert_str) for client in active_clients],
                    return_exceptions=True
                )
        except asyncio.CancelledError:
            break
        except Exception as e:
            logging.error(f"Error in mock Redis listener: {e}")


async def heartbeat_loop(websocket):
    """
    Periodic heartbeat to keep connections open.
    Render/Railway balancers kill idle connections. We ping every 30 seconds.
    """
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            logging.debug(f"Sending heartbeat ping to {websocket.remote_address}")
            # Sends a WebSocket Ping control frame
            pong_waiter = await websocket.ping()
            # Wait for Pong reply with a 10s timeout
            await asyncio.wait_for(pong_waiter, timeout=10.0)
            logging.debug(f"Received heartbeat pong from {websocket.remote_address}")
    except asyncio.TimeoutError:
        logging.warning(f"Heartbeat timeout from client {websocket.remote_address}. Closing connection.")
        await websocket.close(1011, "Heartbeat timeout")
    except ConnectionClosed:
        pass
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logging.warning(f"Heartbeat error for {websocket.remote_address}: {e}")


async def handler(websocket):
    """Handles incoming WebSocket connections."""
    # Extract path without query parameters
    path = websocket.request.path.split('?')[0]
    
    # Path routing check
    if path != GATEWAY_PATH:
        logging.warning(f"Rejected connection from {websocket.remote_address} on invalid path: {websocket.request.path}")
        await websocket.close(1008, f"Invalid path. Use {GATEWAY_PATH}")
        return

    logging.info(f"New client connected from {websocket.remote_address} on {path}")
    active_clients.add(websocket)
    
    # Start heartbeat task for this connection
    heartbeat_task = asyncio.create_task(heartbeat_loop(websocket))
    
    try:
        # Keep connection open. We don't expect messages from dashboard clients,
        # but we must listen so we detect if the client closes the connection.
        async for _ in websocket:
            # Client sent a message, we can log it or ignore
            pass
    except ConnectionClosed as e:
        logging.info(f"Client {websocket.remote_address} disconnected: code={e.code}, reason={e.reason}")
    except Exception as e:
        logging.error(f"Error on connection {websocket.remote_address}: {e}")
    finally:
        # Clean up
        active_clients.discard(websocket)
        heartbeat_task.cancel()
        logging.info(f"Cleaned up connection for {websocket.remote_address}. Active clients: {len(active_clients)}")


async def main():
    # Start the correct listener background task
    if REDIS_URL.lower() == "mock":
        asyncio.create_task(mock_redis_listener())
    else:
        asyncio.create_task(redis_listener())
    
    logging.info(f"Starting Aegis WebSocket Gateway on ws://{HOST}:{PORT}{GATEWAY_PATH}")
    async with websockets.serve(handler, HOST, PORT):
        # Keep the main event loop running forever
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Aegis WebSocket Gateway server stopped by user.")
