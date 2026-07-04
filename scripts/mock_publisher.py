import asyncio
import json
import os
import random
import sys
from redis.asyncio import Redis

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
REDIS_CHANNEL = os.environ.get("REDIS_CHANNEL", "aegis-alerts")

# Mock data generators
ACCOUNTS = ["acc_alpha", "acc_beta", "acc_gamma", "acc_delta", "acc_epsilon", "acc_omega"]
LOCATIONS = ["New York, USA", "London, UK", "Berlin, Germany", "Tokyo, Japan", "Unknown IP"]

def generate_mock_alert():
    return {
        "event_id": f"evt_{random.randint(100000, 999999)}",
        "type": random.choice(["transfer", "withdrawal", "login_attempt"]),
        "status": "flagged",
        "amount": round(random.uniform(10.0, 15000.0), 2),
        "account_from": random.choice(ACCOUNTS),
        "account_to": random.choice(ACCOUNTS),
        "risk_score": random.randint(55, 99),
        "location": random.choice(LOCATIONS),
    }

async def main():
    print(f"Connecting to Redis at {REDIS_URL}...")
    r = Redis.from_url(REDIS_URL, decode_responses=True)
    
    print(f"Publisher ready. Will publish to channel '{REDIS_CHANNEL}'")
    print("Press Ctrl+C to stop.")
    
    try:
        while True:
            # Generate a mock fraud alert
            alert = generate_mock_alert()
            alert_str = json.dumps(alert)
            
            print(f"Publishing event to '{REDIS_CHANNEL}': {alert_str}")
            await r.publish(REDIS_CHANNEL, alert_str)
            
            # Wait random time between 2 to 7 seconds
            await asyncio.sleep(random.uniform(2.0, 7.0))
    except KeyboardInterrupt:
        print("\nPublisher stopped.")
    finally:
        await r.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
