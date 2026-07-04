import json
import os
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict
import requests
from faker import Faker

fake = Faker()

@dataclass(frozen=True)
class SimulatorConfig:
    risk_engine_url: str
    interval_ms: int = 3000

def load_config() -> SimulatorConfig:
    risk_engine_url = os.environ.get("RISK_ENGINE_URL", "http://127.0.0.1:8000/api/v1/analyze")
    interval_ms = int(os.environ.get("SIMULATOR_INTERVAL_MS", "3000"))
    return SimulatorConfig(risk_engine_url=risk_engine_url, interval_ms=interval_ms)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# Pool of corporate IPs to simulate
IP_POOL = [f"10.0.1.{i}" for i in range(10, 150)] + [f"192.168.10.{i}" for i in range(20, 80)]
SERVER_IPS = ["FW_Gateway", "DB_Server", "Corp_Intranet", "Ext_Server"]

def build_traffic_payload(source_ip: str, is_exfil=False, is_dos=False) -> Dict[str, Any]:
    target_ip = random.choice(SERVER_IPS)
    protocol = random.choice(["HTTPS", "SSH", "TLS", "UDP"])
    
    if is_exfil:
        payload_size = round(random.uniform(5000.0, 15000.0), 2)  # Exfil over 5GB
    elif is_dos:
        payload_size = round(random.uniform(0.1, 5.0), 2)
    else:
        payload_size = round(random.uniform(0.5, 450.0), 2)

    return {
        "session_id": f"sess_{fake.uuid4()[:8]}",
        "source_ip": source_ip,
        "target_ip": target_ip,
        "payload_size_mb": payload_size,
        "protocol": protocol,
        "timestamp": now_iso()
    }

def post_transaction(config: SimulatorConfig, payload: Dict[str, Any]) -> None:
    # Explicitly add country_code inside payload to map location
    payload["country_code"] = "US" if payload["source_ip"].startswith("10.") else "GB"
    response = requests.post(config.risk_engine_url, json=payload, timeout=5)
    response.raise_for_status()
    print(json.dumps({"sent": True, "status_code": response.status_code, "session_id": payload["session_id"], "source_ip": payload["source_ip"], "type": payload["protocol"]}))

def main() -> None:
    config = load_config()
    print(json.dumps({"app": "aegis_nexus", "mode": "simulator", "endpoint": config.risk_engine_url, "interval_ms": config.interval_ms}))

    cycle = 0
    while True:
        cycle += 1
        
        # Check for rapid-fire DoS packet flood sequence (every 25 cycles)
        if cycle % 25 == 0:
            dos_ip = random.choice(IP_POOL)
            print(json.dumps({"info": f"Initiating high-velocity DoS packet flood burst from {dos_ip}"}))
            # Send 30 rapid requests in a fast sub-second loop spaced 0.02s apart
            for _ in range(30):
                payload = build_traffic_payload(dos_ip, is_dos=True)
                try:
                    post_transaction(config, payload)
                except Exception as exc:
                    print(json.dumps({"sent": False, "error": str(exc)}))
                time.sleep(0.02)
        else:
            # 10% chance of data exfiltration payload
            is_exfil = random.random() < 0.10
            source_ip = random.choice(IP_POOL)
            payload = build_traffic_payload(source_ip, is_exfil=is_exfil)
            try:
                post_transaction(config, payload)
            except requests.RequestException as exc:
                print(json.dumps({"sent": False, "error": str(exc)}))
            except Exception as exc:
                print(json.dumps({"sent": False, "error": str(exc)}))

        time.sleep(1.0) # Send JSON network logs every 1000ms

if __name__ == "__main__":
    main()
