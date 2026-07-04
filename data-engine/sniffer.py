import json
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
import requests
from scapy.all import sniff, IP, TCP, UDP

# FastAPI Telemetry Endpoint
API_URL = os.environ.get("AEGIS_API_URL", "http://localhost:8000/api/v1/analyze")

# Thread-safe packet processing queue
packet_queue = queue.Queue(maxsize=5000)

def telemetry_poster():
    """Background worker thread that posts packet events from the queue to the FastAPI analysis endpoint."""
    print("[Aegis Nexus Sniffer] Non-blocking background worker poster thread started.")
    session = requests.Session()
    
    while True:
        try:
            # Block until a packet telemetry payload is available
            payload = packet_queue.get()
            
            try:
                # Add country_code mapping header
                payload["country_code"] = "US" if payload["source_ip"].startswith("10.") else "GB"
                response = session.post(API_URL, json=payload, timeout=2)
                if response.status_code == 200:
                    resp_data = response.json()
                    if resp_data.get("status") == "flagged":
                        print(f"[!] TELEMETRY WARNING: {payload['source_ip']} -> {payload['target_ip']} flagged as THREAT! Risk Score: {resp_data['score']}%")
                else:
                    print(f"[-] Telemetry post status: {response.status_code}")
            except requests.RequestException as e:
                # Silently catch request exceptions to avoid crashing when backend is offline
                pass
            finally:
                packet_queue.task_done()
                
        except Exception as e:
            print(f"[-] Sniffer worker thread error: {e}", file=sys.stderr)
            time.sleep(1)

def packet_callback(packet):
    """Callback triggered for every sniffed raw network packet."""
    if not packet.haslayer(IP):
        return
        
    try:
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        target_ip = ip_layer.dst
        
        # Calculate size of raw packet in Megabytes
        payload_size_mb = len(packet) / (1024.0 * 1024.0)
        
        # Determine protocol layer type
        protocol = "TCP"
        if packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(TCP):
            protocol = "TCP"
        else:
            protocol = "IP"

        # Construct Zero-Trust telemetry payload
        payload = {
            "session_id": f"sess_sniff_{int(time.time() * 1000) % 10000000}",
            "source_ip": source_ip,
            "target_ip": target_ip,
            "payload_size_mb": round(payload_size_mb, 6),
            "protocol": protocol,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Put packet payload on the queue without blocking if queue is full
        try:
            packet_queue.put_nowait(payload)
        except queue.Full:
            pass # Drop packet telemetry to prevent sniffer memory starvation
            
    except Exception as e:
        pass

def main():
    print(f"[Aegis Nexus Sniffer] Initializing Scapy packet sniffer. Forwarding telemetry to {API_URL}")
    
    # Start the non-blocking telemetry poster background thread
    worker = threading.Thread(target=telemetry_poster, daemon=True)
    worker.start()
    
    # Listen on host network interface card (sniffs IP packets)
    try:
        print("[Aegis Nexus Sniffer] Sniffing live local interface card socket packets... Press Ctrl+C to terminate.")
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[Aegis Nexus Sniffer] Sniffer session closed by user.")
    except Exception as e:
        print(f"[-] Scapy sniffing failure (requires administrator privileges on some systems): {e}")

if __name__ == "__main__":
    main()
