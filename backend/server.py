import asyncio
import csv
import json
import logging
import os
import random
import sys
from io import StringIO
from typing import List, Dict, Any, Tuple
from datetime import datetime
import subprocess

link_history: Dict[Tuple[str, str], List[Tuple[float, float]]] = {}

import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from redis.asyncio import Redis

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Configuration from Environment
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
REDIS_CHANNEL = os.environ.get("REDIS_CHANNEL", "cyber_anomalies")
HEARTBEAT_INTERVAL = float(os.environ.get("HEARTBEAT_INTERVAL", "30.0"))

app = FastAPI(title="Aegis Nexus Cybersecurity Command Center API")

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory graph state
graph_state = {
    "nodes": [
        {"id": "FW_Gateway", "riskScore": 10, "mlClass": "normal"},
        {"id": "DB_Server", "riskScore": 20, "mlClass": "normal"},
        {"id": "Corp_Intranet", "riskScore": 15, "mlClass": "normal"},
        {"id": "WS_Endpoint_01", "riskScore": 25, "mlClass": "normal"},
        {"id": "WS_Endpoint_02", "riskScore": 85, "mlClass": "dos_attack"},
        {"id": "Ext_Server", "riskScore": 90, "mlClass": "exfiltration"},
    ],
    "links": [
        {"source": "WS_Endpoint_02", "target": "FW_Gateway", "riskScore": 85, "payload_size_mb": 12000.0},
        {"source": "WS_Endpoint_01", "target": "Corp_Intranet", "riskScore": 15, "payload_size_mb": 150.0},
        {"source": "Corp_Intranet", "target": "DB_Server", "riskScore": 20, "payload_size_mb": 350.0},
        {"source": "Ext_Server", "target": "FW_Gateway", "riskScore": 90, "payload_size_mb": 5200.0},
    ]
}

# Transaction/Session history
recent_transactions: List[Dict[str, Any]] = [
    {"id": "sess_101", "source": "Ext_Server", "target": "FW_Gateway", "payload_size_mb": 5200.0, "riskScore": 90, "timestamp": "2026-07-04T19:40:00Z", "protocol": "HTTPS", "status": "Flagged", "type": "exfiltration"},
    {"id": "sess_102", "source": "WS_Endpoint_02", "target": "FW_Gateway", "payload_size_mb": 12000.0, "riskScore": 85, "timestamp": "2026-07-04T19:45:00Z", "protocol": "UDP", "status": "Flagged", "type": "dos_attack"},
    {"id": "sess_103", "source": "Corp_Intranet", "target": "DB_Server", "payload_size_mb": 350.0, "riskScore": 20, "timestamp": "2026-07-04T19:50:00Z", "protocol": "SSH", "status": "Safe", "type": "normal"},
    {"id": "sess_104", "source": "WS_Endpoint_01", "target": "Corp_Intranet", "payload_size_mb": 150.0, "riskScore": 15, "timestamp": "2026-07-04T19:52:00Z", "protocol": "TLS", "status": "Safe", "type": "normal"},
]

# Temporary holder for uploaded file content
uploaded_data_store = []

# WebSocket active client connections
active_clients = set()

# Redis Pub/Sub client
redis_pub_client = None

# Machine Learning Anomaly Detection Model
ml_model = None

def train_fallback_base_model():
    """Trains a fallback base IsolationForest model using synthetic normal traffic features."""
    global ml_model
    logging.info("Training fallback base IsolationForest model with synthetic normal traffic...")
    
    # Feature vector layout: [payload_size_mb, request_rate_per_sec, protocol_id]
    np.random.seed(42)
    
    # 1. Normal payloads: 5MB to 150MB
    normal_payloads = np.random.uniform(5.0, 150.0, 300)
    # 2. Normal request rates: 0.2 to 2.5 requests/sec
    normal_rates = np.random.uniform(0.2, 2.5, 300)
    # 3. Normal protocol IDs: mostly HTTPS (1), SSH (2), TLS (3)
    normal_protocols = np.random.choice([1, 2, 3], 300, p=[0.6, 0.2, 0.2])
    
    X_train = np.column_stack((normal_payloads, normal_rates, normal_protocols))
    
    # Fit model with 3% anomaly contamination rate
    ml_model = IsolationForest(n_estimators=100, contamination=0.03, random_state=42)
    ml_model.fit(X_train)
    logging.info("IsolationForest model training completed successfully.")

async def get_redis_client():
    global redis_pub_client
    if redis_pub_client is None and REDIS_URL.lower() != "mock":
        try:
            redis_pub_client = Redis.from_url(REDIS_URL, decode_responses=True)
        except Exception as e:
            logging.error(f"Failed to initialize Redis client: {e}")
    return redis_pub_client

# Heuristics Evaluator Class
class RiskEvaluator:
    def __init__(self):
        # Maps source_ip -> list of timestamps (floats) for DoS window checks
        self._dos_tracker: Dict[str, List[float]] = {}
        # Maps user/IP -> general request logs for 24h
        self._in_memory_history: Dict[str, List[dict]] = {}

    def _parse_timestamp(self, timestamp_str: str) -> float:
        cleaned = timestamp_str.replace('Z', '+00:00')
        dt = datetime.fromisoformat(cleaned)
        return dt.timestamp()

    def get_sliding_request_rate(self, source_ip: str, current_epoch: float) -> float:
        """Returns the rolling request rate per second within a 10s window."""
        if source_ip not in self._dos_tracker:
            self._dos_tracker[source_ip] = []
        
        self._dos_tracker[source_ip].append(current_epoch)
        cutoff = current_epoch - 10.0
        self._dos_tracker[source_ip] = [t for t in self._dos_tracker[source_ip] if t >= cutoff]
        
        # Calculate rate (requests per second)
        count = len(self._dos_tracker[source_ip])
        return count / 10.0

    def evaluate_heuristics(self, payload: dict, current_epoch: float) -> Tuple[int, List[str], float]:
        source_ip = payload.get("source_ip")
        payload_size_mb = payload.get("payload_size_mb", 0.0)
        protocol = payload.get("protocol", "HTTPS").upper()

        points = 0
        rules_triggered = []

        # DoS Velocity check (heuristical threshold)
        req_rate = self.get_sliding_request_rate(source_ip, current_epoch)
        if len(self._dos_tracker[source_ip]) > 20:
            points += 65
            rules_triggered.append("DoS Velocity Spike")

        # Exfiltration check
        if payload_size_mb > 5000.0:
            points += 80
            rules_triggered.append("Massive Data Exfiltration")

        # Protocol Abuse check
        if protocol == "UDP" and payload_size_mb < 5.0:
            points += 20
            rules_triggered.append("Anomalous Protocol Scan (UDP)")

        # Save general history log
        if source_ip not in self._in_memory_history:
            self._in_memory_history[source_ip] = []
        self._in_memory_history[source_ip].append({
            "epoch": current_epoch,
            "payload_size_mb": payload_size_mb,
            "protocol": protocol
        })
        history_cutoff = current_epoch - 86400
        self._in_memory_history[source_ip] = [x for x in self._in_memory_history[source_ip] if x["epoch"] >= history_cutoff]

        return points, rules_triggered, req_rate

evaluator = RiskEvaluator()

# Models
class MLProcessRequest(BaseModel):
    filePath: str = "uploaded_transactions.csv"

class IngestRequest(BaseModel):
    accounts: List[Dict[str, Any]]
    links: List[Dict[str, Any]]

class AnalyzeRequest(BaseModel):
    session_id: str
    source_ip: str
    target_ip: str
    payload_size_mb: float
    protocol: str
    timestamp: str

class AnalyzeResponse(BaseModel):
    session_id: str
    source_ip: str
    score: int
    status: str
    rules_triggered: List[str]

# WebSocket Gateway implementation
async def heartbeat_loop(websocket: WebSocket):
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            await websocket.send_text("ping")
    except Exception:
        pass

@app.websocket("/backend/gateway")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    logging.info(f"WebSocket client connected: {websocket.client}")
    active_clients.add(websocket)
    heartbeat_task = asyncio.create_task(heartbeat_loop(websocket))
    try:
        while True:
            data = await websocket.receive_text()
            if data == "pong":
                logging.debug("WS heartbeat pong received")
    except WebSocketDisconnect:
        logging.info(f"WebSocket client disconnected: {websocket.client}")
    except Exception as e:
        logging.error(f"WebSocket connection error: {e}")
    finally:
        active_clients.discard(websocket)
        heartbeat_task.cancel()

async def broadcast_alert(alert_message: str):
    if active_clients:
        logging.info(f"Broadcasting cyber anomaly alert to {len(active_clients)} client(s)")
        await asyncio.gather(
            *[client.send_text(alert_message) for client in active_clients],
            return_exceptions=True
        )

async def redis_subscription_listener():
    while True:
        try:
            if REDIS_URL.lower() == "mock":
                logging.info("Starting background subscriber in MOCK Redis mode.")
                IPS = ["10.0.1.45", "192.168.1.102", "172.16.50.8", "FW_Gateway", "DB_Server", "WS_Endpoint_01", "WS_Endpoint_02", "Ext_Server"]
                while True:
                    await asyncio.sleep(random.uniform(5.0, 12.0))
                    if active_clients:
                        is_threat = random.random() > 0.6
                        risk_score = random.randint(75, 99) if is_threat else random.randint(5, 45)
                        threat_type = "normal"
                        if is_threat:
                            threat_type = random.choice(["dos_attack", "exfiltration", "ai_anomaly_flagged"])
                        
                        alert = {
                            "event_id": f"evt_{random.randint(100000, 999999)}",
                            "type": threat_type,
                            "status": "flagged" if is_threat else "approved",
                            "payload_size_mb": round(random.uniform(5000.0, 18000.0), 2) if threat_type == "exfiltration" else round(random.uniform(0.1, 50.0), 2),
                            "account_from": random.choice(IPS),
                            "account_to": random.choice(IPS),
                            "risk_score": risk_score,
                            "location": "Aegis Network Stream",
                        }
                        await broadcast_alert(json.dumps(alert))
            else:
                logging.info(f"Connecting background subscriber to Redis at {REDIS_URL}...")
                r = Redis.from_url(REDIS_URL, decode_responses=True)
                async with r.pubsub() as pubsub:
                    await pubsub.subscribe(REDIS_CHANNEL)
                    logging.info(f"Subscribed to Redis channel: '{REDIS_CHANNEL}'")
                    async for message in pubsub.listen():
                        if message["type"] == "message":
                            await broadcast_alert(message["data"])
        except Exception as e:
            logging.error(f"Redis listener error: {e}. Retrying in 5 seconds...")
            await asyncio.sleep(5)

# REST Endpoints
@app.get("/api/graph")
async def get_graph():
    return graph_state

@app.get("/api/transactions")
async def get_transactions():
    return recent_transactions

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    global uploaded_data_store
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")
    try:
        content = await file.read()
        csv_text = content.decode("utf-8")
        reader = csv.DictReader(StringIO(csv_text))
        uploaded_data_store = []
        for row in reader:
            if "source_ip" not in row or "target_ip" not in row or "payload_size_mb" not in row:
                raise HTTPException(status_code=400, detail="CSV must contain 'source_ip', 'target_ip', and 'payload_size_mb' headers.")
            uploaded_data_store.append({
                "source_ip": row["source_ip"].strip(),
                "target_ip": row["target_ip"].strip(),
                "payload_size_mb": float(row["payload_size_mb"].strip()),
                "protocol": row.get("protocol", "HTTPS").strip(),
                "timestamp": row.get("timestamp", "2026-07-04T20:00:00Z").strip()
            })
        logging.info(f"Uploaded {len(uploaded_data_store)} records.")
        return {"status": "success", "filename": file.filename, "records": len(uploaded_data_store)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process CSV: {str(e)}")

@app.post("/api/process-ml")
async def process_ml(request: MLProcessRequest):
    global uploaded_data_store
    if not uploaded_data_store:
        raise HTTPException(status_code=400, detail="No uploaded transactions found. Upload a file first.")
    processed_accounts = {}
    processed_links = []
    
    # Process files simulating Isolation Forest classifier mapped to Zero Trust rules
    for tx in uploaded_data_store:
        payload_size = tx["payload_size_mb"]
        protocol = tx["protocol"]
        
        base_score = 10
        if payload_size > 5000.0:
            base_score += 45
        if protocol.upper() == "UDP":
            base_score += 20
        
        risk_score = min(99, max(5, base_score + random.randint(-5, 10)))
        
        threat_label = "normal"
        if risk_score > 70:
            threat_label = "exfiltration" if payload_size > 5000.0 else "protocol_abuse"
            
        src = tx["source_ip"]
        tgt = tx["target_ip"]
        
        if src not in processed_accounts:
            processed_accounts[src] = {"id": src, "riskScore": risk_score, "mlClass": threat_label}
        else:
            processed_accounts[src]["riskScore"] = max(processed_accounts[src]["riskScore"], risk_score)
            if threat_label != "normal":
                processed_accounts[src]["mlClass"] = threat_label
                
        if tgt not in processed_accounts:
            processed_accounts[tgt] = {"id": tgt, "riskScore": max(10, risk_score - 20), "mlClass": "normal"}
            
        processed_links.append({
            "source": src,
            "target": tgt,
            "payload_size_mb": payload_size,
            "riskScore": risk_score,
            "timestamp": tx["timestamp"],
            "protocol": protocol,
            "type": threat_label
        })
        
    return {
        "status": "success",
        "accounts": list(processed_accounts.values()),
        "links": processed_links
    }

@app.post("/api/ingest-neo4j")
async def ingest_neo4j(request: IngestRequest):
    global graph_state, recent_transactions
    existing_nodes = {n["id"]: n for n in graph_state["nodes"]}
    for new_node in request.accounts:
        nid = new_node["id"]
        if nid in existing_nodes:
            existing_nodes[nid]["riskScore"] = max(existing_nodes[nid]["riskScore"], new_node["riskScore"])
            if new_node["mlClass"] != "normal":
                existing_nodes[nid]["mlClass"] = new_node["mlClass"]
        else:
            existing_nodes[nid] = new_node
            
    graph_state["nodes"] = list(existing_nodes.values())
    
    for new_link in request.links:
        src = new_link["source"]
        tgt = new_link["target"]
        if src not in existing_nodes:
            existing_nodes[src] = {"id": src, "riskScore": new_link["riskScore"], "mlClass": new_link.get("type", "normal")}
        if tgt not in existing_nodes:
            existing_nodes[tgt] = {"id": tgt, "riskScore": max(10, new_link["riskScore"] - 20), "mlClass": "normal"}
            
        graph_state["nodes"] = list(existing_nodes.values())
        
        graph_state["links"].append({
            "source": src,
            "target": tgt,
            "riskScore": new_link["riskScore"],
            "payload_size_mb": new_link.get("payload_size_mb", 10.0)
        })
        
        tx_id = f"sess_{random.randint(1000, 9999)}"
        recent_transactions.insert(0, {
            "id": tx_id,
            "source": src,
            "target": tgt,
            "payload_size_mb": new_link.get("payload_size_mb", 10.0),
            "riskScore": new_link["riskScore"],
            "timestamp": new_link.get("timestamp", "2026-07-04T20:00:00Z"),
            "protocol": new_link.get("protocol", "HTTPS"),
            "status": "Flagged" if new_link["riskScore"] > 70 else "Safe",
            "type": new_link.get("type", "normal")
        })
        
        if new_link["riskScore"] > 70:
            alert = {
                "event_id": f"evt_{random.randint(100000, 999999)}",
                "type": new_link.get("type", "dos_attack"),
                "status": "flagged",
                "payload_size_mb": new_link.get("payload_size_mb", 10.0),
                "account_from": src,
                "account_to": tgt,
                "risk_score": new_link["riskScore"],
                "location": "Aegis System Ingest",
            }
            alert_str = json.dumps(alert)
            r_client = await get_redis_client()
            if r_client:
                try:
                    await r_client.publish(REDIS_CHANNEL, alert_str)
                except Exception:
                    await broadcast_alert(alert_str)
            else:
                await broadcast_alert(alert_str)
                
    recent_transactions = recent_transactions[:100]
    return {"status": "success", "nodes_count": len(graph_state["nodes"]), "links_count": len(graph_state["links"])}

@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_transaction(payload: AnalyzeRequest):
    try:
        source_ip = payload.source_ip
        target_ip = payload.target_ip
        payload_size_mb = payload.payload_size_mb
        protocol = payload.protocol
        timestamp_str = payload.timestamp

        try:
            current_epoch = evaluator._parse_timestamp(timestamp_str)
        except Exception:
            current_epoch = datetime.utcnow().timestamp()

        # 1. Run heuristics and fetch request rates
        h_score, rules, req_rate = evaluator.evaluate_heuristics(
            {"source_ip": source_ip, "payload_size_mb": payload_size_mb, "protocol": protocol},
            current_epoch
        )

        # Convert protocol type to integer ID
        # HTTPS=1, SSH=2, TLS=3, UDP=4, others=1
        proto_upper = protocol.upper()
        if proto_upper == "HTTPS":
            proto_id = 1.0
        elif proto_upper == "SSH":
            proto_id = 2.0
        elif proto_upper == "TLS":
            proto_id = 3.0
        elif proto_upper == "UDP":
            proto_id = 4.0
        else:
            proto_id = 1.0

        # 2. Machine Learning Inference (IsolationForest)
        ai_risk = 0
        ai_anomaly_flag = False
        
        if ml_model is not None:
            features = np.array([[payload_size_mb, req_rate, proto_id]])
            prediction = ml_model.predict(features)[0]  # -1 for anomaly, 1 for normal
            score_sample = ml_model.score_samples(features)[0]  # lower value means more anomalous
            
            # Map IsolationForest score (-0.8 anomaly to -0.4 normal) to 0-100 risk score
            ai_risk = int(max(0, min(100, (-score_sample - 0.38) * 250)))
            
            if prediction == -1:
                ai_anomaly_flag = True
                rules.append("AI Outlier Detected (IsolationForest)")
            
            if ai_risk > 75:
                rules.append(f"AI Anomaly Score Exceeded Threshold ({ai_risk}%)")

        # Combine heuristic and machine learning risk values
        final_score = max(h_score, ai_risk)
        if ai_anomaly_flag and h_score > 40:
            final_score = max(final_score, 95)
            rules.append("Security Severity Escalation (Heuristic + AI Correlation)")
            
        final_score = min(max(final_score, 0), 100)

        # Threat classification priority
        threat_class = "normal"
        if final_score > 70:
            if "DoS Velocity Spike" in rules:
                threat_class = "dos_attack"
            elif "Massive Data Exfiltration" in rules:
                threat_class = "exfiltration"
            elif ai_anomaly_flag:
                threat_class = "ai_anomaly_flagged"
            else:
                threat_class = "protocol_abuse"

        tx_status = "flagged" if final_score > 70 else "approved"

        # Update in-memory visual graph nodes registry
        existing_nodes = {n["id"]: n for n in graph_state["nodes"]}
        if source_ip not in existing_nodes:
            existing_nodes[source_ip] = {"id": source_ip, "riskScore": final_score, "mlClass": threat_class}
        else:
            existing_nodes[source_ip]["riskScore"] = max(existing_nodes[source_ip]["riskScore"], final_score)
            if threat_class != "normal":
                existing_nodes[source_ip]["mlClass"] = threat_class
                
        if target_ip not in existing_nodes:
            existing_nodes[target_ip] = {"id": target_ip, "riskScore": max(10, final_score - 20), "mlClass": "normal"}
            
        graph_state["nodes"] = list(existing_nodes.values())
        
        # Throughput Tracking per second (10s sliding window)
        link_key = (source_ip, target_ip)
        if link_key not in link_history:
            link_history[link_key] = []
        link_history[link_key].append((current_epoch, payload_size_mb))
        
        # Clean history older than 10 seconds
        link_history[link_key] = [x for x in link_history[link_key] if x[0] >= current_epoch - 10.0]
        total_vol_10s = sum(x[1] for x in link_history[link_key])
        throughput_rate = round(total_vol_10s / 10.0, 2)
        
        # Active Mitigation Layer (IP Block on risk >= 90%)
        if final_score >= 90:
            logging.warning(f"CRITICAL THREAT: Risk score {final_score}% exceeds mitigation threshold of 90%!")
            logging.info(f"Firewall Active Drop Countermeasure Triggered for source IP: {source_ip}")
            try:
                # safe mock shell command placeholder executing echo block rule
                cmd = f"echo [Aegis Nexus Active Defense] BLOCK RULE ADDED FOR remoteip={source_ip}"
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logging.info(f"Mock firewall rule execution succeeded for IP {source_ip}")
                rules.append("Firewall Active Drop Countermeasure Triggered")
            except Exception as exc:
                logging.error(f"Failed to execute mock firewall rule: {exc}")
                
        # Link dynamic edge registration (incorporating throughput_mb_s)
        # Check if link already exists to update it, else append
        found_link = False
        for l in graph_state["links"]:
            if l["source"] == source_ip and l["target"] == target_ip:
                l["riskScore"] = final_score
                l["payload_size_mb"] = payload_size_mb
                l["throughput_mb_s"] = throughput_rate
                found_link = True
                break
        if not found_link:
            graph_state["links"].append({
                "source": source_ip,
                "target": target_ip,
                "riskScore": final_score,
                "payload_size_mb": payload_size_mb,
                "throughput_mb_s": throughput_rate
            })
        
        recent_transactions.insert(0, {
            "id": payload.session_id,
            "source": source_ip,
            "target": target_ip,
            "payload_size_mb": payload_size_mb,
            "riskScore": final_score,
            "timestamp": timestamp_str,
            "protocol": protocol,
            "status": "Flagged" if final_score > 70 else "Safe",
            "type": threat_class
        })
        
        # Alert Broadcast triggers
        if final_score > 70:
            alert = {
                "event_id": f"evt_{random.randint(100000, 999999)}",
                "type": threat_class,
                "status": "flagged",
                "payload_size_mb": payload_size_mb,
                "account_from": source_ip,
                "account_to": target_ip,
                "risk_score": final_score,
                "location": "Aegis AI Engine",
            }
            alert_str = json.dumps(alert)
            r_client = await get_redis_client()
            if r_client:
                try:
                    await r_client.publish(REDIS_CHANNEL, alert_str)
                except Exception:
                    await broadcast_alert(alert_str)
            else:
                await broadcast_alert(alert_str)
                
        return AnalyzeResponse(
            session_id=payload.session_id,
            source_ip=source_ip,
            score=final_score,
            status=tx_status,
            rules_triggered=rules
        )
    except Exception as e:
        logging.error(f"Error evaluating risk: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/audit/csv")
async def audit_csv_log(file: UploadFile = File(...)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV log files are supported.")
        
    try:
        content = await file.read()
        csv_text = content.decode("utf-8")
        reader = csv.DictReader(StringIO(csv_text))
        
        anomalies = []
        rows_parsed = 0
        global recent_transactions
        
        # Track sliding request rates within a 10s window per source_ip
        csv_dos_tracker = {}
        
        def parse_generic_timestamp(t_str: str) -> float:
            try:
                parts = t_str.split(":")
                if len(parts) == 3:
                    return float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2])
            except Exception:
                pass
            try:
                cleaned = t_str.replace('Z', '+00:00')
                dt = datetime.fromisoformat(cleaned)
                return dt.timestamp()
            except Exception:
                pass
            return datetime.utcnow().timestamp()
            
        for row in reader:
            rows_parsed += 1
            
            # Resolve keys from row case-insensitively and interchangeably
            def get_val(keys_list, default=""):
                for k in keys_list:
                    if k in row and row[k] is not None:
                        return str(row[k])
                    for rk in row.keys():
                        if rk.strip().lower() == k.lower():
                            return str(row[rk])
                return default

            session_id = get_val(["session_id", "id", "transaction_id"], f"sess_batch_{random.randint(1000, 9999)}").strip()
            source_ip = get_val(["source_ip", "user_id", "source"]).strip()
            target_ip = get_val(["target_ip", "transaction_id", "target"]).strip()
            
            if not source_ip or not target_ip:
                continue
                
            payload_size_val = get_val(["payload_size_mb", "amount"], "0.0").strip()
            try:
                payload_size_mb = float(payload_size_val)
            except ValueError:
                payload_size_mb = 0.0
                
            request_type = get_val(["request_type", "protocol"], "HTTPS").strip()
            timestamp = get_val(["timestamp", "time"], datetime.utcnow().isoformat() + "Z").strip()
            
            proto_upper = request_type.upper()
            if proto_upper == "HTTPS":
                proto_id = 1.0
            elif proto_upper == "SSH" or proto_upper == "INTERNAL_SSH":
                proto_id = 2.0
            elif proto_upper == "TLS" or proto_upper == "TLS_SESSION":
                proto_id = 3.0
            elif proto_upper == "UDP" or proto_upper == "RAW_UDP":
                proto_id = 4.0
            else:
                proto_id = 1.0
                
            t_val = parse_generic_timestamp(timestamp)
            if source_ip not in csv_dos_tracker:
                csv_dos_tracker[source_ip] = []
            csv_dos_tracker[source_ip].append(t_val)
            csv_dos_tracker[source_ip] = [t for t in csv_dos_tracker[source_ip] if t_val - t <= 10.0]
            request_rate = len(csv_dos_tracker[source_ip]) / 10.0
            
            h_score = 10
            rules = []
            if payload_size_mb > 5000.0:
                h_score += 75
                rules.append("Massive Data Exfiltration")
            if proto_upper in ["UDP", "RAW_UDP"]:
                h_score += 20
                rules.append("UDP Protocol Abuse")
            if len(csv_dos_tracker[source_ip]) > 10:
                h_score += 65
                rules.append("DoS Velocity Spike")
                
            ai_risk = 0
            ai_anomaly_flag = False
            prediction = 1
            
            if ml_model is not None:
                features = np.array([[payload_size_mb, request_rate, proto_id]])
                prediction = ml_model.predict(features)[0]
                score_sample = ml_model.score_samples(features)[0]
                ai_risk = int(max(0, min(100, (-score_sample - 0.38) * 250)))
                
                if prediction == -1:
                    ai_anomaly_flag = True
                    rules.append("AI Outlier Detected (IsolationForest)")
                if ai_risk > 75:
                    rules.append(f"AI Anomaly Score Exceeded Threshold ({ai_risk}%)")
                    
            final_score = max(h_score, ai_risk)
            if ai_anomaly_flag and h_score > 40:
                final_score = max(final_score, 95)
                rules.append("Security Severity Escalation (Heuristic + AI Correlation)")
            final_score = min(max(final_score, 0), 100)
            
            threat_class = "normal"
            if final_score > 70:
                if "Massive Data Exfiltration" in rules:
                    threat_class = "exfiltration"
                elif "UDP Protocol Abuse" in rules or "DoS Velocity Spike" in rules:
                    threat_class = "dos_attack"
                elif ai_anomaly_flag:
                    threat_class = "ai_anomaly_flagged"
                else:
                    threat_class = "protocol_abuse"
            
            existing_nodes = {n["id"]: n for n in graph_state["nodes"]}
            if source_ip not in existing_nodes:
                existing_nodes[source_ip] = {"id": source_ip, "riskScore": final_score, "mlClass": threat_class}
            else:
                existing_nodes[source_ip]["riskScore"] = max(existing_nodes[source_ip]["riskScore"], final_score)
                if threat_class != "normal":
                    existing_nodes[source_ip]["mlClass"] = threat_class
                    
            if target_ip not in existing_nodes:
                existing_nodes[target_ip] = {"id": target_ip, "riskScore": max(10, final_score - 20), "mlClass": "normal"}
                
            graph_state["nodes"] = list(existing_nodes.values())
            
            found_link = False
            for l in graph_state["links"]:
                if l["source"] == source_ip and l["target"] == target_ip:
                    l["riskScore"] = final_score
                    l["payload_size_mb"] = payload_size_mb
                    l["throughput_mb_s"] = 0.0
                    found_link = True
                    break
            if not found_link:
                graph_state["links"].append({
                    "source": source_ip,
                    "target": target_ip,
                    "riskScore": final_score,
                    "payload_size_mb": payload_size_mb,
                    "throughput_mb_s": 0.0
                })
                
            if prediction == -1 or final_score > 75:
                anomaly_item = {
                    "event_id": f"evt_{random.randint(100000, 999999)}",
                    "type": threat_class,
                    "status": "flagged",
                    "payload_size_mb": payload_size_mb,
                    "account_from": source_ip,
                    "account_to": target_ip,
                    "risk_score": final_score,
                    "location": "Aegis Forensic Audit",
                    "session_id": session_id,
                    "timestamp": timestamp,
                    "protocol": request_type,
                    "rules_triggered": rules
                }
                anomalies.append(anomaly_item)
                
                recent_transactions.insert(0, {
                    "id": session_id,
                    "source": source_ip,
                    "target": target_ip,
                    "payload_size_mb": payload_size_mb,
                    "riskScore": final_score,
                    "timestamp": timestamp,
                    "protocol": request_type,
                    "status": "Flagged",
                    "type": threat_class
                })
                
        recent_transactions = recent_transactions[:100]
        logging.info(f"Forensic audit parsed {rows_parsed} rows; flagged {len(anomalies)} threat(s).")
        return {"status": "success", "rows_parsed": rows_parsed, "anomalies": anomalies}
        
    except Exception as e:
        logging.error(f"Failed to audit CSV logs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to audit CSV: {str(e)}")

# ==========================================
# Gemini AI Copilot & Security Orchestration
# ==========================================

class ThreatAnalysisPayload(BaseModel):
    source_ip: str
    target_ip: str
    risk_score: float
    payload_size_mb: float
    triggers: str

class ChatMessage(BaseModel):
    role: str
    content: str

class SystemStateMetadata(BaseModel):
    nodes_count: int
    links_count: int
    anomalies_count: int

class ChatPayload(BaseModel):
    messages: List[ChatMessage]
    system_state: SystemStateMetadata

class AuditTopologyPayload(BaseModel):
    nodes: List[Dict[str, Any]]
    links: List[Dict[str, Any]]

@app.post("/api/v1/copilot/analyze-threat")
async def analyze_threat(payload: ThreatAnalysisPayload):
    prompt = f"""
You are a Tier-3 SecOps Incident Responder. Analyze this cybersecurity incident payload:
- Source IP: {payload.source_ip}
- Target IP: {payload.target_ip}
- Risk Score: {payload.risk_score}%
- Payload Size: {payload.payload_size_mb} MB
- Rules/Triggers: {payload.triggers}

Generate a clean markdown report containing:
1. Executive Incident Summary
2. Technical Attack Vector Breakdown
3. Step-by-step Containment Playbook recommendations (including explicit CLI firewall block commands for the source/target IP).
"""
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(prompt)
            return {"markdown": response.text}
        except Exception as e:
            logging.error(f"Gemini API analysis failed: {e}")
            
    fallback_markdown = f"""# Incident Analysis Report: Flagged Threat Alert

## Executive Incident Summary
An anomalous event has been detected originating from **{payload.source_ip}** and targeting **{payload.target_ip}** with an AI risk score of **{payload.risk_score:.1f}%**. The session payload was **{payload.payload_size_mb:.2f} MB** and triggered the following rules: `{payload.triggers}`. This pattern matches unauthorized exfiltration or denial-of-service indicators.

## Technical Attack Vector Breakdown
* **Risk Score**: {payload.risk_score:.1f}% (AI/Heuristics flag)
* **Payload Volume**: {payload.payload_size_mb:.2f} MB (Anomalous deviation from baseline)
* **Connection Link**: {payload.source_ip} → {payload.target_ip}

## Step-by-step Containment Playbook
1. **Network Quarantine**: Disconnect and isolate the link between `{payload.source_ip}` and `{payload.target_ip}` in the active routing registry.
2. **Execute Firewall Block**:
   Apply the following commands to drop all traffic from the threat source:
   ```bash
   # Add rule to drop traffic from source IP
   iptables -A INPUT -s {payload.source_ip} -j DROP
   ufw deny from {payload.source_ip}
   ```
3. **Trace Intrusions**: Examine systemic access logs on the target endpoint.
"""
    return {"markdown": fallback_markdown}

@app.post("/api/v1/copilot/chat")
async def chat_copilot(payload: ChatPayload):
    history = ""
    for msg in payload.messages:
        role_label = "User" if msg.role == "user" else "Assistant"
        history += f"{role_label}: {msg.content}\n"
        
    system_instruction = f"""
You are a Tier-3 SecOps Incident Responder inside the Aegis Nexus Security Operations Center (SOC).
Your purpose is to answer user queries, generate bash scripts for isolating rogue servers, and summarize active network node metrics.

Active SOC System State Metrics:
- Total Nodes: {payload.system_state.nodes_count}
- Total Links: {payload.system_state.links_count}
- Flagged Anomalies: {payload.system_state.anomalies_count}

Provide helpful, technical, concise, action-oriented, and security-focused replies. If asked to generate a script, output clean, copy-pasteable shell commands.
"""
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash", system_instruction=system_instruction)
            prompt_content = f"{history}Assistant:"
            response = model.generate_content(prompt_content)
            return {"reply": response.text}
        except Exception as e:
            logging.error(f"Gemini API chat failed: {e}")

    last_query = payload.messages[-1].content.lower() if payload.messages else ""
    if "script" in last_query or "isolate" in last_query or "block" in last_query or "quarantine" in last_query:
        reply = f"""Here is a bash containment script to isolate potential threat actors:
```bash
#!/bin/bash
# Aegis Nexus - Automated Incident Isolation Playbook
# Restrict rogue connections immediately

IFACE="eth0"
TARGET_IP="[ENTER_ROGUE_IP]"

echo "[*] Quarantine mode initiated for $TARGET_IP on interface $IFACE"

# Block at iptables level
iptables -A INPUT -s "$TARGET_IP" -j DROP
iptables -A OUTPUT -d "$TARGET_IP" -j DROP

# Save firewall settings
iptables-save > /etc/iptables/rules.v4
echo "[+] Block applied successfully. Connections dropped."
```"""
    elif "summary" in last_query or "metric" in last_query or "node" in last_query or "status" in last_query:
        reply = f"""### Aegis SOC State Summary
* **Nodes Monitored**: {payload.system_state.nodes_count}
* **Network Links**: {payload.system_state.links_count}
* **Active Threats**: {payload.system_state.anomalies_count}
All pipelines are currently running with ML outlier analysis active."""
    else:
        reply = "Acknowledged. Aegis Copilot is active and monitoring network connections. Let me know if you need firewall scripts, compliance scorecards, or threat analysis reports."
        
    return {"reply": reply}

@app.post("/api/v1/copilot/audit-topology")
async def audit_topology(payload: AuditTopologyPayload):
    nodes_str = json.dumps(payload.nodes[:20])
    links_str = json.dumps(payload.links[:30])
    
    prompt = f"""
You are a Zero-Trust Compliance Auditor. Inspect this Aegis Nexus network topology snapshot:
Nodes: {nodes_str}
Links: {links_str}

Provide a Zero-Trust compliance scorecard audit.
Format your response as a JSON object containing exactly:
{{
  "score": <integer from 0 to 100>,
  "scorecard": "<Markdown text detailing compliance score, vulnerabilities like overcapacity transfer volumes or high risk nodes, and actionable remediation steps>"
}}
Make sure you respond with valid JSON containing "score" and "scorecard" keys.
"""
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(prompt)
            text = response.text.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()
            data = json.loads(text)
            return {"score": data.get("score", 70), "scorecard": data.get("scorecard", "Compliance audit finished.")}
        except Exception as e:
            logging.error(f"Gemini API topology audit failed: {e}")

    high_risk_count = 0
    for node in payload.nodes:
        if node.get("riskScore", 0) > 75:
            high_risk_count += 1
            
    base_score = max(35, 95 - (high_risk_count * 12))
    
    fallback_scorecard = f"""# Zero-Trust Compliance Audit Scorecard

## Compliance Score: {base_score}%

### Findings Summary
* **Active Nodes Audited**: {len(payload.nodes)}
* **Flagged Outlier Nodes**: {high_risk_count}
* **Network Integrity Status**: {"Action Required" if high_risk_count > 0 else "Compliant"}

### Threat & Vulnerability Analysis
1. **Outlier Connection Risk**:
   There are **{high_risk_count}** nodes operating with a risk metric exceeding the 75% threshold. This violates the 'never trust, always verify' paradigm.
2. **Unsegmented Intranet Gateway**:
   High-risk external servers are mapped to internal gateways without strict zero-trust boundary verification.

### Actionable Remediation Plan
1. **Enforce Micro-Segmentation**: Implement network policies to restrict communication between gateways and external hosts.
2. **Deploy IPS Rules**: Roll out real-time firewall block countermeasures for flagged outlier IPs.
"""
    return {"score": base_score, "scorecard": fallback_scorecard}

# Mount static files at root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
    logging.info(f"Serving static frontend files from: {FRONTEND_DIR}")
else:
    logging.warning(f"Frontend directory not found at: {FRONTEND_DIR}.")

@app.on_event("startup")
async def startup_event():
    # Train machine learning IsolationForest on start
    train_fallback_base_model()
    asyncio.create_task(redis_subscription_listener())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host=HOST, port=PORT, reload=True)
