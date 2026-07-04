import asyncio
import json
import os
import sys
import urllib.request
import urllib.parse
import websockets

BACKEND_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/backend/gateway"
CSV_PATH = r"c:\Hacki Project\data\sample_transactions.csv"

async def test_full_pipeline():
    print("--- STARTING AEGIS FULL PIPELINE INTEGRATION TEST ---")
    
    # 1. Connect WebSocket Client
    print(f"Connecting to WebSocket Gateway: {WS_URL}")
    try:
        websocket = await websockets.connect(WS_URL)
        print("WebSocket connected successfully!")
    except Exception as e:
        print(f"WebSocket connection failed: {e}")
        return False

    async def ws_listener():
        try:
            print("WebSocket listener started.")
            async for message in websocket:
                if message == "ping":
                    print("[WS Listener] Received heartbeat ping, responding with pong.")
                    await websocket.send("pong")
                else:
                    try:
                        alert = json.loads(message)
                        print(f"[WS Listener] Received live alert broadcast: {json.dumps(alert, indent=2)}")
                    except Exception:
                        print(f"[WS Listener] Received raw alert: {message}")
        except websockets.exceptions.ConnectionClosed:
            print("WebSocket connection closed.")
        except Exception as e:
            print(f"WebSocket listener error: {e}")

    # Start the WS listener in the background
    listener_task = asyncio.create_task(ws_listener())
    await asyncio.sleep(1) # Allow listener to start

    # 2. Upload CSV
    print(f"\n1. Uploading transaction dataset from: {CSV_PATH}")
    try:
        # Prepare multipart/form-data manually to avoid external libraries dependency
        with open(CSV_PATH, 'rb') as f:
            csv_content = f.read()
            
        boundary = '----WebKitFormBoundaryAegisTest12345'
        data = (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="file"; filename="sample_transactions.csv"\r\n'
            f'Content-Type: text/csv\r\n\r\n'
        ).encode('utf-8') + csv_content + f'\r\n--{boundary}--\r\n'.encode('utf-8')
        
        req = urllib.request.Request(
            f"{BACKEND_URL}/api/upload",
            data=data,
            headers={
                'Content-Type': f'multipart/form-data; boundary={boundary}',
                'Content-Length': len(data)
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req) as res:
            res_data = json.loads(res.read().decode('utf-8'))
            print("Upload Response:", res_data)
            assert res_data["status"] == "success"
    except Exception as e:
        print(f"Upload failed: {e}")
        listener_task.cancel()
        return False

    # 3. Process ML
    print("\n2. Processing ML anomaly detection (IsolationForest)...")
    try:
        ml_data = json.dumps({"filePath": "sample_transactions.csv"}).encode('utf-8')
        req = urllib.request.Request(
            f"{BACKEND_URL}/api/process-ml",
            data=ml_data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        
        with urllib.request.urlopen(req) as res:
            ml_res = json.loads(res.read().decode('utf-8'))
            print(f"ML Processed. Accounts extracted: {len(ml_res['accounts'])}, Links: {len(ml_res['links'])}")
            assert ml_res["status"] == "success"
    except Exception as e:
        print(f"ML Processing failed: {e}")
        listener_task.cancel()
        return False

    # 4. Ingest Graph Database (Neo4j Ingestion)
    print("\n3. Committing Ingestion to Graph Database (Neo4j/Graph Ingest)...")
    try:
        ingest_payload = json.dumps({
            "accounts": ml_res["accounts"],
            "links": ml_res["links"]
        }).encode('utf-8')
        
        req = urllib.request.Request(
            f"{BACKEND_URL}/api/ingest-neo4j",
            data=ingest_payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        
        with urllib.request.urlopen(req) as res:
            ingest_res = json.loads(res.read().decode('utf-8'))
            print("Ingestion Response:", ingest_res)
            assert ingest_res["status"] == "success"
    except Exception as e:
        print(f"Ingestion failed: {e}")
        listener_task.cancel()
        return False

    # Wait for the WebSocket to receive the broadcasted alerts
    print("\nWaiting 4 seconds to observe WebSocket live alerts...")
    await asyncio.sleep(4)

    # 5. Verify Updated Graph State
    print("\n4. Verifying updated visual graph state...")
    try:
        with urllib.request.urlopen(f"{BACKEND_URL}/api/graph") as res:
            graph = json.loads(res.read().decode('utf-8'))
            print(f"Updated Graph: {len(graph['nodes'])} nodes, {len(graph['links'])} links")
            # Verify nodes list has expanded beyond initial mock nodes
            assert len(graph["nodes"]) > 5
    except Exception as e:
        print(f"Graph verification failed: {e}")
        listener_task.cancel()
        return False

    # Clean up WS connection
    print("\nCleaning up WebSocket connection...")
    listener_task.cancel()
    await websocket.close()
    
    print("\n--- ALL PIPELINE STEPS COMPLETED & VERIFIED SUCCESSFULLY ---")
    return True

if __name__ == "__main__":
    try:
        success = asyncio.run(test_full_pipeline())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nTest stopped by user.")
