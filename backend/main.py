"""
AI Network Traffic Analysis System — FastAPI Backend
المراحل 3 + 4 + 6: Auto-Response + Zeek Reader + AI Agent
"""
import asyncio
import random
from datetime import datetime

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from services.traffic_simulator import TrafficSimulator
from services.anomaly_detector   import AnomalyDetector
from services.alert_manager      import AlertManager
from services.auto_response      import AutoResponseEngine
from services.zeek_reader        import ZeekLogReader
from services.ai_agent           import AIAgent
from api.routes                  import router as api_router
from utils.auth                  import verify_token, create_token
from utils.logger                import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="AI Network Traffic Analysis System",
    description="Real-time monitoring · ML anomaly detection · Auto-response · AI Agent",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ─── Services ─────────────────────────────────────────
simulator     = TrafficSimulator()
detector      = AnomalyDetector()
alert_manager = AlertManager()
auto_response = AutoResponseEngine(dry_run=True)   # Set dry_run=False for real iptables
zeek_reader   = ZeekLogReader()                    # Auto-detects Zeek log path
ai_agent      = AIAgent(auto_response=auto_response)


# ─── WebSocket Manager ────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, payload: dict):
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.connections.remove(ws)

manager = ConnectionManager()


# ─── Register notification callbacks ──────────────────
async def _on_auto_action(action: dict):
    """Forward auto-response actions to all dashboard clients."""
    await manager.broadcast({"type": "auto_action", "action": action})

async def _on_agent_incident(event: dict):
    """Forward AI agent incidents to dashboard."""
    await manager.broadcast({"type": "agent_incident", **event})

auto_response.on_action(_on_auto_action)
ai_agent.on_incident(_on_agent_incident)


# ─── Main traffic loop ────────────────────────────────
async def stream_traffic():
    await asyncio.sleep(2)
    while True:
        try:
            # Try real Zeek first, fall back to simulator
            if zeek_reader.available:
                batch = zeek_reader.read_batch()
                if not batch:
                    await asyncio.sleep(0.5)
                    continue
            else:
                batch = simulator.generate_batch(size=random.randint(5, 20))

            # ML anomaly detection
            results = detector.analyze(batch)

            # Alert management
            new_alerts = alert_manager.process(results)

            # Auto-response (Phase 3)
            auto_actions = await auto_response.process(results)

            # Feed AI agent (Phase 6)
            if new_alerts:
                ai_agent.ingest_alerts(new_alerts)

            # Broadcast to dashboard
            await manager.broadcast({
                "type":         "traffic_update",
                "timestamp":    datetime.utcnow().isoformat(),
                "traffic":      results,
                "alerts":       new_alerts,
                "auto_actions": auto_actions,
                "stats":        alert_manager.get_stats(),
                "response_status": auto_response.get_status(),
            })

            await asyncio.sleep(1.5)

        except Exception as e:
            logger.error(f"Stream error: {e}")
            await asyncio.sleep(2)


@app.on_event("startup")
async def startup():
    logger.info("Starting SentryNet AI v3.0 ...")
    detector.train(simulator.generate_batch(size=500))
    asyncio.create_task(stream_traffic())
    logger.info(f"Zeek reader: {'LIVE' if zeek_reader.available else 'SIMULATOR'}")
    logger.info(f"Auto-response: {'DRY-RUN' if auto_response.dry_run else 'ACTIVE'}")
    logger.info("System ready.")


# ─── WebSocket endpoint ───────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({
            "type":    "init",
            "history": alert_manager.get_recent_traffic(limit=50),
            "stats":   alert_manager.get_stats(),
            "alerts":  alert_manager.get_recent_alerts(limit=20),
            "agent_status":    ai_agent.get_status(),
            "response_status": auto_response.get_status(),
        })
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ─── Auth ─────────────────────────────────────────────
@app.post("/auth/login")
async def login(creds: dict):
    if creds.get("username") == "admin" and creds.get("password") == "sentrynet2025":
        return {"token": create_token({"sub": "admin"}), "role": "admin"}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


# ─── Manual controls ──────────────────────────────────
@app.post("/api/v1/response/unblock/{ip}")
async def unblock(ip: str):
    ok = await auto_response.unblock_ip(ip)
    return {"success": ok, "ip": ip}

@app.get("/api/v1/response/status")
async def response_status():
    return auto_response.get_status()

@app.get("/api/v1/agent/status")
async def agent_status():
    return ai_agent.get_status()

@app.get("/api/v1/agent/reports")
async def agent_reports():
    return {"reports": ai_agent.incident_reports}

app.include_router(api_router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {
        "status":            "healthy",
        "version":           "3.0.0",
        "zeek_live":         zeek_reader.available,
        "auto_response":     not auto_response.dry_run,
        "agent_active":      True,
        "model_trained":     detector.is_trained,
        "connections":       len(manager.connections),
        "total_alerts":      alert_manager.total_alerts,
        "blocked_ips":       len(auto_response.blocked_ips),
        "total_incidents":   ai_agent.total_incidents,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
