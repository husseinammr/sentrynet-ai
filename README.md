 https://husseinammr.github.io/sentrynet-ai/

<div align="center">

# 🛡️ SentryNet AI
### AI-Powered Network Traffic Analysis & Autonomous Threat Response

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-Isolation%20Forest-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)](https://scikit-learn.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

<br/>

> **Real-time network threat detection powered by Machine Learning.**
> Monitors traffic, detects anomalies, auto-responds to attacks, and generates AI-driven incident reports — all in one system.

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Quick Demo](#-quick-demo)
- [Full Stack Setup](#-full-stack-setup)
- [Machine Learning Model](#-machine-learning-model)
- [Auto-Response Engine](#-auto-response-engine)
- [AI Agent](#-ai-agent)
- [REST API](#-rest-api-reference)
- [Dashboard](#-dashboard)
- [Project Structure](#-project-structure)
- [Tech Stack](#-tech-stack)
- [Roadmap](#-roadmap)

---

## 🎯 Overview

**SentryNet AI** is a full-stack cybersecurity platform that brings together:

- **Real-time Zeek log ingestion** — reads live `conn.log` streams or falls back to a built-in simulator
- **ML-powered anomaly detection** — Isolation Forest trained on normal traffic, flags anything unusual
- **Automated threat response** — blocks IPs via iptables, isolates infected LAN hosts, auto-unblocks after timeout
- **Autonomous AI Agent** — sends incident batches to Claude AI for deep analysis, generates structured forensic reports, and coordinates response actions
- **Live WebSocket dashboard** — 4-panel UI with real-time charts, GeoIP map, threat log, and incident reports

**The problem it solves:** Networks carry thousands of connections per second — impossible to monitor manually. Attackers exploit this blind spot. SentryNet AI watches 24/7, detects threats in seconds, and responds autonomously.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔍 **Anomaly Detection** | Isolation Forest ML model — learns normal traffic, flags deviations |
| ⚡ **Real-time Streaming** | WebSocket broadcast every 1.5s to all connected dashboards |
| 🚫 **Auto-Block** | Automatically blocks malicious IPs via iptables rules |
| 🔒 **Host Isolation** | Quarantines infected LAN hosts from the network |
| 🤖 **AI Agent** | Claude-powered incident analysis with full forensic reports |
| 📡 **Zeek Integration** | Live `conn.log` tailing; auto-detects Zeek installation |
| 🌍 **GeoIP Mapping** | Animated origin dots on world map by lat/lng |
| 📊 **Attack Classification** | DDoS · Port Scan · Brute Force · Data Exfiltration |
| 🗄️ **Dual Database** | MongoDB + PostgreSQL for logs, alerts, and IP stats |
| 🐳 **Docker Ready** | Full `docker-compose.yml` — one command to run everything |
| 🔐 **JWT Auth** | Token-based authentication with role-based access |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          SentryNet AI v3.0                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│   Network Traffic                                                 │
│        │                                                          │
│   ┌────▼────────┐    ┌───────────────────┐                       │
│   │ Zeek Reader │    │ Traffic Simulator  │  (fallback)           │
│   │ conn.log    │    │ synthetic data     │                       │
│   └────┬────────┘    └─────────┬──────────┘                       │
│        └──────────┬────────────┘                                  │
│                    │                                               │
│           ┌────────▼─────────┐                                    │
│           │ Anomaly Detector │  ← Isolation Forest (sklearn)      │
│           │ Feature Extract  │     9 features per entry           │
│           └────────┬─────────┘                                    │
│                    │  enriched entries                            │
│           ┌────────▼─────────┐                                    │
│           │  Alert Manager   │  ← stats, top IPs, time-series     │
│           └────┬─────────────┘                                    │
│                │                                                   │
│     ┌──────────┼───────────────┐                                  │
│     │          │               │                                  │
│  ┌──▼─────┐ ┌──▼────────┐ ┌───▼──────┐                           │
│  │  Auto  │ │  AI Agent │ │WebSocket │                           │
│  │Response│ │  (Claude) │ │Broadcast │                           │
│  │ Engine │ │           │ │          │                           │
│  └──┬─────┘ └─────┬─────┘ └────┬─────┘                           │
│     │             │             │                                 │
│  iptables    Incident       Dashboard                             │
│  rules       Reports        (browser)                             │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Demo

**No backend needed** — open directly in your browser:

```bash
git clone https://github.com/yourusername/sentrynet-ai.git
cd sentrynet-ai

# Open the dashboard
open frontend/dashboard.html
# or: python3 -m http.server 3000 && open http://localhost:3000/dashboard.html
```

**Login:** `admin` / `sentrynet2025`

The dashboard runs in fully simulated mode — attacks are injected randomly, the AI Agent generates incident reports, and the auto-response engine blocks and unblocks IPs automatically. No backend, database, or API keys required to try it.

---

## 🚀 Full Stack Setup

### Prerequisites

- Python 3.11+
- pip
- (Optional) Docker & Docker Compose
- (Optional) Zeek 6.x for live traffic
- (Optional) Anthropic API key for the AI Agent

### 1. Install dependencies

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start the backend

```bash
# Standard mode (simulated traffic)
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# With live Zeek logs (auto-detected if Zeek is installed)
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 3. Connect the dashboard to the backend

Open `frontend/dashboard.html`, find `connectWS()`, and uncomment the real WebSocket block:

```javascript
ws = new WebSocket('ws://localhost:8000/ws');
ws.onopen    = () => { document.getElementById('hstatus').textContent = 'LIVE'; };
ws.onmessage = e  => { handleMessage(JSON.parse(e.data)); };
ws.onclose   = () => { setTimeout(connectWS, 3000); };
```

### 4. Docker (Full Stack)

```bash
docker-compose up --build

# Services:
#   Dashboard  →  http://localhost:3000
#   Backend    →  http://localhost:8000
#   API Docs   →  http://localhost:8000/docs
#   MongoDB    →  localhost:27017
#   PostgreSQL →  localhost:5432
```

---

## 🤖 Machine Learning Model

### Algorithm: Isolation Forest

Isolation Forest is ideal for network anomaly detection because:
- Works without labeled attack data (unsupervised)
- Fast inference — handles thousands of entries/second
- Low false positive rate on stable, normal traffic patterns

### Features Extracted

| # | Feature | Description |
|---|---|---|
| 1 | `bytes` | Total bytes transferred |
| 2 | `packets` | Packet count |
| 3 | `duration` | Connection duration (seconds) |
| 4 | `dst_port` | Destination port |
| 5 | `src_port` | Source port |
| 6 | `protocol` | TCP=0, UDP=1, ICMP=2 |
| 7 | `conn_state` | SF=0, S0=1, REJ=2, RSTO=3, OTH=4 |
| 8 | `bytes/sec` | Throughput rate |
| 9 | `packets/sec` | Packet rate |

### Attack Classification Rules

| Attack Type | Detection Signature |
|---|---|
| **DDoS** | packets > 200, duration < 0.5s, protocol = UDP |
| **Port Scan** | state = REJ/S0, bytes < 300, duration < 50ms |
| **Brute Force** | port ∈ {22, 3389, 21, 5900}, state = REJ/RSTO |
| **Data Exfiltration** | bytes > 50KB, packets < 50 |

### Train the Model

```bash
cd models
python train_model.py

# ─────────────────────────────────────────────────────────────
#   EVALUATION REPORT
# ─────────────────────────────────────────────────────────────
#   Accuracy : 94.2%
#   Precision: 91.8%
#   Recall   : 88.5%
#   F1 Score : 90.1%
# ─────────────────────────────────────────────────────────────
```

### Generate a Synthetic Dataset

```bash
cd data
python generate_dataset.py --rows 10000 --out zeek_conn.csv

# Distribution:
#   Normal        : ~8,600 rows (86%)
#   DDoS          :   ~500 rows (5%)
#   Port Scan     :   ~500 rows (5%)
#   Brute Force   :   ~400 rows (4%)
```

---

## 🚫 Auto-Response Engine

`backend/services/auto_response.py` reacts to confirmed threats **in real time**, without human intervention.

### Response Actions

| Trigger | Threshold | Action |
|---|---|---|
| DDoS flood | ≥ 1,000 pps from a single IP | Block IP via `iptables -A INPUT -s <ip> -j DROP` |
| Brute Force | ≥ 5 failed attempts | Block IP, log targeted port |
| Port Scan | ≥ 20 distinct ports probed | Block IP |
| Data Exfiltration (internal) | Any internal host | Isolate host via iptables FORWARD rules |
| — | After 300 seconds | Auto-unblock, rule removed automatically |

### Modes

```python
# Dry-run mode (default) — logs actions but never touches iptables
auto_response = AutoResponseEngine(dry_run=True)

# Active mode — applies real iptables rules (requires root)
auto_response = AutoResponseEngine(dry_run=False)
```

### Manual Control via API

```bash
# Unblock a specific IP
curl -X POST http://localhost:8000/api/v1/response/unblock/185.220.101.45

# Check currently blocked IPs and isolated hosts
curl http://localhost:8000/api/v1/response/status
```

---

## 🧠 AI Agent

`backend/services/ai_agent.py` is the autonomous intelligence layer that sits above raw detection.

### Pipeline

```
1. Ingest high/critical alerts from the Alert Manager
2. Batch up to 5 alerts per analysis cycle
3. Send structured context to the Claude API
4. Parse the JSON response into an Incident Report
5. Execute recommended auto-response actions
6. Broadcast the forensic report to the dashboard
7. Store report history (last 50 incidents)
```

If the Claude API is unavailable, the agent falls back to rule-based incident analysis so the system never stops responding.

### Incident Report Structure

```json
{
  "incident_id": "INC-1042",
  "title": "DDoS Attack Detected",
  "severity": "critical",
  "attack_type": "DDoS",
  "confidence": 0.94,
  "summary": "Sustained UDP flood from 185.220.101.45...",
  "attacker_profile": "Botnet operator using UDP amplification",
  "impact_assessment": "Service unavailability, bandwidth saturation",
  "recommended_actions": ["Block source IP", "Enable rate limiting", "..."],
  "auto_actions_taken": ["Blocked IP: 185.220.101.45"],
  "ioc": { "ips": ["185.220.101.45"], "ports": [80, 443], "protocols": ["udp"] },
  "report": "Incident INC-1042: A CRITICAL severity DDoS attack..."
}
```

### Agent API Endpoints

```bash
# Get agent status and queue depth
curl http://localhost:8000/api/v1/agent/status

# Get all incident reports
curl http://localhost:8000/api/v1/agent/reports
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/auth/login` | Authenticate → returns JWT |
| `GET` | `/health` | System health + component status |
| `WS` | `/ws` | Real-time WebSocket stream |
| `GET` | `/api/v1/traffic` | Recent traffic logs (`?limit=100`) |
| `GET` | `/api/v1/alerts` | Recent alerts (`?severity=high&attack_type=DDoS`) |
| `GET` | `/api/v1/stats` | Aggregated statistics + top IPs |
| `GET` | `/api/v1/top-ips` | Top IPs by traffic volume |
| `GET` | `/api/v1/attack-summary` | Attack type distribution |
| `GET` | `/api/v1/response/status` | Blocked IPs + isolated hosts |
| `POST` | `/api/v1/response/unblock/{ip}` | Manually unblock an IP |
| `GET` | `/api/v1/agent/status` | AI Agent queue + stats |
| `GET` | `/api/v1/agent/reports` | All incident reports |

**Interactive API docs:** `http://localhost:8000/docs`

### Example Requests

```bash
# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"sentrynet2025"}'

# Recent critical alerts
curl "http://localhost:8000/api/v1/alerts?severity=critical&limit=10"

# System health
curl http://localhost:8000/health
```

---

## 📊 Dashboard

`frontend/dashboard.html` is a self-contained, single-file application with 4 tabs.

### Tab 1 — Monitor
| Panel | Content |
|---|---|
| Real-Time Traffic | Live line chart — packets/s + anomaly overlay |
| Threat Distribution | Attack type donut + protocol donut |
| Top Source IPs | Volume-ranked bars, red highlights for threat IPs |
| Packet Stream | Last 6 Zeek log entries with status badges |
| Threat Log | Scrolling alert feed, color-coded by severity |
| GeoIP Map | Animated origin dots by geographic coordinates |
| Attack Summary | Counters for DDoS, Port Scan, Brute Force, Exfil |

### Tab 2 — Auto-Response
- **Blocked IPs** — live list with reason, timestamp, manual unblock button
- **Action Feed** — every automated action logged in real time
- **Isolated Hosts** — LAN hosts quarantined by the engine
- **Configuration** — thresholds and current mode (DRY-RUN / ACTIVE)

### Tab 3 — AI Agent
- **Incident Reports** — expandable cards per incident
- **Analysis details** — summary, attacker profile, impact assessment
- **IOC list** — IPs, ports, protocols per incident
- **Forensic report** — full narrative paragraph
- **Agent Status** — live pipeline stats

### Tab 4 — Zeek / Data
- Zeek log detection status and search paths
- Dataset generation commands
- ML feature list
- System architecture overview

---

## 📁 Project Structure

```
sentrynet-ai/
│
├── backend/
│   ├── main.py                  # FastAPI app — all services wired together
│   ├── requirements.txt            # Python dependencies
│   ├── Dockerfile                  # Container image
│   │
│   ├── api/
│   │   └── routes.py               # REST API endpoints (v1)
│   │
│   ├── services/
│   │   ├── traffic_simulator.py    # Zeek-style synthetic traffic generator
│   │   ├── zeek_reader.py          # Live Zeek conn.log reader
│   │   ├── anomaly_detector.py     # Isolation Forest ML model
│   │   ├── alert_manager.py        # Alert tracking, stats, history
│   │   ├── auto_response.py        # Automated IP blocking / isolation
│   │   └── ai_agent.py             # Autonomous Claude-powered agent
│   │
│   └── utils/
│       ├── auth.py                 # HMAC-SHA256 JWT implementation
│       ├── logger.py               # Structured logging
│       └── schema.sql              # PostgreSQL schema
│
├── frontend/
│   ├── dashboard.html               # Full dashboard (self-contained)
│   └── nginx.conf                   # Nginx reverse proxy config
│
├── models/
│   └── train_model.py              # Model training + evaluation script
│
├── data/
│   └── generate_dataset.py         # Zeek CSV dataset generator
│
├── docs/
│   └── estimate.html               # Project estimate
│
├── docker-compose.yml              # Full stack: backend + frontend + DBs
└── README.md
```

---

## 🔧 Environment Variables

Create a `.env` file in `backend/`:

```env
# Database
MONGO_URI=mongodb://localhost:27017/sentrynet
POSTGRES_URI=postgresql://postgres:sentrynet@localhost:5432/sentrynet

# Auth
SECRET_KEY=your-secret-key-change-in-production

# Auto-Response
DRY_RUN=true          # Set to false for real iptables rules

# Zeek
ZEEK_LOG_PATH=         # Leave empty for auto-detection

# AI Agent
ANTHROPIC_API_KEY=     # Required for live Claude analysis (optional — falls back to rules)
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11, FastAPI, Uvicorn |
| **ML** | scikit-learn (Isolation Forest), NumPy, pandas |
| **WebSocket** | FastAPI WebSocket, websockets |
| **Database** | MongoDB 7 + PostgreSQL 16 |
| **Frontend** | Vanilla JS, Chart.js 4, CSS Grid |
| **AI Agent** | Anthropic Claude API |
| **IDS/Traffic** | Zeek 6.x (or built-in simulator) |
| **Auth** | HMAC-SHA256 JWT |
| **Deploy** | Docker, Docker Compose, Nginx |

---

## 🗺️ Roadmap

- [x] Real-time monitoring dashboard
- [x] ML anomaly detection (Isolation Forest)
- [x] Automated IP blocking & host isolation
- [x] Live Zeek log integration
- [x] Autonomous AI Agent (Claude)
- [ ] LSTM time-series model for sequence attacks
- [ ] Mobile push notifications (Telegram / Slack)
- [ ] Multi-tenant / enterprise mode
- [ ] SIEM integration (Splunk, IBM QRadar)
- [ ] Compliance reports (ISO 27001, NCA)

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built for network defenders.

⭐ **Star this repo** if SentryNet AI helped you!

</div>
