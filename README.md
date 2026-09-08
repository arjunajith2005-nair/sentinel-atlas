# Sentinel ATLAS — Stateful AI Security Gateway

Sentinel ATLAS is a **stateful AI security gateway / reverse proxy** designed to detect and intercept multi-turn conversational attacks against AI agents (such as Crescendo attacks, prompt injection, logic hijacking, and intent/action mismatches).

---

## 🛡️ Key Features

- **Stateful Conversation Tracking**: Tracks session context, turn histories, risk trajectories, and topic branching.
- **Session Intent Anchor**: Establishes initial baseline intent (with 10-token minimum quality check and turn 1+2 averaging).
- **Topic Segmentation & Legitimate Topic Change Detection**: Separates benign topic shifts (e.g. asking about recipes or geography) from adversarial drift, preventing false positive lockouts.
- **Semantic Drift Engine**: Measures 4-turn rolling weighted drift and drift trajectories.
- **Threat Persistence**: Distinguishes single isolated anomalies from sustained multi-turn exploit attempts.
- **MITRE ATLAS Vector Indexing**: Offline ChromaDB vector database mapping adversarial prompts to known MITRE ATLAS techniques.
- **Worker & Auditor Architecture**: Dual-agent consensus checking Worker proposed actions against original user intent.
- **Transparent 7-Factor Risk Engine**: 0–100 score breakdown with full explainability.
- **Autonomous Response Playbooks**: `ALLOW` (0–25), `SANITIZE` (26–45), `RESET` (46–70), `REVOKE` (71–100).
- **Human-in-the-Loop Override**: Security analysts can review incidents and manually unblock sessions via the SOC dashboard or REST API.
- **Fail-Safe Mechanism**: Configurable `FAIL_OPEN` (default for development) or `FAIL_CLOSED` mode.

---

## 🏛️ Architecture Overview

```text
USER
 │
 ▼
FastAPI Gateway (/chat)
 │
 ▼
Session Manager (SQLite)
 │
 ▼
Semantic Processor (SentenceTransformers)
 │
 ▼
Intent & Topic Engine
 ├── Session Intent Anchor
 ├── Local Topic Anchor
 ├── Topic Segmentation
 └── Legitimate Topic Change Detection
 │
 ▼
Semantic Drift Engine
 ├── Anchor similarity
 ├── Rolling 4-turn drift
 └── Drift trajectory
 │
 ▼
Threat Analysis
 ├── MITRE ATLAS Vector Mapper (ChromaDB)
 └── Threat Persistence / Attack Trajectory
 │
 ▼
ATLAS Bridge
 ├── Worker Agent
 └── Auditor Agent (Dual-Agent Consensus)
 │
 ▼
Risk Engine (7-Factor 0–100 Formula)
 │
 ▼
Decision Engine
 ├── ALLOW    (0–25)
 ├── SANITIZE (26–45)
 ├── RESET    (46–70)
 └── REVOKE   (71–100)
 │
 ▼
SOC Dashboard (Streamlit)
```

---

## 🚀 Quick Start

### 1. Installation
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the Gateway Server
```powershell
python main.py
```
*The FastAPI gateway will start on `http://127.0.0.1:8000`.*
*Interactive API documentation is available at `http://127.0.0.1:8000/docs`.*

### 3. Run the SOC Operations Dashboard
```powershell
streamlit run dashboard/app.py
```
*Access the SOC dashboard at `http://localhost:8501`.*

---

## 📡 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/chat` | Main stateful reverse proxy chat endpoint |
| `GET` | `/sessions` | List active sessions, valid turns, and risk status |
| `GET` | `/sessions/{id}` | Retrieve session metadata, topics, and risk state |
| `GET` | `/sessions/{id}/messages` | Get complete message history with vector telemetry |
| `GET` | `/sessions/{id}/risk` | Retrieve risk score progression and factor breakdown |
| `GET` | `/sessions/{id}/trajectory` | Get turn-by-turn drift and threat trajectory |
| `GET` | `/alerts` | View operational security alerts |
| `POST` | `/sessions/{id}/override` | Analyst human override to unblock a restricted session |
| `POST` | `/sessions/{id}/reset` | Manually reset conversation context and intent anchors |
| `GET` | `/health` | Health check for gateway, database, and fail-safe mode |

---

## 🧪 Automated Testing & Attack Simulator

Run the complete verification test suite containing all 6 mandatory scenarios from Section 24:
```powershell
pytest tests/test_sentinel_suite.py -v
```

Run the attack scenarios evaluation:
```powershell
python -u tests/test_payloads.py
```
