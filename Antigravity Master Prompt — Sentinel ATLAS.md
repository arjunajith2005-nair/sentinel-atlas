# Build Sentinel ATLAS — Stateful AI Security Gateway

You are working on a project called **Sentinel ATLAS**.

Your job is to turn the existing repository into a fully working prototype of the architecture described below.

Do NOT blindly rewrite the repository.

First inspect the entire existing codebase, understand what is already implemented, identify missing/incomplete components, and then incrementally implement the architecture.

Preserve working code wherever possible.

---

# 1. PROJECT OBJECTIVE

Sentinel ATLAS is a **stateful AI security gateway / reverse proxy** designed to detect multi-turn conversational attacks against AI agents.

The central problem is that traditional AI security systems often inspect prompts independently.

Sentinel ATLAS instead analyzes the **evolution of a conversation over time**.

It should detect:

- gradual semantic manipulation
- Crescendo-style multi-turn attacks
- prompt injection
- role/context manipulation
- logic hijacking
- suspicious tool usage
- intent/action mismatches
- sustained malicious behavior

The system should:

1. Maintain state for every conversation.
2. Establish an initial Session Intent Anchor.
3. Maintain separate local topic anchors.
4. Detect legitimate topic changes.
5. Calculate semantic drift.
6. Analyze a rolling four-turn trajectory.
7. Map suspicious interactions to MITRE ATLAS techniques using vector similarity.
8. Run a Worker and Auditor architecture.
9. Compare the user's intent against the AI's proposed action.
10. Calculate a dynamic risk score.
11. Automatically allow, sanitize, reset, or revoke access.
12. Store all security events.
13. Display them through a SOC dashboard.
14. Provide a human analyst override mechanism.
15. Run locally through Docker.

---

# 2. IMPORTANT DESIGN PRINCIPLE

DO NOT make this mistake:

```text
high semantic drift = attack
```

That is incorrect.

Users can legitimately change topics.

Example:

```text
Turn 1:
Help me build a React website.

Turn 2:
What's the capital of Japan?

Turn 3:
Explain quantum computing.
```

This is semantic drift but NOT an attack.

Therefore:

```text
semantic drift
```

must be treated as a **security signal**, not a verdict.

The system must explicitly detect legitimate topic changes.

The actual decision should combine:

- semantic drift
- topic-change confidence
- MITRE ATLAS similarity
- prompt sensitivity
- behavioral persistence
- intent/action alignment
- Auditor verdict
- previous session risk
- attack trajectory

---

# 3. FINAL ARCHITECTURE

Implement this architecture:

```text
USER
 │
 ▼
FastAPI Gateway
 │
 ▼
Session Manager
 │
 ▼
Semantic Processor
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
 ├── MITRE ATLAS Vector Mapper
 └── Threat Persistence / Attack Trajectory
 │
 ▼
ATLAS Bridge
 ├── Worker Agent
 └── Auditor Agent
 │
 ▼
Risk Engine
 │
 ▼
Decision Engine
 ├── ALLOW
 ├── SANITIZE
 ├── RESET
 └── REVOKE
 │
 ▼
SOC Dashboard
```

---

# 4. TECHNOLOGY STACK

Use this stack for the prototype:

Backend:

- Python
- FastAPI
- Pydantic
- Uvicorn

AI / NLP:

- sentence-transformers
- all-MiniLM-L6-v2
- Ollama

Vector database:

- ChromaDB

Database:

- SQLite

Frontend:

- Streamlit

Numerical processing:

- NumPy
- scikit-learn

Containerization:

- Docker
- Docker Compose

Testing:

- pytest

Do NOT introduce Kafka, Kubernetes, MongoDB, Pinecone, Elasticsearch, AWS infrastructure, Grafana, or OpenTelemetry unless necessary for a clearly isolated production-demo component.

The first goal is a reliable local prototype.

---

# 5. REPOSITORY INSPECTION — DO THIS FIRST

Before changing anything:

1. Inspect the entire repository.
2. List all files.
3. Read the important Python files.
4. Identify existing functionality.
5. Identify duplicate implementations.
6. Identify broken imports.
7. Identify unfinished TODOs.
8. Identify which components already exist.
9. Create a short internal implementation plan.
10. Then implement the missing pieces.

Do not delete existing functionality simply because you would structure it differently.

If an existing implementation is correct, reuse it.

If it is partially correct, refactor it rather than replacing it unnecessarily.

---

# 6. RECOMMENDED PROJECT STRUCTURE

If the current project structure is poor, gradually move toward:

```text
sentinel-atlas/
│
├── gateway/
│   ├── __init__.py
│   ├── main.py
│   ├── routes.py
│   └── middleware.py
│
├── detection/
│   ├── __init__.py
│   ├── embeddings.py
│   ├── topic_engine.py
│   ├── drift.py
│   ├── persistence.py
│   ├── alignment.py
│   └── risk.py
│
├── atlas/
│   ├── __init__.py
│   ├── techniques.json
│   ├── embed_atlas.py
│   └── mapper.py
│
├── agents/
│   ├── __init__.py
│   ├── worker.py
│   └── auditor.py
│
├── response/
│   ├── __init__.py
│   ├── sanitizer.py
│   ├── reset.py
│   └── revoke.py
│
├── storage/
│   ├── __init__.py
│   ├── database.py
│   └── models.py
│
├── dashboard/
│   └── app.py
│
├── tests/
│   ├── test_embeddings.py
│   ├── test_topic_engine.py
│   ├── test_drift.py
│   ├── test_risk.py
│   ├── test_atlas.py
│   ├── test_alignment.py
│   └── test_attacks.py
│
├── data/
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── README.md
```

Adapt this to the existing repository rather than forcing it if the current structure is already good.

---

# 7. SESSION MANAGEMENT

Every conversation must have a unique session ID.

Example:

```json
{
  "session_id": "abc123",
  "message": "Analyse these customer support tickets."
}
```

Maintain session-level state:

```text
session_id
created_at
status
session_risk
intent_anchor
current_topic_id
attack_history
risk_history
```

Maintain message-level state:

```text
message_id
session_id
turn_number
message
embedding
topic_id
topic_change_score
drift_score
atlas_matches
risk_score
auditor_verdict
timestamp
```

Sessions must be completely isolated.

One user's anchor and history must never leak into another session.

---

# 8. EMBEDDING ENGINE

Use:

```text
sentence-transformers/all-MiniLM-L6-v2
```

Every prompt must be converted to a 384-dimensional vector.

Create a reusable embedding service.

Do not repeatedly load the model for every request.

Load it once and reuse it.

Implement:

```python
embed_text(text)
```

and:

```python
cosine_similarity(a, b)
cosine_distance(a, b)
```

---

# 9. SESSION INTENT ANCHOR

When the first message arrives:

If it contains at least 10 tokens:

```text
intent_anchor = embedding(turn_1)
```

If it contains fewer than 10 tokens:

wait for the second turn:

```text
intent_anchor =
mean(
    embedding(turn_1),
    embedding(turn_2)
)
```

The Session Intent Anchor represents the initial security context.

IMPORTANT:

Do not replace the session anchor merely because the user changes topic.

---

# 10. LOCAL TOPIC ANCHORS

Implement a separate topic segmentation system.

Example:

```text
Topic 1:
React development

Topic 2:
Japanese geography

Topic 3:
Quantum computing
```

Each topic should have:

```text
topic_id
topic_anchor
first_turn
last_turn
messages
```

When a new prompt arrives:

Calculate similarity to:

1. current topic anchor
2. previous topic anchors
3. session intent anchor

If similarity to the current topic becomes low but the new prompt is internally coherent and benign, classify it as:

```text
LEGITIMATE_TOPIC_CHANGE
```

Create a new topic anchor.

Do NOT increase risk simply because the topic changed.

---

# 11. LEGITIMATE TOPIC CHANGE DETECTOR

Create:

```python
detect_topic_change(...)
```

It should return something like:

```json
{
  "topic_changed": true,
  "benign_topic_confidence": 0.91,
  "new_topic": true
}
```

A topic change should generally have low security impact when:

- ATLAS similarity is low
- prompt sensitivity is low
- there is no suspicious instruction
- the Auditor does not detect an action mismatch
- malicious persistence is absent

Do NOT rely on keywords alone.

Use semantic similarity and contextual signals.

---

# 12. SEMANTIC DRIFT ENGINE

For every message calculate:

```text
current message
       ↓
distance from Session Intent Anchor
       ↓
drift
```

Also calculate:

```text
current message
       ↓
distance from Local Topic Anchor
       ↓
local topic drift
```

Maintain a rolling four-turn window.

Example:

```text
T2
T3
T4
T5
```

Use a weighted rolling average where recent turns receive greater weight.

Store the drift for every turn.

IMPORTANT:

High drift by itself must NOT trigger blocking.

---

# 13. THREAT PERSISTENCE

Implement:

```python
calculate_persistence(...)
```

The purpose is to distinguish:

```text
one unusual message
```

from:

```text
repeated suspicious behavior across multiple turns
```

Example:

```text
normal
normal
suspicious
suspicious
suspicious
```

should have substantially higher persistence than:

```text
normal
normal
suspicious
normal
normal
```

Persistence should influence risk.

---

# 14. MITRE ATLAS MAPPING

Create a local MITRE ATLAS technique dataset.

Each technique should contain:

```json
{
  "id": "...",
  "name": "...",
  "description": "..."
}
```

At startup:

```text
technique description
        ↓
embedding
        ↓
ChromaDB
```

For a suspicious interaction:

```text
interaction
    ↓
embedding
    ↓
ChromaDB similarity search
    ↓
Top-K techniques
```

Return:

```json
{
  "matches": [
    {
      "technique_id": "...",
      "technique_name": "...",
      "confidence": 0.89
    }
  ]
}
```

Do not claim that semantic similarity is definitive proof of a technique.

It is a candidate attribution signal.

---

# 15. ATLAS BRIDGE

Implement two agents.

## Worker

The Worker represents the target AI agent.

It receives:

```text
system context
conversation
current user prompt
available tools
```

and produces:

```text
text response
```

or:

```text
proposed tool action
```

The Worker should be replaceable with another LLM/API later.

Create a clean abstraction.

---

# 16. AUDITOR

The Auditor is an independent security model.

It receives:

```text
Original Session Intent
Current Local Topic
Conversation history
Current user request
Worker response
Worker proposed tool call
Current risk signals
```

It must determine:

```text
ALIGNED
```

or:

```text
MISALIGNED
```

Example:

```text
Original intent:
Analyse public sales statistics.

Worker action:
Retrieve private customer database.

Auditor:
MISALIGNED
```

The Auditor should return structured JSON:

```json
{
  "verdict": "MISALIGNED",
  "confidence": 0.94,
  "reason": "The proposed database action exceeds the user's stated analytical intent."
}
```

Do not rely on parsing arbitrary prose if structured output can be used.

---

# 17. INTENT-ACTION ALIGNMENT

Calculate a numerical alignment score between:

```text
Original Intent
        ↕
Worker Proposed Action
```

Use embedding similarity where appropriate.

Combine it with the Auditor verdict.

Example:

```text
alignment_score = 0.18
auditor = MISALIGNED
```

This should be a strong risk signal.

But:

```text
alignment_score = 0.25
auditor = ALIGNED
```

should not automatically mean an attack.

The system must combine signals.

---

# 18. PROMPT SENSITIVITY

Create a sensitivity score.

It should represent how security-sensitive the interaction is.

Examples:

```text
"What is Python?"
→ very low

"Explain database indexes."
→ low

"How can I bypass access controls?"
→ high

"Retrieve restricted credentials."
→ critical
```

Do not implement this purely as a hardcoded keyword blacklist.

Use semantic classification where possible.

Keyword indicators may be secondary features.

---

# 19. FINAL RISK ENGINE

Implement a transparent scoring model.

Use:

```text
Risk =
W1 × ATLAS confidence
+
W2 × semantic drift
+
W3 × sensitivity
+
W4 × persistence
+
W5 × action misalignment
+
W6 × behavioral risk
-
W7 × benign topic confidence
```

Normalize the final score to:

```text
0–100
```

Do not hide the calculation.

The dashboard should show WHY a score was produced.

Example:

```text
Risk Score: 78

ATLAS confidence       +21
Semantic drift         +17
Sensitivity            +15
Persistence            +10
Action mismatch        +20
Benign topic discount   -5
                        ----
                         78
```

Make the weights configurable.

Store them in configuration rather than scattering constants through the code.

---

# 20. RESPONSE POLICY

Use:

```text
0–25
ALLOW

26–45
CONTEXT SANITISATION

46–70
SESSION RESET

71–100
ACCESS REVOCATION
```

Implement:

## ALLOW

Pass request normally.

## SANITIZE

Remove or neutralize suspicious contextual material while preserving the legitimate request.

Do not blindly delete random words.

Create a deterministic and inspectable sanitizer.

## RESET

Clear:

```text
conversation memory
local topic state
session intent state
```

or explicitly implement the exact reset semantics and document them.

## REVOKE

Mark:

```text
session.status = REVOKED
```

Reject further requests from that session.

---

# 21. IMPORTANT FAIL-SAFE

Sentinel ATLAS must not become a single point of failure.

If the security proxy itself becomes unavailable, support configurable behavior:

```text
FAIL_OPEN
```

or:

```text
FAIL_CLOSED
```

Default the development environment to:

```text
FAIL_OPEN
```

but log:

```text
SECURITY_GATEWAY_UNAVAILABLE
```

Never silently bypass security.

---

# 22. SOC DASHBOARD

Create a professional Streamlit dashboard.

It should contain:

## Overview

```text
Active Sessions
Total Requests
Active Threats
Critical Threats
Average Risk
Blocked Sessions
```

## Risk Timeline

Display:

```text
Turn 1 → 10
Risk:
12 → 15 → 18 → 29 → 42 → 61 → 78
```

## Semantic Drift Timeline

Display drift per turn.

## Topic Timeline

Example:

```text
T1–T3   React Development
T4–T5   Japan
T6–T9   Database Security
```

## MITRE ATLAS

Display:

```text
Technique
Confidence
Occurrences
```

## Attack Trajectory

Example:

```text
Turn 1
Normal
 ↓
Turn 2
Topic shift
 ↓
Turn 3
Sensitive request
 ↓
Turn 4
ATLAS candidate
 ↓
Turn 5
Action mismatch
 ↓
CRITICAL
```

## Auditor

Display:

```text
ALIGNED / MISALIGNED
confidence
reason
```

## Response

Display:

```text
ALLOW
SANITIZE
RESET
REVOKE
```

## Human Override

Allow an analyst to manually unblock a session.

Every override MUST be logged.

---

# 23. API ENDPOINTS

Implement at minimum:

```text
POST /chat
GET /sessions
GET /sessions/{session_id}
GET /sessions/{session_id}/messages
GET /sessions/{session_id}/risk
GET /sessions/{session_id}/trajectory
GET /alerts
POST /sessions/{session_id}/override
POST /sessions/{session_id}/reset
GET /health
```

Example:

```text
POST /chat
```

request:

```json
{
  "session_id": "abc123",
  "message": "Analyse these sales reports."
}
```

response:

```json
{
  "session_id": "abc123",
  "turn": 1,
  "response": "...",
  "risk_score": 8,
  "decision": "ALLOW",
  "topic_changed": false,
  "drift_score": 0.02,
  "atlas_matches": [],
  "auditor": {
    "verdict": "ALIGNED"
  }
}
```

---

# 24. TESTING IS CRITICAL

Do not just test normal requests.

Create automated test scenarios.

## Test 1 — Normal conversation

```text
Analyse sales data.
Find highest-performing products.
Calculate growth.
Generate summary.
```

Expected:

```text
LOW RISK
ALLOW
```

## Test 2 — Benign unrelated topic changes

```text
Help me build a React website.
What is the capital of Japan?
Explain black holes.
How does a car engine work?
What is SQL?
```

Expected:

```text
multiple topic changes
LOW SECURITY RISK
ALLOW
```

This test is REQUIRED.

## Test 3 — Gradual Crescendo attack

Create a controlled multi-turn attack script.

Expected:

```text
drift increases
persistence increases
ATLAS confidence increases
risk increases
eventually RESET or REVOKE
```

## Test 4 — Single suspicious message

One suspicious message followed by normal behavior.

Expected:

```text
elevated signal
but NOT automatically catastrophic
```

## Test 5 — Benign conversation with technical security terminology

Example:

```text
Explain how authentication works.
What is SQL injection?
How do companies defend against prompt injection?
```

Expected:

```text
technical/security discussion
but not automatically malicious
```

This is important for false-positive testing.

## Test 6 — Worker action mismatch

Original intent:

```text
Summarize public documents.
```

Worker attempts:

```text
retrieve private database records
```

Expected:

```text
Auditor = MISALIGNED
risk increases
```

---

# 25. ATTACK SIMULATOR

Create:

```text
tests/attack_scenarios/
```

with JSON or YAML attack definitions.

Example:

```yaml
name: crescendo_database_attack

turns:
  - ...
  - ...
  - ...
  - ...
```

The test runner should execute the attack automatically and generate:

```text
risk progression
drift progression
ATLAS predictions
Auditor decisions
final response
```

This becomes one of the strongest demonstrations of the project.

---

# 26. DATABASE SCHEMA

Create appropriate tables.

At minimum:

```text
sessions
messages
topics
risk_events
atlas_matches
alerts
auditor_decisions
overrides
```

Relationships:

```text
session
   │
   ├── messages
   │      │
   │      ├── topic
   │      ├── drift
   │      ├── risk
   │      └── ATLAS matches
   │
   ├── alerts
   ├── auditor decisions
   └── overrides
```

---

# 27. SECURITY AND PRIVACY

Do not store sensitive data unnecessarily.

Provide configuration for:

```text
LOG_RETENTION_DAYS
STORE_RAW_PROMPTS
STORE_EMBEDDINGS
```

Document that session logs can contain sensitive information.

Never log:

```text
API keys
passwords
tokens
credentials
```

---

# 28. DOCKER

Create a Dockerized local environment.

At minimum:

```text
sentinel-api
sentinel-dashboard
sentinel-chromadb
sentinel-ollama
```

If Ollama cannot conveniently run inside the same Docker Compose environment on the host, document the supported local configuration rather than creating a fragile container setup.

The application should still run without Docker for development.

---

# 29. OBSERVABILITY

For the prototype, use normal structured application logging.

Every important security event should contain:

```text
timestamp
session_id
turn
event_type
risk_score
decision
atlas_technique
auditor_verdict
```

Production OpenTelemetry/Grafana can be documented as