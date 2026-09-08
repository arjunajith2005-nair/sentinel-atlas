import sys
sys.dont_write_bytecode = True

import os
import asyncio
import logging
from contextlib import asynccontextmanager
import uuid
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Gateway & Logging
from gateway.logger import log_security_event
from gateway.async_auditor import auditor

# Embeddings & Classification
from embeddings.encoder import get_embedding
from embeddings.rules import evaluate_security_rules
from embeddings.safety import check_content_safety
from intelligence.classifier import classify_threat

# Detection Engines (Sections 8-13, 17, 18, 19)
from detection.topic_engine import TopicEngine
from detection.drift import calculate_semantic_drift
from detection.sensitivity import calculate_prompt_sensitivity
from detection.persistence import calculate_threat_persistence
from detection.alignment import calculate_intent_action_alignment
from detection.risk import calculate_transparent_risk, determine_action, DEFAULT_CONFIG_WEIGHTS

# Agents (Sections 15 & 16)
from agents.worker import WorkerAgent
from agents.auditor import AuditorAgent

# Storage & Session Management (Sections 7 & 26)
from session.db import (
    init_db,
    save_turn,
    save_blocked_turn,
    get_session_history,
    get_all_sessions,
    get_security_events,
    get_or_create_session,
    update_session,
    get_session,
    get_session_topics,
    save_risk_event,
    get_session_risk_history,
    save_atlas_match,
    get_atlas_matches,
    save_alert,
    get_alerts,
    record_override,
    get_overrides,
    reset_session_state,
    get_session_trajectory,
    save_consensus_event,
    get_pending_consensus_alert,
    mark_consensus_enforced,
)
from session.anchor import compute_intent_anchor

# Playbooks (Section 20)
from intelligence.playbooks import (
    sanitize_context_prompt,
    execute_session_reset,
    execute_access_revocation
)
from intelligence.attribution import (
    generate_threat_attribution_report,
    compute_persistence_score
)

# Section 21: Fail-safe configuration
GATEWAY_FAIL_SAFE = os.getenv("GATEWAY_FAIL_SAFE", "FAIL_OPEN").upper()

# Core Agent & Detection Engine instances
worker = WorkerAgent()
auditor_agent = AuditorAgent()
topic_engine = TopicEngine(topic_similarity_threshold=0.45)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup & shutdown lifecycle management."""
    init_db()
    await auditor.start()
    logging.info(f"Sentinel ATLAS Gateway initialized (Fail-Safe: {GATEWAY_FAIL_SAFE})")
    yield


app = FastAPI(
    title="Sentinel ATLAS - Stateful AI Security Gateway",
    description="Stateful reverse proxy detecting multi-turn conversational attacks against AI agents.",
    version="2.0.0",
    lifespan=lifespan
)


# ============================================================================
# Request / Response Schemas
# ============================================================================

class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str


class OverrideRequest(BaseModel):
    analyst_id: Optional[str] = "SOC_ANALYST"
    reason: Optional[str] = "Manual analyst false-positive override"


# ============================================================================
# Section 23: Gateway REST Endpoints
# ============================================================================

@app.post("/chat")
async def chat_endpoint(request: ChatRequest, background_tasks: BackgroundTasks):
    """
    Main stateful reverse proxy chat endpoint.
    Maintains session state, local topic anchors, detects legitimate topic changes,
    evaluates 7-factor composite risk, and executes response playbooks.
    """
    session_id = request.session_id if request.session_id else str(uuid.uuid4())
    session_obj = get_or_create_session(session_id)

    # 1. Check if Session is already REVOKED
    if session_obj.get("status") == "REVOKED":
        revoke_msg = "ACCESS_REVOKED: This session has been terminated by Sentinel ATLAS security policy. Contact a SOC analyst for override."
        return {
            "session_id": session_id,
            "turn": 0,
            "turn_number": 0,
            "status": "blocked",
            "gate": "revocation_policy",
            "response": revoke_msg,
            "llm_response": revoke_msg,
            "risk_score": 100,
            "decision": "REVOKE",
            "playbook_action": "revoke",
            "topic_changed": False,
            "drift_score": 1.0,
            "atlas_matches": [],
            "auditor": {
                "verdict": "MISALIGNED",
                "confidence": 1.0,
                "reason": "Session is in REVOKED state."
            },
            "risk_breakdown": {"reason": "Session Revoked"}
        }

    try:
        # 2. Retrieve history and active state
        history = get_session_history(session_id)
        turn_number = len(history) + 1
        
        # 3. Vector embedding for current prompt
        message_embedding = get_embedding(request.message)

        # 4. Compute Session Intent Anchor (Turn 1 or Turn 1+2 blend per Section 9)
        if not history:
            intent_anchor = compute_intent_anchor(
                [{"message_text": request.message, "embedding": message_embedding}],
                min_tokens=10
            )
            anchor_text = request.message
            if intent_anchor:
                update_session(session_id, intent_anchor=intent_anchor)
        else:
            intent_anchor = session_obj.get("intent_anchor")
            if not intent_anchor:
                intent_anchor = compute_intent_anchor(history, min_tokens=10)
                if intent_anchor:
                    update_session(session_id, intent_anchor=intent_anchor)
            anchor_text = history[0]["message_text"]

        # 5. MITRE ATLAS Vector Mapping (Section 14)
        classification = classify_threat(request.message, distance_threshold=0.40)
        atlas_matches = []
        if classification.get("matched"):
            technique_entry = {
                "technique_id": classification["technique_id"],
                "technique_name": classification["technique_name"],
                "confidence": classification["confidence"],
                "severity": classification.get("severity", 0.5)
            }
            atlas_matches.append(technique_entry)
            save_atlas_match(
                session_id=session_id,
                turn_number=turn_number,
                technique_id=classification["technique_id"],
                technique_name=classification["technique_name"],
                confidence=classification["confidence"]
            )

        # 6. Prompt Sensitivity Classification (Section 18)
        prompt_sensitivity = calculate_prompt_sensitivity(request.message, message_embedding)

        # Fast Pre-Flight Regex / Keyword check boost
        rule_check = evaluate_security_rules(request.message)
        if rule_check["flagged"]:
            prompt_sensitivity = max(prompt_sensitivity, 0.90)

        # Check for educational / defensive query framing (Section 24 Test 5)
        import re
        defensive_patterns = [
            r"(?i)\b(defend(ing)?|protect(ing)?|prevent(ing)?|mitigat(e|ing|ion)|remediat(e|ion)|safeguard|best\s+practices)\s+(against|from|for|in)\b",
            r"(?i)\bhow\s+(do|can)\s+.{0,30}\s+(defend|protect|prevent|mitigate|secure)\b",
            r"(?i)\bhow\s+to\s+(defend|protect|prevent|mitigate|secure)\b"
        ]
        is_defensive = any(re.search(p, request.message) for p in defensive_patterns)
        if is_defensive:
            prompt_sensitivity = min(prompt_sensitivity, 0.10)

        # 7. Topic Engine & Legitimate Topic Change Detection (Sections 10 & 11)
        topic_result = topic_engine.process_turn(
            session_id=session_id,
            turn_number=turn_number,
            prompt_text=request.message,
            embedding=message_embedding,
            session_anchor=intent_anchor,
            atlas_matches=[] if is_defensive else atlas_matches,
            prompt_sensitivity=prompt_sensitivity
        )
        active_topic_id = topic_result["topic_id"]
        active_topic_anchor = topic_result["topic_anchor"]
        topic_changed = topic_result["topic_changed"]
        benign_topic_confidence = 0.95 if is_defensive else topic_result["benign_topic_confidence"]

        # 8. Semantic Drift Calculation (Section 12)
        drift_result = calculate_semantic_drift(
            current_emb=message_embedding,
            session_anchor=intent_anchor,
            topic_anchor=active_topic_anchor,
            recent_history=history,
            window_size=4
        )
        semantic_drift = drift_result["rolling_drift"]
        session_sim = drift_result["session_similarity"]

        # 9. Threat Persistence (Section 13)
        persistence_eval = calculate_threat_persistence(
            history=history,
            current_turn_flagged=((not is_defensive) and (classification.get("matched", False) or prompt_sensitivity > 0.65))
        )
        threat_persistence = persistence_eval["persistence_factor"]

        # 10. Worker Agent - Draft Response / Proposed Action (Section 15)
        worker_out = await worker.generate_response(
            prompt=request.message,
            conversation_history=history
        )
        proposed_text = worker_out.get("text", "")

        # 11. Auditor Agent - Alignment Verification (Section 16 & 17)
        auditor_eval = await auditor_agent.evaluate(
            session_id=session_id,
            turn_number=turn_number,
            session_intent=anchor_text,
            current_topic=topic_result["topic_name"],
            user_request=request.message,
            worker_response=proposed_text
        )
        auditor_verdict = auditor_eval.get("verdict", "ALIGNED")
        auditor_confidence = auditor_eval.get("confidence", 0.90)

        alignment_eval = calculate_intent_action_alignment(
            session_intent_vec=intent_anchor,
            proposed_response=proposed_text,
            auditor_verdict=auditor_verdict,
            auditor_confidence=auditor_confidence
        )
        action_misalignment = alignment_eval["misalignment_penalty"]

        # 12. Final 7-Factor Transparent Risk Calculation (Section 19)
        previous_events = get_security_events(session_id)
        effective_atlas_conf = 0.0 if is_defensive else (classification["confidence"] if classification.get("matched") else 0.0)
        effective_severity = 0.0 if is_defensive else (classification.get("severity", 0.0) if classification.get("matched") else 0.0)

        risk_eval = calculate_transparent_risk(
            atlas_confidence=effective_atlas_conf,
            technique_severity=effective_severity,
            semantic_drift=semantic_drift,
            prompt_sensitivity=prompt_sensitivity,
            threat_persistence=threat_persistence,
            action_misalignment=action_misalignment,
            previous_flags=len(previous_events),
            benign_topic_confidence=benign_topic_confidence
        )

        risk_score = risk_eval["risk_score"]
        decision = risk_eval["action"]

        # 13. Response Policy Execution (Section 20)
        final_response_text = proposed_text
        is_sanitized = False

        if decision == "REVOKE":
            execute_access_revocation(session_id)
            save_blocked_turn(
                session_id=session_id,
                turn_number=turn_number,
                message_text=request.message,
                similarity_score=session_sim,
                threshold=0.35,
                reason=f"Risk Score {risk_score}/100: Access Revocation triggered."
            )
            save_risk_event(session_id, turn_number, risk_score, risk_eval["breakdown"], decision)
            return {
                "session_id": session_id,
                "turn": turn_number,
                "turn_number": turn_number,
                "status": "blocked",
                "gate": "risk_engine",
                "response": "ACCESS_REVOKED: This session has been terminated due to high cumulative adversarial risk.",
                "llm_response": "ACCESS_REVOKED: This session has been terminated due to high cumulative adversarial risk.",
                "risk_score": risk_score,
                "decision": "REVOKE",
                "playbook_action": "revoke",
                "topic_changed": topic_changed,
                "drift_score": round(semantic_drift, 4),
                "atlas_matches": atlas_matches,
                "auditor": auditor_eval,
                "risk_breakdown": risk_eval["breakdown"]
            }

        elif decision == "RESET":
            execute_session_reset(session_id)
            save_blocked_turn(
                session_id=session_id,
                turn_number=turn_number,
                message_text=request.message,
                similarity_score=session_sim,
                threshold=0.35,
                reason=f"Risk Score {risk_score}/100: Session Reset triggered."
            )
            save_risk_event(session_id, turn_number, risk_score, risk_eval["breakdown"], decision)
            return {
                "session_id": session_id,
                "turn": turn_number,
                "turn_number": turn_number,
                "status": "blocked",
                "gate": "risk_engine",
                "response": "SESSION_RESET: The conversational context and intent anchors have been wiped due to elevated threat trajectory.",
                "llm_response": "SESSION_RESET: The conversational context and intent anchors have been wiped due to elevated threat trajectory.",
                "risk_score": risk_score,
                "decision": "RESET",
                "playbook_action": "reset",
                "topic_changed": topic_changed,
                "drift_score": round(semantic_drift, 4),
                "atlas_matches": atlas_matches,
                "auditor": auditor_eval,
                "risk_breakdown": risk_eval["breakdown"]
            }

        elif decision == "SANITIZE":
            is_sanitized = True
            sanitized_prompt = sanitize_context_prompt(request.message, anchor_text, session_id)
            sanitized_worker_out = await worker.generate_response(
                prompt=sanitized_prompt,
                conversation_history=history
            )
            final_response_text = sanitized_worker_out.get("text", proposed_text)

        # 14. Save turn & risk telemetry
        save_turn(
            session_id=session_id,
            turn_number=turn_number,
            message_text=request.message,
            embedding=message_embedding,
            similarity_score=session_sim,
            llm_response=final_response_text,
            drift_score=semantic_drift,
            risk_score=float(risk_score),
            attack_technique=classification["technique_name"] if classification.get("matched") else None,
            attack_confidence=classification["confidence"] if classification.get("matched") else None
        )
        save_risk_event(session_id, turn_number, risk_score, risk_eval["breakdown"], decision)
        update_session(session_id, session_risk=float(risk_score), current_topic_id=active_topic_id)

        return {
            "session_id": session_id,
            "turn": turn_number,
            "turn_number": turn_number,
            "status": "success",
            "gate": "passed",
            "response": final_response_text,
            "llm_response": final_response_text,
            "risk_score": risk_score,
            "decision": decision,
            "playbook_action": decision.lower(),
            "sanitized": is_sanitized,
            "topic_changed": topic_changed,
            "drift_score": round(semantic_drift, 4),
            "similarity_score": round(session_sim, 4),
            "atlas_matches": atlas_matches,
            "auditor": auditor_eval,
            "risk_breakdown": risk_eval["breakdown"]
        }

    except Exception as exc:
        logging.error(f"Gateway Pipeline Exception: {exc}", exc_info=True)
        if GATEWAY_FAIL_SAFE == "FAIL_OPEN":
            log_security_event("SECURITY_GATEWAY_UNAVAILABLE", session_id, {
                "error": str(exc),
                "mode": "FAIL_OPEN"
            })
            # Forward directly to worker agent in fail-open mode
            fallback_res = await worker.generate_response(request.message)
            return {
                "session_id": session_id,
                "turn": 1,
                "response": fallback_res.get("text", "Service operating in FAIL_OPEN mode."),
                "llm_response": fallback_res.get("text", "Service operating in FAIL_OPEN mode."),
                "risk_score": 0,
                "decision": "ALLOW",
                "topic_changed": False,
                "drift_score": 0.0,
                "atlas_matches": [],
                "auditor": {"verdict": "UNVERIFIED", "reason": "SECURITY_GATEWAY_UNAVAILABLE (FAIL_OPEN)"}
            }
        else:
            log_security_event("SECURITY_GATEWAY_UNAVAILABLE", session_id, {
                "error": str(exc),
                "mode": "FAIL_CLOSED"
            })
            raise HTTPException(
                status_code=503,
                detail="SECURITY_GATEWAY_UNAVAILABLE: Gateway pipeline error in FAIL_CLOSED mode."
            )


@app.get("/sessions")
async def list_sessions():
    """Returns list of active sessions and activity metadata."""
    sessions = get_all_sessions()
    results = []
    for s in sessions:
        session_id = s[0]
        meta = get_session(session_id)
        results.append({
            "session_id": session_id,
            "valid_turns": s[1],
            "last_seen": s[2],
            "status": meta.get("status", "ACTIVE") if meta else "ACTIVE",
            "session_risk": meta.get("session_risk", 0.0) if meta else 0.0
        })
    return results


@app.get("/sessions/{session_id}")
async def get_session_details(session_id: str):
    """Retrieves session metadata, status, topics, and risk state."""
    meta = get_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found.")
    topics = get_session_topics(session_id)
    return {
        "metadata": meta,
        "topics": topics
    }


@app.get("/sessions/{session_id}/messages")
async def get_session_messages(session_id: str):
    """Returns full message history for a session."""
    history = get_session_history(session_id)
    return {
        "session_id": session_id,
        "count": len(history),
        "messages": history
    }


@app.get("/sessions/{session_id}/risk")
async def get_session_risk(session_id: str):
    """Returns granular risk progression and score breakdowns across turns."""
    risk_events = get_session_risk_history(session_id)
    meta = get_session(session_id)
    return {
        "session_id": session_id,
        "current_status": meta.get("status", "ACTIVE") if meta else "ACTIVE",
        "current_risk": meta.get("session_risk", 0.0) if meta else 0.0,
        "events": risk_events
    }


@app.get("/sessions/{session_id}/trajectory")
async def get_trajectory_endpoint(session_id: str):
    """Returns step-by-step threat and drift trajectory."""
    trajectory = get_session_trajectory(session_id)
    persistence = compute_persistence_score(session_id)
    return {
        "session_id": session_id,
        "trajectory": trajectory,
        "persistence": persistence
    }


@app.get("/alerts")
async def list_alerts(session_id: Optional[str] = None):
    """Returns operational security alerts."""
    return get_alerts(session_id)


@app.post("/sessions/{session_id}/override")
async def override_session_endpoint(session_id: str, request: OverrideRequest):
    """
    Human analyst override: manually unblocks a session, restores status to ACTIVE,
    and records an immutable audit log entry in the overrides table.
    """
    record = record_override(
        session_id=session_id,
        analyst_id=request.analyst_id or "SOC_ANALYST",
        reason=request.reason or "Analyst manual false-positive override"
    )
    log_security_event("analyst_override", session_id, record)
    return {
        "status": "success",
        "message": f"Session {session_id} unblocked by {record['analyst_id']}",
        "override": record
    }


@app.post("/sessions/{session_id}/reset")
async def reset_session_endpoint(session_id: str):
    """Explicitly triggers a session memory and topic state reset."""
    result = execute_session_reset(session_id)
    return result


@app.get("/health")
async def health_check():
    """Health check for Gateway, DB, and Fail-Safe mode."""
    return {
        "status": "ok",
        "gateway": "online",
        "database": "sqlite_connected",
        "fail_safe_mode": GATEWAY_FAIL_SAFE,
        "risk_tiers": {
            "0-25": "ALLOW",
            "26-45": "SANITIZE",
            "46-70": "RESET",
            "71-100": "REVOKE"
        }
    }


@app.get("/attribution/report/{session_id}")
async def get_attribution_report(session_id: str):
    """Generates an executive plain-English Threat Attribution Report using local LLM."""
    report = await generate_threat_attribution_report(session_id)
    persistence = compute_persistence_score(session_id)
    return {
        "session_id": session_id,
        "report": report,
        "persistence": persistence
    }


@app.get("/attribution/persistence/{session_id}")
async def get_session_persistence(session_id: str):
    """Returns persistence score and sustained intent metrics."""
    return compute_persistence_score(session_id)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=True)