import sys
sys.dont_write_bytecode = True

import asyncio
from contextlib import asynccontextmanager
import uuid
from typing import Optional
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

from gateway.proxy import forward_to_llm
from gateway.logger import log_security_event
from gateway.async_auditor import auditor
from embeddings.encoder import get_embedding
from embeddings.drift import check_intent_drift
from embeddings.rules import evaluate_security_rules
from embeddings.safety import check_content_safety
from session.db import init_db, save_turn, save_blocked_turn, get_session_history, get_security_events
from session.anchor import compute_intent_anchor
from intelligence.risk import calculate_composite_risk, BLOCKING_ACTIONS
from intelligence.classifier import classify_threat
from gateway.agreement import compute_agreement
from intelligence.bridge import audit_consensus_async, check_next_turn_enforcement
from intelligence.playbooks import sanitize_context_prompt, execute_session_reset, execute_access_revocation
from intelligence.attribution import generate_threat_attribution_report, compute_persistence_score
from embeddings.auditor import calculate_iaa_score, dispatch_async_audit

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB and start Async Auditor queue worker
    init_db()
    await auditor.start()
    yield

app = FastAPI(title="Sentinel ATLAS - Security Gateway", lifespan=lifespan)

# Autonomous response tiers (<= 0.25 allow, 0.26-0.45 sanitize, 0.46-0.70 reset,
# > 0.70 revoke) are defined once in intelligence/risk.py::RISK_TIERS. This module
# dispatches on the action that engine recommends — do not re-derive bands here.

class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str

@app.get("/health")
async def health_check():
    """Ultra-fast non-blocking health check for dashboard telemetry."""
    return {"status": "online", "service": "Sentinel ATLAS Gateway"}

@app.post("/chat")
async def chat_endpoint(request: ChatRequest, background_tasks: BackgroundTasks):
    session_id = request.session_id if request.session_id else str(uuid.uuid4())
    
    # 0. Check Next-Turn Enforcement from Dual-Agent Auditor (Page 6, Bullet 2)
    prior_audit_alert = check_next_turn_enforcement(session_id)
    if prior_audit_alert:
        enforce_reason = f"Dual-Agent Consensus Enforcement: Prior action was flagged by Auditor Agent ({prior_audit_alert.get('auditor_reason')})"
        save_blocked_turn(
            session_id=session_id,
            turn_number=0,
            message_text=request.message,
            similarity_score=prior_audit_alert.get("iaa_score", 0.0),
            threshold=0.35,
            reason=enforce_reason
        )
        return {
            "status": "blocked",
            "reason": enforce_reason,
            "session_id": session_id,
            "gate": "auditor_consensus",
            "playbook_action": "reset"
        }

    # 1. Pre-Flight Rule Check (Fast keyword & regex gate)
    rule_check = evaluate_security_rules(request.message)
    if rule_check["flagged"]:
        event_type = "rule_engine_secret" if "secret" in rule_check["reason"].lower() else "rule_engine_injection"
        
        # Async non-blocking queue dispatch (Phase 2 - Person B)
        await auditor.log_event_async(session_id, event_type, {
            "reason": rule_check["reason"],
            "prompt": request.message,
            "detector_flag": 1
        })
        
        log_security_event(event_type, session_id, {"reason": rule_check["reason"], "prompt": request.message})
        
        save_blocked_turn(
            session_id=session_id,
            turn_number=0,
            message_text=request.message,
            similarity_score=0.0,
            threshold=0.35,
            reason=rule_check["reason"]
        )
        return {
            "status": "blocked",
            "reason": rule_check["reason"],
            "session_id": session_id,
            "gate": "rule_engine",
            "detector_flag": 1
        }

    # 2. LLM Semantic Safety Check (uses Ollama to classify intent)
    safety = check_content_safety(request.message)
    if not safety["safe"]:
        safety_reason = f"LLM Safety Classifier: {safety['reason']}"
        log_security_event("llm_safety_block", session_id, {
            "reason": safety_reason,
            "raw_classification": safety["raw"],
            "prompt": request.message
        })
        save_blocked_turn(
            session_id=session_id,
            turn_number=0,
            message_text=request.message,
            similarity_score=0.0,
            threshold=0.0,
            reason=safety_reason
        )
        return {
            "status": "blocked",
            "reason": safety_reason,
            "session_id": session_id,
            "gate": "llm_safety"
        }

    # Fetch existing session history
    history = get_session_history(session_id)
    turn_number = len(history) + 1
    
    # 3. Embedding Generation & 4-Turn Rolling Intent Drift
    message_embedding = get_embedding(request.message)
    intent_anchor = compute_intent_anchor(history, min_tokens=10)
    anchor_text = history[0]["message_text"] if history else request.message
    
    drift_result = check_intent_drift(
        anchor_vec=intent_anchor, 
        current_vec=message_embedding, 
        recent_history=history, 
        threshold=0.35,
        window_size=4
    )
    
    # 3b. Independent MITRE ATLAS classification on EVERY turn.
    # Deliberately NOT gated on drift detection. Cohen's Kappa in
    # gateway/agreement.py only means something if the two raters judge the same
    # turns independently — and a fluent injection that stays semantically close
    # to the anchor would otherwise never be classified at all. Reuses
    # message_embedding, so the added cost is one HNSW lookup, not a re-encode.
    classification = classify_threat(
        prompt=request.message,
        distance_threshold=0.45,
        query_embedding=message_embedding
    )
    detector_flag = 1 if drift_result["drift_detected"] else 0
    classifier_flag = 1 if classification["matched"] else 0

    outbound_prompt = request.message
    applied_playbook = "allow"
    risk_info = None

    # 4. Composite Risk Scoring — runs on EVERY turn.
    # Previously this whole block was nested under `if drift_result["drift_detected"]`,
    # which meant turn 1 of any session was never risk-scored at all: with no history
    # there is no intent anchor, so drift cannot fire, so no playbook could run. An
    # attacker only had to open a fresh session. Drift is one weighted input (w1) to
    # the score, not a precondition for computing it.
    previous_events = get_security_events(session_id)
    previous_flags = len(previous_events)
    
    risk = calculate_composite_risk(
        drift_score=drift_result["similarity_score"],
        prompt_text=request.message,
        turn_number=turn_number,
        previous_flags=previous_flags,
        classification=classification,
    )
    risk_info = risk
    score = risk["risk_score"]
    action = risk["recommended_action"]

    # MITRE ATLAS classification, carried into every downstream record.
    # The blocking playbooks return before save_turn (and session reset wipes
    # session_turns outright), so without this the matched technique would
    # never be persisted for the heatmaps or weight tuning to read.
    threat_telemetry = {
        "risk_score": score,
        "attack_technique": risk["attack_technique"],
        "attack_confidence": risk["attack_confidence"],
        "technique_severity": risk["technique_severity"],
        "tactic": risk["tactic"],
        "detector_flag": detector_flag,
        "classifier_flag": classifier_flag,
    }

    # 4. Autonomous Response Playbooks (Page 7, Bullet 3).
    # Dispatch on the action recommended by intelligence/risk.py - the tier
    # thresholds are defined there and must not be duplicated here.
    if action in BLOCKING_ACTIONS:
        playbook = (
            execute_access_revocation(session_id) if action == "revoke"
            else execute_session_reset(session_id)
        )
        save_blocked_turn(
            session_id=session_id,
            turn_number=turn_number,
            message_text=request.message,
            similarity_score=drift_result["similarity_score"],
            threshold=0.35,
            reason=playbook["reason"],
            playbook_action=action,
            **threat_telemetry
        )
        await auditor.log_event_async(session_id, "vector_drift", {
            "reason": playbook["reason"],
            "similarity_score": drift_result["similarity_score"],
            "rolling_avg_similarity": drift_result["rolling_avg_similarity"],
            "prompt": request.message,
            "playbook_action": action,
            **threat_telemetry
        })
        log_security_event("vector_drift", session_id, {
            "reason": playbook["reason"],
            "similarity_score": drift_result["similarity_score"],
            "rolling_avg_similarity": drift_result["rolling_avg_similarity"],
            "prompt": request.message,
            "playbook_action": action,
            **threat_telemetry
        })
        return {
            "status": "blocked",
            "reason": playbook["reason"],
            "session_id": session_id,
            "turn_number": turn_number,
            "similarity_score": drift_result["similarity_score"],
            "rolling_avg_similarity": drift_result["rolling_avg_similarity"],
            "turns_evaluated": drift_result["window_turns_evaluated"],
            "gate": "risk_engine",
            "risk_score": score,
            "risk_level": risk["risk_level"],
            "attack_technique": risk["attack_technique"],
            "playbook_action": action,
            "detector_flag": detector_flag,
            "classifier_flag": classifier_flag
        }

    # Context Sanitisation: strip adversarial framing, rebuild from core
    # noun phrases, then forward the cleaned prompt to the Worker Agent.
    elif action == "sanitize":
        applied_playbook = "sanitize"
        anchor_text = history[0]["message_text"] if history else request.message
        outbound_prompt = sanitize_context_prompt(request.message, anchor_text, session_id)
        await auditor.log_event_async(session_id, "playbook_sanitize", {
            "original_prompt": request.message,
            "sanitized_prompt": outbound_prompt,
            **threat_telemetry
        })
        log_security_event("playbook_sanitize", session_id, {
            "original_prompt": request.message,
            "sanitized_prompt": outbound_prompt,
            **threat_telemetry
        })

    # 5. Forward to Worker Agent (Zero latency penalty to user)
    llm_response = await forward_to_llm(outbound_prompt)

    # 4. Intent Alignment Assessment (IAA) & Async Secondary Auditor (Person B)
    anchor_text = history[0]["message_text"] if history else request.message
    iaa_score = calculate_iaa_score(intent_anchor, llm_response)

    # Non-blocking background audit via secondary Ollama model
    dispatch_async_audit(
        session_id=session_id,
        turn_number=turn_number,
        anchor_text=anchor_text,
        user_prompt=request.message,
        llm_response=llm_response,
        iaa_score=iaa_score
    )

    save_turn(
        session_id=session_id,
        turn_number=turn_number,
        message_text=request.message,
        embedding=message_embedding,
        similarity_score=drift_result["similarity_score"],
        llm_response=llm_response,
        drift_score=drift_result["similarity_score"],
        risk_score=risk_info["risk_score"] if risk_info else None,
        attack_technique=risk_info.get("attack_technique") if risk_info else classification["attack_technique"],
        attack_confidence=risk_info.get("attack_confidence") if risk_info else classification["attack_confidence"],
        detector_flag=detector_flag,
        classifier_flag=classifier_flag,
        playbook_action=applied_playbook
    )

    # 6. ATLAS Bridge: Asynchronous Auditor Agent Consensus Check in Background
    # (Runs in background without delaying user response, ready for next turn)
    if intent_anchor:
        background_tasks.add_task(
            audit_consensus_async,
            session_id=session_id,
            turn_number=turn_number,
            user_prompt=request.message,
            proposed_response=llm_response,
            intent_anchor_vec=intent_anchor
        )
    
    return {
        "status": "success",
        "session_id": session_id,
        "turn_number": turn_number,
        "similarity_score": drift_result["similarity_score"],
        "rolling_avg_similarity": drift_result["rolling_avg_similarity"],
        "iaa_score": iaa_score,
        "gate": "passed",
        "playbook_action": applied_playbook,
        "sanitized": (applied_playbook == "sanitize"),
        "detector_flag": detector_flag,
        "classifier_flag": classifier_flag,
        "attack_technique": classification["attack_technique"],
        "llm_response": llm_response
    }


@app.get("/metrics/agreement")
async def get_agreement_metrics(session_id: Optional[str] = None):
    """
    Inter-rater agreement (Cohen's Kappa) between Person B's drift detector and
    Person C's MITRE ATLAS classifier. Omit session_id for the whole corpus.
    Feeds Phase 5 weight tuning.
    """
    return compute_agreement(session_id)


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
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)