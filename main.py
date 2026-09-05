import sys
sys.dont_write_bytecode = True

from fastapi import FastAPI
from pydantic import BaseModel
import uuid
from typing import Optional

from gateway.proxy import forward_to_llm
from gateway.logger import log_security_event
from embeddings.encoder import get_embedding
from embeddings.drift import check_intent_drift
from embeddings.rules import evaluate_security_rules
from session.db import init_db, save_turn, save_blocked_turn, get_session_history
from session.anchor import compute_intent_anchor
app = FastAPI(title="Sentinel ATLAS - Security Gateway")
init_db()

class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    session_id = request.session_id if request.session_id else str(uuid.uuid4())
    
    # 1. Pre-Flight Rule Check (Person B / Pre-flight Gate)
    rule_check = evaluate_security_rules(request.message)
    if rule_check["flagged"]:
        event_type = "rule_engine_secret" if "secret" in rule_check["reason"].lower() else "rule_engine_injection"
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
            "gate": "rule_engine"
        }

    # Fetch existing session history from Person A's db module
    history = get_session_history(session_id)
    turn_number = len(history) + 1
    
    # 2. Embedding Generation & 4-Turn Rolling Intent Drift (Arjun Nair - Person B)
    message_embedding = get_embedding(request.message)
    intent_anchor = compute_intent_anchor(history)
    
    drift_result = check_intent_drift(
        anchor_vec=intent_anchor, 
        current_vec=message_embedding, 
        recent_history=history, 
        threshold=0.35,
        window_size=4
    )
    
    if drift_result["drift_detected"]:
        save_blocked_turn(
            session_id=session_id,
            turn_number=turn_number,
            message_text=request.message,
            similarity_score=drift_result["similarity_score"],
            threshold=0.35,
            reason="Intent drift detected. Prompt strays from session intent anchor baseline."
        )
        log_security_event("vector_drift", session_id, {
            "reason": "4-Turn rolling average or instant similarity below threshold",
            "similarity_score": drift_result["similarity_score"],
            "rolling_avg_similarity": drift_result["rolling_avg_similarity"],
            "prompt": request.message
        })
        
        return {
            "status": "blocked",
            "reason": "Intent drift detected. Prompt strays from session intent anchor baseline.",
            "session_id": session_id,
            "turn_number": turn_number,
            "similarity_score": drift_result["similarity_score"],
            "rolling_avg_similarity": drift_result["rolling_avg_similarity"],
            "turns_evaluated": drift_result["window_turns_evaluated"],
            "gate": "vector_drift"
        }
    
    # 3. Save Turn and Forward Downstream
    llm_response = await forward_to_llm(request.message)
    save_turn(
        session_id=session_id,
        turn_number=turn_number,
        message_text=request.message,
        embedding=message_embedding,
        similarity_score=drift_result["similarity_score"],
        llm_response=llm_response
    )
    
    return {
        "status": "success",
        "session_id": session_id,
        "turn_number": turn_number,
        "similarity_score": drift_result["similarity_score"],
        "rolling_avg_similarity": drift_result["rolling_avg_similarity"],
        "gate": "passed",
        "llm_response": llm_response
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)