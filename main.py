import sys
sys.dont_write_bytecode = True

from fastapi import FastAPI
from pydantic import BaseModel
import uuid
from typing import Optional

from gateway.proxy import forward_to_llm
from embeddings.encoder import get_embedding
from embeddings.drift import check_intent_drift
<<<<<<< HEAD
from embeddings.rules import evaluate_security_rules
from session.db import init_db, save_turn, get_session_history
=======
from session.db import init_db, save_turn, save_blocked_turn, get_session_history
>>>>>>> arjun-manoj
from session.anchor import compute_intent_anchor

app = FastAPI(title="Sentinel ATLAS - Security Gateway")
init_db()

class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    session_id = request.session_id if request.session_id else str(uuid.uuid4())
    
    # 1. Pre-Flight Rule Check (Prompt Injection & Secret Leak Prevention)
    rule_check = evaluate_security_rules(request.message)
    if rule_check["flagged"]:
        return {
            "status": "blocked",
            "reason": rule_check["reason"],
            "session_id": session_id,
            "gate": "rule_engine"
        }

    history = get_session_history(session_id)
    turn_number = len(history) + 1
    
    # 2. Embedding Generation & Intent Drift Evaluation
    message_embedding = get_embedding(request.message)
    intent_anchor = compute_intent_anchor(history)
    
    drift_result = check_intent_drift(intent_anchor, message_embedding, threshold=0.35)
    if drift_result["drift_detected"]:
        save_blocked_turn(
            session_id=session_id,
            turn_number=turn_number,
            message_text=request.message,
            similarity_score=drift_result["similarity_score"],
            threshold=0.35,
            reason="Intent drift detected. Prompt strays too far from established intent anchor."
        )
        return {
            "status": "blocked",
            "reason": "Intent drift detected. Prompt strays from session intent anchor.",
            "session_id": session_id,
            "turn_number": turn_number,
            "similarity_score": drift_result["similarity_score"],
            "gate": "vector_drift"
        }
    

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
        "gate": "passed",
        "llm_response": llm_response
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)