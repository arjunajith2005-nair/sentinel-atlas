import asyncio
import json
import logging
import httpx
from datetime import datetime
from typing import Optional

from embeddings.encoder import get_embedding
from embeddings.drift import calculate_cosine_similarity
from gateway.logger import log_security_event

# Ensure async audit logger is configured
logging.basicConfig(
    filename="async_sentinel_audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

OLLAMA_GENERATE_URL = "http://127.0.0.1:11434/api/generate"
AUDITOR_MODEL = "smollm:135m"


def calculate_iaa_score(anchor_vec: list[float], response_text: str) -> float:
    """
    IAA Score (Intent Alignment Assessment):
    A mathematical alignment check using embeddings to measure how closely
    a generated response matches the initial session anchor vector.
    """
    if not anchor_vec or not response_text:
        return 1.0

    response_embedding = get_embedding(response_text)
    score = calculate_cosine_similarity(anchor_vec, response_embedding)
    return round(float(score), 4)


class AsyncAuditor:
    """
    Secondary AI check running in the background via Ollama that evaluates
    whether a prompt and response adhere to the session anchor without blocking the user.
    """
    def __init__(self, ollama_url: str = OLLAMA_GENERATE_URL, model: str = AUDITOR_MODEL):
        self.ollama_url = ollama_url
        self.model = model

    async def audit_turn(
        self,
        session_id: str,
        turn_number: int,
        anchor_text: str,
        user_prompt: str,
        llm_response: str,
        iaa_score: Optional[float] = None
    ) -> dict:
        """
        Executes a background secondary model evaluation against the session anchor.
        Captures verdict, adherence reasoning, and logs to the security audit trail.
        """
        audit_prompt = (
            f"You are an independent AI security auditor for Sentinel ATLAS.\n"
            f"Initial session anchor/goal: \"{anchor_text}\"\n"
            f"Current user prompt (Turn {turn_number}): \"{user_prompt}\"\n"
            f"Assistant's proposed response: \"{llm_response}\"\n\n"
            f"Determine if the assistant's response adheres to the original session goal and safety boundaries.\n"
            f"Respond ONLY in valid JSON format:\n"
            f'{{"verdict": "COMPLIANT" or "DRIFTED", "confidence": <float 0.0-1.0>, "reason": "<brief explanation>"}}'
        )

        payload = {
            "model": self.model,
            "prompt": audit_prompt,
            "stream": False,
            "format": "json",
            "keep_alive": "30m",
            "options": {
                "num_predict": 35,
                "temperature": 0.0
            }
        }

        audit_result = {
            "session_id": session_id,
            "turn_number": turn_number,
            "timestamp": datetime.utcnow().isoformat(),
            "iaa_score": iaa_score,
            "verdict": "UNVERIFIED",
            "confidence": 0.0,
            "reason": "",
            "status": "pending"
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(self.ollama_url, json=payload)
                if resp.status_code == 200:
                    raw_text = resp.json().get("response", "{}")
                    parsed = json.loads(raw_text)
                    audit_result["verdict"] = parsed.get("verdict", "COMPLIANT").upper()
                    audit_result["confidence"] = float(parsed.get("confidence", 0.9))
                    audit_result["reason"] = parsed.get("reason", "Adheres to session anchor.")
                    audit_result["status"] = "completed"
                else:
                    audit_result["status"] = f"error_http_{resp.status_code}"
                    audit_result["reason"] = f"Auditor HTTP Error {resp.status_code}"
        except Exception as ex:
            audit_result["status"] = "failover"
            audit_result["reason"] = f"Auditor failover: Ollama offline or timed out ({type(ex).__name__})"

        # Structured log record
        logging.info(json.dumps({
            "event": "async_secondary_audit",
            **audit_result
        }))

        # If secondary model flagged drift, register security incident
        if audit_result["verdict"] == "DRIFTED":
            log_security_event("async_auditor_drift", session_id, {
                "turn_number": turn_number,
                "reason": audit_result["reason"],
                "confidence": audit_result["confidence"],
                "iaa_score": iaa_score
            })

        return audit_result


# Singleton instance
auditor = AsyncAuditor()


def dispatch_async_audit(
    session_id: str,
    turn_number: int,
    anchor_text: str,
    user_prompt: str,
    llm_response: str,
    iaa_score: Optional[float] = None
) -> asyncio.Task:
    """
    Non-blocking helper to launch Async Auditor in the background event loop.
    Guarantees user response is returned immediately.
    """
    return asyncio.create_task(
        auditor.audit_turn(
            session_id=session_id,
            turn_number=turn_number,
            anchor_text=anchor_text,
            user_prompt=user_prompt,
            llm_response=llm_response,
            iaa_score=iaa_score
        )
    )
