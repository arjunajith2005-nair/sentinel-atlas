"""
ATLAS Bridge (Dual-Agent Consensus Engine)
Implements Page 6, Bullet 2 of the research paper:
- Worker Agent generates response / proposed action.
- Auditor Agent (asynchronous Ollama LLM) audits intent-action alignment in background.
- Intent-Action Alignment (IAA) score measured by cosine similarity between Intent Anchor and Response vector.
- Triggers consensus alert if IAA falls below threshold or Auditor flags MISALIGNED.
- Next-turn enforcement intervenes if prior turn failed consensus check.
"""

import httpx
import numpy as np
import logging
import re
from typing import Dict, Optional, List, Tuple
from embeddings.encoder import get_embedding
from embeddings.drift import calculate_cosine_similarity
from embeddings.auditor import calculate_iaa_score
from session.db import save_consensus_event, get_pending_consensus_alert, mark_consensus_enforced
from gateway.logger import log_security_event

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
AUDITOR_MODEL = "smollm:135m"
IAA_THRESHOLD = 0.35  # Cosine similarity threshold between Intent Anchor and Response

# Intent-Action Alignment is defined once, in embeddings/auditor.py, and re-exported
# here so both the Auditor Agent and this Bridge score alignment identically.
#
# Do not confuse this with Inter-Rater Agreement in gateway/agreement.py: that one
# is Cohen's Kappa between the drift detector and the ATLAS classifier across the
# whole corpus. This one is per-turn cosine between anchor and response.
compute_cosine_similarity = calculate_cosine_similarity

# The Auditor is asked to reply with a single line: "ALIGNED: <reason>" or
# "MISALIGNED: <reason>". The verdict is only accepted as the LEADING token of
# the reply, after optional markdown/quoting/"Verdict:" noise.
_VERDICT_PREFIX = re.compile(r"^\s*(?:\**\s*verdict\s*\**\s*[:\-]?\s*)?", re.IGNORECASE)
_VERDICT_TOKEN = re.compile(
    r"^[\s\"'`*_>#\[\(]*(?P<verdict>MIS[\s_-]*ALIGNED|ALIGNED)\b[\s\"'`*_\]\)]*[:\-–]?\s*(?P<reason>.*)",
    re.IGNORECASE | re.DOTALL,
)


def parse_auditor_verdict(raw_response: str) -> Tuple[str, str]:
    """
    Parses the Auditor Agent's reply into (verdict, reason).

    verdict is one of "ALIGNED", "MISALIGNED", or "UNPARSEABLE".

    This deliberately does NOT substring-search the reply. The previous
    implementation flagged MISALIGNED whenever the text contained "MISALIGNED",
    "JAILBREAK" or "ATTACK" anywhere — unworkable for a security assistant,
    where those words appear routinely in correct answers, and where a small
    auditor model often ignores the format and emits prose or code instead of a
    verdict. Both produced false MISALIGNED verdicts that blocked the user's
    NEXT turn, making the block look unrelated to its cause.

    An unreadable reply returns "UNPARSEABLE" rather than a verdict. The caller
    decides what to do with that; it is not by itself evidence of misalignment.
    """
    if not raw_response or not raw_response.strip():
        return "UNPARSEABLE", "Auditor returned an empty response."

    # Consider only the first non-empty line — the prompt asks for exactly one.
    first_line = ""
    for line in raw_response.strip().splitlines():
        if line.strip():
            first_line = line.strip()
            break

    candidate = _VERDICT_PREFIX.sub("", first_line, count=1)
    match = _VERDICT_TOKEN.match(candidate)
    if not match:
        snippet = " ".join(raw_response.split())[:120]
        return "UNPARSEABLE", f"Auditor reply did not begin with a verdict: {snippet}"

    token = re.sub(r"[\s_-]+", "", match.group("verdict")).upper()
    verdict = "MISALIGNED" if token == "MISALIGNED" else "ALIGNED"
    reason = match.group("reason").strip()[:150]

    if not reason:
        reason = (
            "Mismatch between intent and action detected."
            if verdict == "MISALIGNED"
            else "Action evaluated as safe and aligned with expected intent."
        )
    return verdict, reason


async def audit_consensus_async(
    session_id: str,
    turn_number: int,
    user_prompt: str,
    proposed_response: str,
    intent_anchor_vec: List[float],
    timeout: float = 20.0
) -> Dict:
    """
    Asynchronous Auditor Agent evaluation (runs in background without blocking the Worker).
    Inspects user intent and proposed action to issue ALIGNED or MISALIGNED verdict.
    """
    iaa_score = calculate_iaa_score(intent_anchor_vec, proposed_response)
    
    auditor_prompt = (
        "You are the Sentinel ATLAS Auditor Agent. Your task is to verify if the AI Worker's response "
        "is consistent with a safe, benign conversation or if it aids an adversarial attack, jailbreak, "
        "or unauthorized system manipulation.\n\n"
        f"User Prompt: {user_prompt.strip()}\n"
        f"AI Worker Response: {proposed_response[:400].strip()}\n\n"
        "Reply with EXACTLY one line:\n"
        "ALIGNED: <brief reason>\n"
        "MISALIGNED: <brief reason>\n\n"
        "Verdict:"
    )

    payload = {
        "model": AUDITOR_MODEL,
        "prompt": auditor_prompt,
        "stream": False,
        "keep_alive": "30m",
        "options": {
            "temperature": 0.0,
            "num_predict": 40
        }
    }

    auditor_verdict = "ALIGNED"
    auditor_reason = "Action evaluated as safe and aligned with expected intent."

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(OLLAMA_URL, json=payload)
            if resp.status_code == 200:
                raw = resp.json().get("response", "")
                auditor_verdict, auditor_reason = parse_auditor_verdict(raw)
            else:
                auditor_verdict = "UNPARSEABLE"
                auditor_reason = f"Auditor HTTP {resp.status_code}"
    except Exception as e:
        auditor_verdict = "UNPARSEABLE"
        auditor_reason = f"Auditor failover: {e}"

    # Flag a consensus alert only on an explicit MISALIGNED verdict.
    #
    # When no usable second opinion came back (unparseable reply, HTTP error, or
    # Ollama offline), fall back to the mathematical signal alone and only at a
    # critically low alignment — an auditor that failed to answer is not evidence
    # of an attack, and this verdict blocks the user's next turn.
    has_substantive_prompt = len(user_prompt.strip().split()) >= 6
    if auditor_verdict == "MISALIGNED":
        is_mismatch = True
    elif auditor_verdict == "UNPARSEABLE":
        is_mismatch = (
            bool(intent_anchor_vec)
            and has_substantive_prompt
            and iaa_score < 0.15
        )
    else:
        is_mismatch = False

    save_consensus_event(
        session_id=session_id,
        turn_number=turn_number,
        iaa_score=iaa_score,
        auditor_verdict="MISALIGNED" if is_mismatch else "ALIGNED",
        auditor_reason=auditor_reason
    )

    if is_mismatch:
        log_security_event("consensus_alert", session_id, {
            "turn_number": turn_number,
            "iaa_score": iaa_score,
            "iaa_threshold": IAA_THRESHOLD,
            "auditor_verdict": "MISALIGNED",
            "auditor_reason": auditor_reason,
            "action": "flagged_for_next_turn_enforcement"
        })

    return {
        "iaa_score": iaa_score,
        "auditor_verdict": "MISALIGNED" if is_mismatch else "ALIGNED",
        "auditor_reason": auditor_reason,
        "enforcement_flag": is_mismatch
    }


def check_next_turn_enforcement(session_id: str) -> Optional[Dict]:
    """
    Checks if the session was flagged by the Auditor on the prior turn.
    Returns the pending alert if enforcement is needed, else None.
    """
    alert = get_pending_consensus_alert(session_id)
    if alert:
        mark_consensus_enforced(session_id)
        return alert
    return None
