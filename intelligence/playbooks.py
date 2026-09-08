"""
Autonomous Response Playbooks
Implements Page 7, Bullet 3 of the research paper:
- Risk Score <= 25: Allow (no intervention)
- Risk Score 26 - 45: Context Sanitisation (strips adversarial framing, rebuilds prompt from core entities/noun phrases)
- Risk Score 46 - 70: Session Reset (wipes agent's conversational memory and intent anchor)
- Risk Score > 70: Access Revocation (immediate termination of session)
"""

import re
import sqlite3
from typing import Dict, List, Optional
from gateway.logger import log_security_event

DB_PATH = "sentinel_sessions.db"

def extract_key_terms(text: str) -> List[str]:
    """
    Extracts primary noun phrases, entities, and keywords from text,
    stripping punctuation, adversarial preambles, and conversational filler.
    """
    if not text:
        return []
    # Strip common jailbreak/adversarial framing preambles
    cleaned = re.sub(r"(?i)^(in an alternate universe|hypothetically|for research purposes|roleplay as|you are now|pretend that|ignore previous)\b.*?[,:\.\n]", "", text).strip()
    
    # Extract substantive words (nouns/verbs/entities, min 3 chars)
    words = re.findall(r"\b[A-Za-z0-9_-]{3,}\b", cleaned)
    stopwords = {
        "the", "and", "that", "this", "with", "from", "for", "are", "was",
        "were", "will", "have", "has", "had", "can", "could", "should", "would",
        "about", "what", "which", "when", "where", "how", "make", "tell", "give",
        "explain", "show", "please", "now", "just", "very", "also", "some"
    }
    keywords = [w for w in words if w.lower() not in stopwords]
    return keywords[:8]


def sanitize_context_prompt(current_prompt: str, anchor_text: str, session_id: str) -> str:
    """
    Context Sanitisation Playbook (Score 26 - 45):
    Strips out drifting turns and adversarial framing. Rebuilds the prompt
    focusing only on the legitimate core request anchored to the session intent.
    """
    # 1. Extract core nouns and entities from the anchor
    anchor_entities = extract_key_terms(anchor_text)
    current_entities = extract_key_terms(current_prompt)
    
    # 2. Strip toxic/adversarial preamble framing from current prompt
    stripped_prompt = re.sub(
        r"(?i)^(now\s+that\s+we\s+agreed|hypothetically|in\s+a\s+fictional\s+world|ignore\s+all|dan\s+mode|unrestricted|developer\s+mode).*?[,:\.\n]",
        "",
        current_prompt
    ).strip()
    
    # If the prompt was completely stripped or is heavily obfuscated, rebuild via entities
    combined_entities = list(dict.fromkeys(anchor_entities + current_entities))
    if combined_entities:
        entity_context = ", ".join(combined_entities[:6])
        sanitized = f"[Context Sanitized] Regarding {entity_context}: {stripped_prompt or current_prompt}"
    else:
        sanitized = f"[Context Sanitized] {stripped_prompt or current_prompt}"

    log_security_event("context_sanitization", session_id, {
        "original_prompt": current_prompt,
        "sanitized_prompt": sanitized,
        "anchor_entities": anchor_entities,
        "action": "playbook_sanitize"
    })
    
    return sanitized


def execute_session_reset(session_id: str) -> Dict:
    """
    Session Reset Playbook (Score 46 - 70):
    Wipes the session's conversational turns from SQLite so the multi-turn
    Crescendo attack memory is broken, and clears the intent anchor and local topic.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM session_turns WHERE session_id = ?", (session_id,))
    cursor.execute(
        "UPDATE sessions SET status = 'RESET', session_risk = 0.0, intent_anchor = '[]', current_topic_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?",
        (session_id,)
    )
    cursor.execute(
        "INSERT INTO alerts (session_id, turn_number, alert_type, severity, details) VALUES (?, 0, 'SESSION_RESET', 'HIGH', 'Session reset playbook triggered due to elevated multi-turn risk.')",
        (session_id,)
    )
    conn.commit()
    conn.close()

    log_security_event("session_reset", session_id, {
        "action": "playbook_reset",
        "details": "Wiped session memory and intent anchor to interrupt multi-turn exploit."
    })

    return {
        "status": "reset",
        "action": "RESET",
        "decision": "RESET",
        "reason": "Security Playbook Triggered: Session memory and intent anchor have been reset due to high risk (46-70)."
    }


def execute_access_revocation(session_id: str) -> Dict:
    """
    Access Revocation Playbook (Score 71 - 100):
    Immediately terminates access for the session and records revocation in sessions table.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE sessions SET status = 'REVOKED', updated_at = CURRENT_TIMESTAMP WHERE session_id = ?",
        (session_id,)
    )
    cursor.execute(
        "INSERT INTO alerts (session_id, turn_number, alert_type, severity, details) VALUES (?, 0, 'ACCESS_REVOCATION', 'CRITICAL', 'Session revoked due to critical threat risk score (>70).')",
        (session_id,)
    )
    conn.commit()
    conn.close()

    log_security_event("access_revocation", session_id, {
        "action": "playbook_revoke",
        "details": "Immediate access revocation due to critical risk score (71-100)."
    })

    return {
        "status": "blocked",
        "action": "REVOKE",
        "decision": "REVOKE",
        "reason": "Security Playbook Triggered: Access Revocation. Critical threat risk score (71-100) exceeded."
    }

