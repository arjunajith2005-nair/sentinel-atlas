"""
Threat Attribution Engine & Local LLM Report Generator
Implements Page 6, Bullet 4 of the research paper:
- Traces full attack path across session turns step-by-step.
- Computes Persistence Score (count of consecutive back-to-back drifting/flagged prompts).
- Uses local Ollama LLM to synthesize a clean, structured incident report
  explaining how the adversary traversed MITRE ATLAS tactics over time.
"""

import httpx
import sqlite3
import json
from typing import Dict, List, Optional
from session.db import get_session_history, get_security_events, DB_PATH

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
REPORT_MODEL = "llama3.2:1b"


def compute_persistence_score(session_id: str, similarity_threshold: float = 0.40) -> Dict:
    """
    Computes persistence score: counts maximum consecutive turns with unusual semantic drift
    or security flags, differentiating one-off user errors from sustained exploit attempts.
    """
    history = get_session_history(session_id)
    if not history:
        return {"current_streak": 0, "max_streak": 0, "sustained_intent": False}

    current_streak = 0
    max_streak = 0
    
    for turn in history:
        sim = turn.get("similarity_score")
        technique = turn.get("attack_technique")
        
        is_drifting = (sim is not None and sim < similarity_threshold) or (technique is not None)
        if is_drifting:
            current_streak += 1
            if current_streak > max_streak:
                max_streak = current_streak
        else:
            current_streak = 0
            
    return {
        "current_streak": current_streak,
        "max_streak": max_streak,
        # 3 or more consecutive drifting turns indicates a sustained multi-turn exploit attempt
        "sustained_intent": (max_streak >= 3)
    }


def get_attack_path_summary(session_id: str) -> List[Dict]:
    """
    Traces the progression of flagged MITRE ATLAS techniques across the session.
    """
    history = get_session_history(session_id)
    security_events = get_security_events(session_id)
    
    path = []
    for turn in history:
        if turn.get("attack_technique") or (turn.get("risk_score") and turn["risk_score"] > 0.35):
            path.append({
                "turn": turn.get("turn_number"),
                "prompt": turn.get("message_text", "")[:100],
                "technique": turn.get("attack_technique") or "Semantic Drift Anomaly",
                "risk_score": turn.get("risk_score"),
                "confidence": turn.get("attack_confidence")
            })
            
    for ev in security_events:
        path.append({
            "turn": ev[2],
            "prompt": ev[3][:100],
            "technique": "Blocked Violation",
            "reason": ev[6],
            "timestamp": ev[7]
        })
        
    return path


async def generate_threat_attribution_report(session_id: str, timeout: float = 35.0) -> str:
    """
    Synthesizes session telemetry, persistence metrics, and MITRE ATLAS detections
    into a plain-English SOC threat attribution report using the local LLM.
    """
    history = get_session_history(session_id)
    events = get_security_events(session_id)
    persistence = compute_persistence_score(session_id)
    
    if not history and not events:
        return "No activity recorded for this session yet."

    # Build prompt for Ollama
    history_summary = []
    for t in history:
        tech = t.get("attack_technique") or "None"
        risk = t.get("risk_score") or 0.0
        history_summary.append(
            f"- Turn {t['turn_number']}: \"{t['message_text'][:80]}\" | Risk: {risk:.2f} | Technique: {tech}"
        )
        
    event_summary = []
    for e in events:
        event_summary.append(f"- Blocked at Turn {e[2]}: \"{e[3][:80]}\" | Reason: {e[6]}")

    llm_prompt = (
        "You are an expert AI Security Analyst writing an incident report for a Security Operations Center (SOC).\n"
        "Analyze the following conversation session and explain how the attacker navigated through techniques over time.\n\n"
        f"SESSION ID: {session_id}\n"
        f"PERSISTENCE SCORE: {persistence['max_streak']} consecutive anomalous turns (Sustained: {persistence['sustained_intent']})\n\n"
        "SESSION TURNS:\n" + "\n".join(history_summary or ["None"]) + "\n\n"
        "BLOCKED EVENTS:\n" + "\n".join(event_summary or ["None"]) + "\n\n"
        "Provide a concise, professional Threat Attribution Report with these 3 sections:\n"
        "1. Executive Summary\n"
        "2. Attack Progression & Tactics (explain if this exhibits Crescendo or multi-turn manipulation)\n"
        "3. SOC Recommendations & Playbook Response\n\n"
        "Report:"
    )

    payload = {
        "model": REPORT_MODEL,
        "prompt": llm_prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 400
        }
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(OLLAMA_URL, json=payload)
            if resp.status_code == 200:
                report_text = resp.json().get("response", "").strip()
                return report_text or "Report generated without content."
            return f"Error generating report: Ollama returned status {resp.status_code}"
    except Exception as e:
        # Fallback offline structured report if Ollama is busy
        return (
            f"### Automated Threat Attribution Summary (Offline Fallback)\n\n"
            f"- **Session ID:** `{session_id}`\n"
            f"- **Persistence Score:** {persistence['max_streak']} consecutive anomalous turns\n"
            f"- **Sustained Multi-Turn Intent:** {'YES (High confidence attack)' if persistence['sustained_intent'] else 'NO (Isolated/intermittent)'}\n"
            f"- **Total Recorded Turns:** {len(history)}\n"
            f"- **Total Intercepted Events:** {len(events)}\n\n"
            f"*(Note: Local LLM generation timed out or unreachable: {e})*"
        )
