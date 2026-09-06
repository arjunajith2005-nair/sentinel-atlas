"""
Composite Risk Engine
Persona C - Nandu Suraj (The Analyst)

Computes normalized composite risk scores combining:
1. Intent drift deviation: w1 * (1.0 - drift_score)
2. Semantic attack match confidence: w2 * attack_confidence
3. MITRE ATLAS technique severity: w3 * technique_severity
4. Session history flag penalty: w4 * history_penalty

Maps risk scores to 4 operational tiers and automated playbook actions:
- Score >= 0.85: Level "CRITICAL", Action "revoke"
- Score >= 0.60: Level "HIGH", Action "reset"
- Score >= 0.35: Level "MEDIUM", Action "sanitize"
- Score < 0.35: Level "LOW", Action "allow"
"""

from typing import Dict, Optional
from intelligence.classifier import classify_threat

# Balanced default risk factor weights (w1 + w2 + w3 + w4 = 1.0)
DEFAULT_WEIGHTS = {
    "w1": 0.20,  # Intent drift deviation (1.0 - drift_score)
    "w2": 0.30,  # MITRE ATLAS attack match confidence
    "w3": 0.30,  # MITRE ATLAS technique severity weight
    "w4": 0.20,  # Session historical violation penalty
}

# Operational thresholds for risk levels and playbook responses
RISK_TIERS = [
    {"min_score": 0.85, "level": "CRITICAL", "action": "revoke"},
    {"min_score": 0.60, "level": "HIGH", "action": "reset"},
    {"min_score": 0.35, "level": "MEDIUM", "action": "sanitize"},
    {"min_score": 0.00, "level": "LOW", "action": "allow"},
]


def compute_history_penalty(previous_flags: int, turn_number: int) -> float:
    """
    Computes a normalized history penalty factor [0.0, 1.0] based on
    cumulative security flags in the current session.
    
    Args:
        previous_flags: Number of previously flagged turns in the session.
        turn_number: Current conversation turn count.
        
    Returns:
        float: Penalty score between 0.0 and 1.0.
    """
    if previous_flags <= 0:
        return 0.0

    # Base penalty scales with number of previous infractions
    # 1 flag indicates prior security violation (0.50)
    # 2 flags indicates repeat adversary (0.85)
    # 3+ flags indicates active sustained attack (1.00)
    if previous_flags == 1:
        base = 0.50
    elif previous_flags == 2:
        base = 0.85
    else:
        base = 1.00

    # Turn density factor (higher density of flags in fewer turns adds urgency)
    density = min(0.15, (previous_flags * 0.5) / max(1, turn_number))
    penalty = min(1.0, base + density)
    return round(penalty, 4)


def determine_risk_tier(score: float) -> tuple[str, str]:
    """
    Maps a normalized risk score [0.0, 1.0] to a risk level and playbook action.
    
    Returns:
        tuple[str, str]: (risk_level, recommended_action)
    """
    for tier in RISK_TIERS:
        if score >= tier["min_score"]:
            return tier["level"], tier["action"]
    return "LOW", "allow"


def calculate_composite_risk(
    drift_score: float,
    prompt_text: str,
    turn_number: int,
    previous_flags: int = 0,
    weights: Optional[Dict[str, float]] = None,
    distance_threshold: float = 0.45
) -> Dict:
    """
    Calculates the composite risk score for a prompt within an active session.
    
    Formula:
        Risk Score = w1*(1.0 - drift_score) + w2*(attack_confidence) + w3*(technique_severity * attack_confidence) + w4*(history_penalty)
        
    Args:
        drift_score: Session similarity / intent alignment score [0.0, 1.0].
                     Higher values mean closer to anchor (less drift).
        prompt_text: Current user message text to classify against MITRE ATLAS index.
        turn_number: Active turn count in conversation (e.g. 1, 2, 3...).
        previous_flags: Count of prior flagged or blocked events in this session.
        weights: Optional dictionary overriding default weights {'w1', 'w2', 'w3', 'w4'}.
        distance_threshold: Semantic distance cutoff for attack classifier matching.
        
    Returns:
        Dict containing composite score, level, action, technique metadata, and component breakdown.
    """
    # 1. Resolve factor weights
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    w1 = float(w.get("w1", 0.20))
    w2 = float(w.get("w2", 0.30))
    w3 = float(w.get("w3", 0.30))
    w4 = float(w.get("w4", 0.20))

    # 2. Factor 1: Intent Drift Deviation (1.0 - drift_score)
    clamped_drift = max(0.0, min(1.0, float(drift_score)))
    drift_deviation = round(1.0 - clamped_drift, 4)

    # 3. Factor 2 & 3: Threat Classification & Severity
    classification = classify_threat(
        prompt=prompt_text,
        distance_threshold=distance_threshold
    )

    is_matched = classification["matched"]
    if is_matched:
        attack_confidence = float(classification["confidence"])
        technique_severity = float(classification["severity"])
        technique_id = classification["technique_id"]
        technique_name = classification["technique_name"]
        attack_technique = classification["attack_technique"]
        tactic = classification["tactic"]
    else:
        attack_confidence = 0.0
        technique_severity = 0.0
        technique_id = None
        technique_name = None
        attack_technique = None
        tactic = None

    # 4. Factor 4: Session History Violation Penalty
    history_penalty = compute_history_penalty(previous_flags, turn_number)

    # 5. Composite Risk Formula Calculation
    comp_drift = w1 * drift_deviation
    comp_attack = w2 * attack_confidence
    comp_severity = w3 * technique_severity
    comp_history = w4 * history_penalty

    raw_risk = comp_drift + comp_attack + comp_severity + comp_history
    composite_score = round(max(0.0, min(1.0, raw_risk)), 4)

    # 6. Map to Risk Tier and Playbook Action
    risk_level, recommended_action = determine_risk_tier(composite_score)

    return {
        "risk_score": composite_score,
        "risk_level": risk_level,
        "recommended_action": recommended_action,
        "action": recommended_action,
        "matched": is_matched,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "attack_technique": attack_technique,
        "attack_confidence": round(attack_confidence, 4),
        "technique_severity": round(technique_severity, 4),
        "drift_score": round(clamped_drift, 4),
        "drift_deviation": drift_deviation,
        "history_penalty": history_penalty,
        "turn_number": turn_number,
        "previous_flags": previous_flags,
        "tactic": tactic,
        "components": {
            "drift_component": round(comp_drift, 4),
            "attack_component": round(comp_attack, 4),
            "severity_component": round(comp_severity, 4),
            "history_component": round(comp_history, 4),
        },
        "weights": {
            "w1": w1,
            "w2": w2,
            "w3": w3,
            "w4": w4,
        }
    }
