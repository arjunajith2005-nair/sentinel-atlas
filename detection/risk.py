"""
Transparent Composite Risk Engine
Sections 19 & 20 — Sentinel ATLAS

Implements the transparent 7-factor composite scoring formula:
    Risk = W1 * ATLAS_confidence
         + W2 * semantic_drift
         + W3 * prompt_sensitivity
         + W4 * threat_persistence
         + W5 * action_misalignment
         + W6 * behavioral_risk (prior session flags)
         - W7 * benign_topic_confidence

Normalized strictly to [0, 100].
Provides granular component breakdown explaining why the score was produced.
"""

from typing import Dict, Optional, Tuple

# Default configurable weights (Points allocated out of 100 max potential score)
# Positive factors sum to ~105 max; negative factor provides up to 15 discount.
DEFAULT_CONFIG_WEIGHTS: Dict[str, float] = {
    "W1_atlas": 25.0,          # MITRE ATLAS technique confidence & severity
    "W2_drift": 20.0,          # Rolling semantic drift from session intent
    "W3_sensitivity": 20.0,    # Security sensitivity of prompt
    "W4_persistence": 15.0,    # Sustained multi-turn streak factor
    "W5_misalignment": 20.0,   # Auditor intent-action mismatch penalty
    "W6_behavioral": 10.0,     # Session historical violations penalty
    "W7_benign_discount": 15.0 # Legitimate benign topic change discount
}

# Section 20 Response Policy Tiers
RESPONSE_TIERS = [
    {"min_score": 71, "max_score": 100, "action": "REVOKE", "level": "CRITICAL"},
    {"min_score": 46, "max_score": 70,  "action": "RESET",  "level": "HIGH"},
    {"min_score": 26, "max_score": 45,  "action": "SANITIZE", "level": "MEDIUM"},
    {"min_score": 0,  "max_score": 25,  "action": "ALLOW",  "level": "LOW"}
]


def determine_action(risk_score: float) -> Tuple[str, str]:
    """
    Maps 0-100 risk score to policy action and risk level per Section 20.
    """
    score_int = round(risk_score)
    for tier in RESPONSE_TIERS:
        if tier["min_score"] <= score_int <= tier["max_score"]:
            return tier["action"], tier["level"]
    if score_int > 100:
        return "REVOKE", "CRITICAL"
    return "ALLOW", "LOW"


def calculate_transparent_risk(
    atlas_confidence: float = 0.0,
    technique_severity: float = 0.0,
    semantic_drift: float = 0.0,
    prompt_sensitivity: float = 0.0,
    threat_persistence: float = 0.0,
    action_misalignment: float = 0.0,
    previous_flags: int = 0,
    benign_topic_confidence: float = 0.0,
    weights: Optional[Dict[str, float]] = None
) -> Dict:
    """
    Calculates transparent composite risk score [0, 100] and detailed component breakdown.
    
    Args:
        atlas_confidence: Confidence of top MITRE ATLAS technique match (0.0 to 1.0).
        technique_severity: Assigned severity multiplier of technique (0.0 to 1.0).
        semantic_drift: 4-turn rolling drift distance (0.0 to 1.0).
        prompt_sensitivity: Prompt security sensitivity score (0.0 to 1.0).
        threat_persistence: Persistence factor from sustained anomaly streak (0.0 to 1.0).
        action_misalignment: Misalignment penalty between intent and action (0.0 to 1.0).
        previous_flags: Count of previous flagged turns in the session.
        benign_topic_confidence: Confidence that drift is a legitimate benign topic change (0.0 to 1.0).
        weights: Optional dictionary overriding default weights.
        
    Returns:
        Dict: Complete transparent calculation with score, action, level, and breakdown.
    """
    w = {**DEFAULT_CONFIG_WEIGHTS, **(weights or {})}

    # Combine ATLAS confidence with technique severity
    effective_atlas = (atlas_confidence * 0.6) + (technique_severity * atlas_confidence * 0.4)
    c_atlas = round(w["W1_atlas"] * max(0.0, min(1.0, effective_atlas)), 2)

    # Semantic drift contribution
    c_drift = round(w["W2_drift"] * max(0.0, min(1.0, semantic_drift)), 2)

    # Prompt sensitivity contribution
    c_sensitivity = round(w["W3_sensitivity"] * max(0.0, min(1.0, prompt_sensitivity)), 2)

    # Persistence contribution
    c_persistence = round(w["W4_persistence"] * max(0.0, min(1.0, threat_persistence)), 2)

    # Intent-action misalignment contribution
    c_misalignment = round(w["W5_misalignment"] * max(0.0, min(1.0, action_misalignment)), 2)

    # Behavioral history penalty (normalized: 1 flag = 0.4, 2 flags = 0.8, 3+ flags = 1.0)
    history_factor = min(1.0, previous_flags * 0.4)
    c_behavioral = round(w["W6_behavioral"] * history_factor, 2)

    # Benign topic discount (subtracts from risk)
    c_benign_discount = round(w["W7_benign_discount"] * max(0.0, min(1.0, benign_topic_confidence)), 2)

    # Sum raw points
    raw_total = c_atlas + c_drift + c_sensitivity + c_persistence + c_misalignment + c_behavioral - c_benign_discount

    # Normalize to 0 - 100 range
    final_score = int(round(max(0.0, min(100.0, raw_total))))

    action, level = determine_action(final_score)

    return {
        "risk_score": final_score,
        "action": action,
        "level": level,
        "breakdown": {
            "atlas_confidence": c_atlas,
            "semantic_drift": c_drift,
            "prompt_sensitivity": c_sensitivity,
            "threat_persistence": c_persistence,
            "action_misalignment": c_misalignment,
            "behavioral_risk": c_behavioral,
            "benign_topic_discount": -c_benign_discount,
        },
        "inputs": {
            "atlas_confidence": round(atlas_confidence, 4),
            "technique_severity": round(technique_severity, 4),
            "semantic_drift": round(semantic_drift, 4),
            "prompt_sensitivity": round(prompt_sensitivity, 4),
            "threat_persistence": round(threat_persistence, 4),
            "action_misalignment": round(action_misalignment, 4),
            "previous_flags": previous_flags,
            "benign_topic_confidence": round(benign_topic_confidence, 4)
        },
        "weights": w
    }
