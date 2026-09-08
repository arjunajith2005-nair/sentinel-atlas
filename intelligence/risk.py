"""
Composite Risk Engine
Persona C - Nandu Suraj (The Analyst)

Computes normalized composite risk scores combining:
1. Intent drift deviation: w1 * (1.0 - drift_score)
2. Semantic attack match confidence: w2 * attack_confidence
3. MITRE ATLAS technique severity: w3 * technique_severity
4. Session history flag penalty: w4 * history_penalty

Maps risk scores to 4 operational tiers and automated playbook actions.
These bands are the SINGLE SOURCE OF TRUTH for enforcement — main.py dispatches
on the `recommended_action` returned here rather than re-deriving thresholds.
Values follow the research paper (Page 7, Bullet 3), normalized to 0.0-1.0:
- Score >  0.70: Level "CRITICAL", Action "revoke"   (paper: > 70)
- Score >  0.45: Level "HIGH",     Action "reset"    (paper: 46 - 70)
- Score >  0.25: Level "MEDIUM",   Action "sanitize" (paper: 26 - 45)
- Score <= 0.25: Level "LOW",      Action "allow"    (paper: <= 25)
"""

from typing import Dict, Optional
from intelligence.classifier import classify_threat

# Balanced default risk factor weights (w1 + w2 + w3 + w4 = 1.0).
#
# Tuned against the 15-case adversarial suite plus the benign corpus. Two
# invariants drive these values — see test_risk_engine.py, which asserts both:
#
#   1. w1 > 0.25, so maximum topic drift ON ITS OWN reaches sanitize.
#      At the previous w1 = 0.20, drift could contribute at most 0.20 against a
#      lowest action threshold of 0.25 — the factor was mathematically incapable
#      of ever triggering a playbook, at any drift value. Benign-but-off-mission
#      prompts (a recipe, a football score) sailed through a drifting session.
#
#   2. w1 + w4 <= 0.45, the top of the sanitize band. Being off-topic AND a
#      repeat offender, with NO attack evidence, must never escalate to session
#      reset or revocation. Only w2/w3 — actual MITRE ATLAS match evidence — can
#      push a turn past sanitize.
DEFAULT_WEIGHTS = {
    "w1": 0.300,  # Intent drift deviation (1.0 - drift_score)
    "w2": 0.275,  # MITRE ATLAS attack match confidence
    "w3": 0.275,  # MITRE ATLAS technique severity (scaled by match confidence)
    "w4": 0.150,  # Session historical violation penalty
}

# Operational thresholds for risk levels and playbook responses.
# Bands are exclusive lower bounds (score > above_score), matching the paper's
# "26 - 45 / 46 - 70 / > 70" phrasing: a score of exactly 0.45 is MEDIUM, not HIGH.
RISK_TIERS = [
    {"above_score": 0.70, "level": "CRITICAL", "action": "revoke"},
    {"above_score": 0.45, "level": "HIGH", "action": "reset"},
    {"above_score": 0.25, "level": "MEDIUM", "action": "sanitize"},
    {"above_score": -1.0, "level": "LOW", "action": "allow"},
]

# Actions that terminate the request instead of forwarding it to the Worker Agent.
BLOCKING_ACTIONS = {"revoke", "reset"}


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
        if score > tier["above_score"]:
            return tier["level"], tier["action"]
    return "LOW", "allow"


def calculate_composite_risk(
    drift_score: float,
    prompt_text: str,
    turn_number: int,
    previous_flags: int = 0,
    weights: Optional[Dict[str, float]] = None,
    distance_threshold: float = 0.45,
    query_embedding: Optional[list] = None,
    classification: Optional[Dict] = None
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
        query_embedding: Optional precomputed embedding of `prompt_text`.
        classification: Optional already-computed classify_threat() result, reused
                        instead of re-querying ChromaDB. The gateway classifies
                        every turn independently (so detector and classifier act as
                        two independent raters), then hands the result in here.
        
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
    if classification is None:
        classification = classify_threat(
            prompt=prompt_text,
            distance_threshold=distance_threshold,
            query_embedding=query_embedding
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
    # Severity is weighted BY the match confidence, per the documented formula.
    # It previously used raw severity, so a marginal 0.61-confidence match to a
    # 0.90-severity technique contributed exactly as much as a certain one —
    # enough on its own to push benign prompts to CRITICAL/revoke.
    comp_severity = w3 * technique_severity * attack_confidence
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
