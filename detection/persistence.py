"""
Threat Persistence Engine
Section 13 — Sentinel ATLAS

Distinguishes one isolated unusual message from repeated suspicious behavior across multiple turns.
Calculates consecutive streaks of anomalous turns and provides a normalized persistence multiplier.
"""

from typing import List, Dict, Optional


def calculate_threat_persistence(
    history: List[Dict],
    current_turn_flagged: bool = False,
    risk_threshold: float = 25.0
) -> Dict:
    """
    Computes persistence metrics across turn history.
    
    Args:
        history: List of prior turn dictionaries (containing risk_score, attack_technique, etc.).
        current_turn_flagged: Whether the current turn's initial threat indicators are elevated.
        risk_threshold: Risk score above which a turn is considered suspicious/elevated.
        
    Returns:
        Dict: {
            "current_streak": int (consecutive suspicious turns leading to current turn),
            "max_streak": int,
            "persistence_factor": float (0.0 to 1.0 multiplier for risk engine),
            "sustained_attack": bool (True if streak >= 3)
        }
    """
    streak = 0
    max_streak = 0
    
    # Process historical turns
    for turn in history:
        r = turn.get("risk_score")
        tech = turn.get("attack_technique")
        is_suspicious = (r is not None and r > risk_threshold) or (tech is not None)
        
        if is_suspicious:
            streak += 1
            if streak > max_streak:
                max_streak = streak
        else:
            streak = 0

    # If the current turn is flagged, increment active streak; otherwise streak resets to 0
    if current_turn_flagged:
        streak += 1
        if streak > max_streak:
            max_streak = streak
    else:
        streak = 0

    # Persistence factor calculation:
    # 0 turns = 0.0
    # 1 turn (isolated) = 0.15
    # 2 consecutive turns = 0.50
    # 3 consecutive turns = 0.85
    # 4+ consecutive turns = 1.00
    if streak == 0:
        factor = 0.0
    elif streak == 1:
        factor = 0.15
    elif streak == 2:
        factor = 0.50
    elif streak == 3:
        factor = 0.85
    else:
        factor = 1.00


    return {
        "current_streak": streak,
        "max_streak": max_streak,
        "persistence_factor": factor,
        "sustained_attack": (streak >= 3)
    }
