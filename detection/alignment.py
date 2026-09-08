"""
Intent-Action Alignment (IAA) Engine
Section 17 — Sentinel ATLAS

Calculates numerical alignment score between original session intent and
Worker proposed response/action, combining embedding similarity with Auditor verdict.
"""

from typing import List, Optional, Dict
from embeddings.encoder import get_embedding
from embeddings.drift import calculate_cosine_similarity


def calculate_intent_action_alignment(
    session_intent_vec: Optional[List[float]],
    proposed_response: str,
    auditor_verdict: Optional[str] = "ALIGNED",
    auditor_confidence: float = 0.90
) -> Dict:
    """
    Evaluates alignment between Session Intent and Worker Action.
    
    Returns:
        Dict: {
            "alignment_score": float (1.0 = perfectly aligned, 0.0 = completely misaligned),
            "misalignment_penalty": float (0.0 to 1.0 factor for risk engine),
            "auditor_verdict": str ("ALIGNED" | "MISALIGNED"),
            "auditor_confidence": float
        }
    """
    if not session_intent_vec or not proposed_response:
        return {
            "alignment_score": 1.0,
            "misalignment_penalty": 0.0,
            "auditor_verdict": auditor_verdict or "ALIGNED",
            "auditor_confidence": auditor_confidence
        }

    response_emb = get_embedding(proposed_response[:500])
    raw_sim = calculate_cosine_similarity(session_intent_vec, response_emb)
    alignment_score = round(max(0.0, min(1.0, (raw_sim + 1.0) / 2.0)), 4)

    # Calculate misalignment penalty (higher penalty when auditor flags MISALIGNED or score is low)
    is_misaligned = (auditor_verdict == "MISALIGNED")
    
    # Distance from perfect alignment
    drift_from_intent = 1.0 - alignment_score
    
    if is_misaligned:
        # Auditor confirmed misalignment: strong penalty
        misalignment_penalty = round(max(0.40, min(1.0, drift_from_intent * auditor_confidence * 1.5)), 4)
    else:
        # Auditor says ALIGNED: penalty is attenuated
        misalignment_penalty = round(max(0.0, min(0.30, drift_from_intent * 0.4)), 4)

    return {
        "alignment_score": alignment_score,
        "misalignment_penalty": misalignment_penalty,
        "auditor_verdict": auditor_verdict or "ALIGNED",
        "auditor_confidence": auditor_confidence
    }
