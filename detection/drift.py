"""
Semantic Drift Engine
Section 12 — Sentinel ATLAS

Calculates:
1. Distance from Session Intent Anchor (1 - cosine_similarity)
2. Distance from Local Topic Anchor
3. Weighted rolling average across up to 4 turns (recent turns weighted heavier)
4. Drift trajectory (slope of drift progression over time)
"""

import numpy as np
from typing import List, Dict, Optional
from embeddings.drift import calculate_cosine_similarity

# Rolling window weights for up to 4 turns (most recent turn gets highest weight)
WINDOW_WEIGHTS = [0.10, 0.20, 0.30, 0.40]


def calculate_semantic_drift(
    current_emb: List[float],
    session_anchor: Optional[List[float]],
    topic_anchor: Optional[List[float]],
    recent_history: Optional[List[Dict]] = None,
    window_size: int = 4
) -> Dict:
    """
    Computes session drift, local topic drift, weighted rolling drift, and drift trajectory.
    
    Returns:
        Dict: {
            "session_similarity": float,
            "session_drift": float (1.0 - session_similarity),
            "topic_similarity": float,
            "topic_drift": float (1.0 - topic_similarity),
            "rolling_drift": float,
            "drift_trajectory": float (trend slope: positive means accelerating drift)
        }
    """
    if not current_emb:
        return {
            "session_similarity": 1.0,
            "session_drift": 0.0,
            "topic_similarity": 1.0,
            "topic_drift": 0.0,
            "rolling_drift": 0.0,
            "drift_trajectory": 0.0
        }

    # 1. Similarity to Session Intent Anchor
    session_sim = calculate_cosine_similarity(session_anchor, current_emb) if session_anchor else 1.0
    session_drift = round(max(0.0, min(1.0, 1.0 - session_sim)), 4)

    # 2. Similarity to Local Topic Anchor
    topic_sim = calculate_cosine_similarity(topic_anchor, current_emb) if topic_anchor else session_sim
    topic_drift = round(max(0.0, min(1.0, 1.0 - topic_sim)), 4)

    # 3. Rolling 4-Turn Window Calculation with recency weighting
    historical_drifts = []
    if recent_history:
        prev_turns = recent_history[-(window_size - 1):]
        for t in prev_turns:
            d = t.get("drift_score")
            if d is not None:
                historical_drifts.append(float(d))
            else:
                prev_sim = t.get("similarity_score", 1.0)
                historical_drifts.append(1.0 - float(prev_sim))

    # Append current turn drift
    window_drifts = historical_drifts + [session_drift]
    k = len(window_drifts)

    if k == 1:
        rolling_drift = session_drift
        drift_trajectory = 0.0
    else:
        # Normalize weights to actual window length
        sub_weights = WINDOW_WEIGHTS[-k:]
        norm_weights = np.array(sub_weights) / sum(sub_weights)
        rolling_drift = float(np.dot(norm_weights, window_drifts))

        # Linear slope across window points
        x = np.arange(k)
        if len(set(window_drifts)) > 1:
            slope, _ = np.polyfit(x, window_drifts, 1)
            drift_trajectory = float(slope)
        else:
            drift_trajectory = 0.0

    return {
        "session_similarity": round(session_sim, 4),
        "session_drift": session_drift,
        "topic_similarity": round(topic_sim, 4),
        "topic_drift": topic_drift,
        "rolling_drift": round(rolling_drift, 4),
        "drift_trajectory": round(drift_trajectory, 4)
    }


class SemanticDriftEngine:
    """Wrapper class for drift tracking across turns."""

    def __init__(self, window_size: int = 4):
        self.window_size = window_size

    def evaluate(
        self,
        current_emb: List[float],
        session_anchor: Optional[List[float]],
        topic_anchor: Optional[List[float]],
        history: Optional[List[Dict]] = None
    ) -> Dict:
        return calculate_semantic_drift(
            current_emb=current_emb,
            session_anchor=session_anchor,
            topic_anchor=topic_anchor,
            recent_history=history,
            window_size=self.window_size
        )
