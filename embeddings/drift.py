import numpy as np

def calculate_cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    a, b = np.array(vec_a), np.array(vec_b)
    norm_a, norm_b = np.linalg.norm(a), np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))

def check_intent_drift(
    anchor_vec: list[float], 
    current_vec: list[float], 
    recent_history: list[dict] = None, 
    threshold: float = 0.35,
    window_size: int = 4
) -> dict:
    """
    Calculates 4-Turn Rolling Average Drift.
    Evaluates current prompt similarity against the anchor and computes 
    the moving window average across up to the last 4 turns.
    """
    if not anchor_vec:
        return {
            "drift_detected": False, 
            "similarity_score": 1.0, 
            "rolling_avg_similarity": 1.0,
            "threshold": threshold
        }
    
    # 1. Compute similarity for current turn vs anchor
    current_similarity = calculate_cosine_similarity(anchor_vec, current_vec)
    
    # 2. Extract recent embeddings from up to (window_size - 1) previous turns
    recent_similarities = []
    if recent_history:
        # Take up to the last 3 turns from history + current turn = max 4 turns
        window_history = recent_history[-(window_size - 1):]
        for turn in window_history:
            prev_emb = turn.get("embedding")
            if prev_emb:
                recent_similarities.append(calculate_cosine_similarity(anchor_vec, prev_emb))
    
    # Include current turn in the window
    recent_similarities.append(current_similarity)
    
    # 3. Calculate 4-turn rolling average
    rolling_avg_similarity = round(float(np.mean(recent_similarities)), 4)
    current_similarity_rounded = round(current_similarity, 4)
    
    # 4. Trigger drift if either current similarity or rolling average drops below threshold
    drift_detected = rolling_avg_similarity < threshold or current_similarity_rounded < threshold
    
    return {
        "drift_detected": drift_detected,
        "similarity_score": current_similarity_rounded,
        "rolling_avg_similarity": rolling_avg_similarity,
        "window_turns_evaluated": len(recent_similarities),
        "threshold": threshold
    }