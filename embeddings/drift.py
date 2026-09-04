import numpy as np

def calculate_cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    a, b = np.array(vec_a), np.array(vec_b)
    norm_a, norm_b = np.linalg.norm(a), np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))

def check_intent_drift(anchor_vec: list[float], current_vec: list[float], threshold: float = 0.35) -> dict:
    if not anchor_vec:
        return {"drift_detected": False, "similarity_score": 1.0}
    similarity = calculate_cosine_similarity(anchor_vec, current_vec)
    return {
        "drift_detected": similarity < threshold,
        "similarity_score": round(similarity, 4),
        "threshold": threshold
    }