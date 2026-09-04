import numpy as np

def compute_intent_anchor(history: list[dict]) -> list[float]:
    """
    Computes baseline intent vector for session.
    Averages turn 1 & 2 if initial prompt is under 40 chars; otherwise uses turn 1.
    """
    if not history:
        return []
    
    first_turn_text = history[0]["message_text"]
    first_turn_emb = history[0]["embedding"]
    
    # If turn 1 is detailed enough, set it immediately as anchor
    if len(first_turn_text) >= 40:
        return first_turn_emb
    
    # If turn 1 is short (<40 chars), wait for turn 2 to average vectors
    if len(history) >= 2:
        second_turn_emb = history[1]["embedding"]
        avg_vector = (np.array(first_turn_emb) + np.array(second_turn_emb)) / 2.0
        return avg_vector.tolist()
        
    # Temporary fallback until turn 2 arrives
    return first_turn_emb