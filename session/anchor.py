import numpy as np

def compute_intent_anchor(history: list[dict], min_tokens: int = 10) -> list[float]:
    """
    Computes baseline Intent Anchor vector for session.
    Applies anchor quality check (Page 6 of research paper):
    If opening turn has fewer than 10 tokens, the anchor is deferred and computed
    as the mean embedding of the first two turns once turn 2 arrives.
    """
    if not history:
        return []
    
    first_turn_text = history[0]["message_text"]
    first_turn_emb = history[0]["embedding"]
    
    # Check token count using whitespace tokenization
    token_count = len(first_turn_text.strip().split())
    
    # If opening turn satisfies quality check (>= 10 tokens), establish it as anchor
    if token_count >= min_tokens:
        return first_turn_emb
    
    # If opening turn is below threshold, wait for turn 2 and compute mean embedding
    if len(history) >= 2:
        second_turn_text = history[1].get("message_text", "")
        second_turn_emb = history[1]["embedding"]
        combined_tokens = token_count + len(second_turn_text.strip().split())
        if combined_tokens >= min_tokens:
            avg_vector = (np.array(first_turn_emb) + np.array(second_turn_emb)) / 2.0
            return avg_vector.tolist()
        
        # Look for the first turn in history with sufficient substance
        for turn in history[1:]:
            t_tokens = len(turn.get("message_text", "").strip().split())
            if t_tokens >= min_tokens:
                return turn["embedding"]
        return []
        
    # Defer anchor until more substantive context arrives
    return []