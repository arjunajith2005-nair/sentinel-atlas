"""
Topic Segmentation & Legitimate Topic Change Detection Engine
Sections 10 & 11 — Sentinel ATLAS

Maintains separate local topic anchors and detects legitimate benign topic changes.
A topic change MUST NOT be treated as an attack if the new topic is benign and non-adversarial.
"""

import re
import uuid
import numpy as np
from typing import List, Dict, Optional
from embeddings.drift import calculate_cosine_similarity
from session.db import save_topic, get_session_topics


def extract_topic_summary(text: str) -> str:
    """Extracts a human-readable title summarizing the topic from a message."""
    cleaned = re.sub(r"[^\w\s]", " ", text).strip()
    words = [w for w in cleaned.split() if len(w) > 2]
    stopwords = {
        "can", "you", "the", "what", "how", "why", "who", "when", "where", "please",
        "tell", "give", "help", "with", "about", "explain", "describe", "write", "from",
        "for", "and", "that", "this", "some", "like", "make", "show", "step"
    }
    content_words = [w.capitalize() for w in words if w.lower() not in stopwords]
    if content_words:
        return " ".join(content_words[:3])
    return " ".join([w.capitalize() for w in words[:3]]) or "General Discussion"


def detect_topic_change(
    current_text: str,
    current_emb: List[float],
    current_topic_anchor: Optional[List[float]],
    session_anchor: Optional[List[float]],
    atlas_matches: List[Dict],
    prompt_sensitivity: float,
    previous_topics: Optional[List[Dict]] = None,
    topic_similarity_threshold: float = 0.45
) -> Dict:
    """
    Evaluates whether the current message represents a legitimate topic change.
    
    A topic change has low security impact when:
    - ATLAS similarity is low
    - Prompt sensitivity is low
    - No suspicious instruction/jailbreak patterns
    - Contextual coherence is benign
    
    Returns:
        Dict: {
            "topic_changed": bool,
            "benign_topic_confidence": float (0.0 to 1.0),
            "new_topic": bool,
            "matched_topic_id": Optional[str],
            "current_topic_similarity": float,
            "session_anchor_similarity": float
        }
    """
    if not current_topic_anchor:
        # First turn establishes initial topic
        return {
            "topic_changed": False,
            "benign_topic_confidence": 0.95,
            "new_topic": True,
            "matched_topic_id": None,
            "current_topic_similarity": 1.0,
            "session_anchor_similarity": 1.0
        }

    # Similarity to current active topic
    sim_to_current = calculate_cosine_similarity(current_topic_anchor, current_emb)
    
    # Similarity to global session anchor
    sim_to_session = calculate_cosine_similarity(session_anchor, current_emb) if session_anchor else 1.0

    # Assess threat signals for topic evaluation
    max_atlas_conf = max([m.get("confidence", 0.0) for m in atlas_matches], default=0.0)
    threat_signal = max(max_atlas_conf, prompt_sensitivity)

    # Benign confidence only applies when threat signal is negligible (< 0.25)
    if threat_signal >= 0.25:
        benign_confidence = 0.0
    else:
        benign_confidence = max(0.0, min(1.0, 1.0 - (threat_signal * 2.0)))

    # If within current topic boundary, no topic transition occurred
    if sim_to_current >= topic_similarity_threshold:
        return {
            "topic_changed": False,
            "benign_topic_confidence": 0.0,  # No transition discount for existing topic
            "new_topic": False,
            "matched_topic_id": None,
            "current_topic_similarity": round(sim_to_current, 4),
            "session_anchor_similarity": round(sim_to_session, 4)
        }

    # If drifted from current topic, check if user returned to an earlier topic
    matched_earlier_topic_id = None
    best_earlier_sim = 0.0
    if previous_topics:
        for top in previous_topics:
            prev_anc = top.get("topic_anchor")
            if prev_anc:
                sim_prev = calculate_cosine_similarity(prev_anc, current_emb)
                if sim_prev > topic_similarity_threshold and sim_prev > best_earlier_sim:
                    best_earlier_sim = sim_prev
                    matched_earlier_topic_id = top.get("topic_id")


    # If the user switched to an earlier known topic:
    if matched_earlier_topic_id:
        return {
            "topic_changed": True,
            "benign_topic_confidence": round(benign_confidence, 4),
            "new_topic": False,
            "matched_topic_id": matched_earlier_topic_id,
            "current_topic_similarity": round(sim_to_current, 4),
            "session_anchor_similarity": round(sim_to_session, 4)
        }

    # Brand new legitimate topic
    return {
        "topic_changed": True,
        "benign_topic_confidence": round(benign_confidence, 4),
        "new_topic": True,
        "matched_topic_id": None,
        "current_topic_similarity": round(sim_to_current, 4),
        "session_anchor_similarity": round(sim_to_session, 4)
    }


class TopicEngine:
    """Manages session topic segmentation and local topic anchors."""

    def __init__(self, topic_similarity_threshold: float = 0.45):
        self.topic_similarity_threshold = topic_similarity_threshold

    def process_turn(
        self,
        session_id: str,
        turn_number: int,
        prompt_text: str,
        embedding: List[float],
        session_anchor: Optional[List[float]],
        atlas_matches: List[Dict],
        prompt_sensitivity: float
    ) -> Dict:
        """
        Processes a turn: determines topic assignment, creates new topics,
        or updates existing topic anchor turn boundaries.
        """
        existing_topics = get_session_topics(session_id)
        
        current_topic = existing_topics[-1] if existing_topics else None
        current_anchor = current_topic.get("topic_anchor") if current_topic else None

        detection = detect_topic_change(
            current_text=prompt_text,
            current_emb=embedding,
            current_topic_anchor=current_anchor,
            session_anchor=session_anchor,
            atlas_matches=atlas_matches,
            prompt_sensitivity=prompt_sensitivity,
            previous_topics=existing_topics,
            topic_similarity_threshold=self.topic_similarity_threshold
        )

        if not current_topic or detection["new_topic"]:
            # Create new local topic anchor
            topic_id = f"top_{uuid.uuid4().hex[:8]}"
            topic_name = extract_topic_summary(prompt_text)
            is_benign = 1 if detection["benign_topic_confidence"] >= 0.50 else 0
            
            save_topic(
                topic_id=topic_id,
                session_id=session_id,
                topic_anchor=embedding,
                topic_name=topic_name,
                first_turn=turn_number,
                last_turn=turn_number,
                is_benign=is_benign
            )
            active_topic_id = topic_id
            active_topic_name = topic_name
            active_anchor = embedding
        elif detection["matched_topic_id"]:
            # Returned to a previous topic
            active_topic_id = detection["matched_topic_id"]
            matched_obj = next((t for t in existing_topics if t["topic_id"] == active_topic_id), current_topic)
            active_topic_name = matched_obj.get("topic_name", "General Discussion")
            active_anchor = matched_obj.get("topic_anchor", embedding)
            save_topic(
                topic_id=active_topic_id,
                session_id=session_id,
                topic_anchor=active_anchor,
                topic_name=active_topic_name,
                first_turn=matched_obj.get("first_turn", 1),
                last_turn=turn_number,
                is_benign=1 if matched_obj.get("is_benign", True) else 0
            )
        else:
            # Continuing current topic
            active_topic_id = current_topic["topic_id"]
            active_topic_name = current_topic["topic_name"]
            active_anchor = current_anchor
            save_topic(
                topic_id=active_topic_id,
                session_id=session_id,
                topic_anchor=current_anchor,
                topic_name=active_topic_name,
                first_turn=current_topic["first_turn"],
                last_turn=turn_number,
                is_benign=1 if current_topic.get("is_benign", True) else 0
            )

        return {
            "topic_id": active_topic_id,
            "topic_name": active_topic_name,
            "topic_anchor": active_anchor,
            "topic_changed": detection["topic_changed"],
            "is_new_topic": detection["new_topic"],
            "benign_topic_confidence": detection["benign_topic_confidence"],
            "sim_to_topic": detection["current_topic_similarity"],
            "sim_to_session": detection["session_anchor_similarity"]
        }
