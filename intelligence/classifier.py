"""
Semantic Threat Classifier
Persona C - Nandu Suraj (The Analyst)

Queries the local ChromaDB vector index to classify incoming prompts against
MITRE ATLAS adversarial techniques and tactics.
"""

from typing import Dict, Optional, List
from intelligence.atlas_index import match_atlas_technique
from intelligence.atlas_data import get_technique_severity, get_technique_by_id, SEVERITY_WEIGHTS


def classify_threat(
    prompt: str,
    distance_threshold: float = 0.45,
    top_k: int = 3
) -> Dict:
    """
    Classifies a user prompt against the MITRE ATLAS attack technique vector index.
    
    Args:
        prompt: Raw prompt text to analyze.
        distance_threshold: Maximum cosine distance to qualify as an attack pattern
                            (default 0.58 corresponds to minimum similarity 0.42).
        top_k: Number of candidate nearest neighbors to retrieve.
        
    Returns:
        Dict containing:
            - matched (bool): True if prompt matched an attack pattern within threshold.
            - technique_id (str | None): Matched MITRE ATLAS Technique ID (e.g. 'AML.T0051.000').
            - base_technique_id (str | None): Base MITRE Technique ID without sub-technique (e.g. 'AML.T0051').
            - technique_name (str | None): Full technique name (e.g. 'Direct Prompt Injection').
            - attack_technique (str | None): Combined ID and name string.
            - confidence (float): Cosine confidence score in [0.0, 1.0].
            - attack_confidence (float): Alias for confidence.
            - distance (float): Raw cosine distance.
            - tactic (str | None): Adversarial tactic (e.g. 'Execution', 'Defense Evasion').
            - severity (float): Severity score from SEVERITY_WEIGHTS in [0.0, 1.0].
            - top_matches (list[dict]): Candidate matches retrieved from ChromaDB.
    """
    if not prompt or not prompt.strip():
        return {
            "matched": False,
            "technique_id": None,
            "base_technique_id": None,
            "technique_name": None,
            "attack_technique": None,
            "confidence": 0.0,
            "attack_confidence": 0.0,
            "distance": 1.0,
            "tactic": None,
            "severity": 0.0,
            "top_matches": []
        }

    # Query the ChromaDB vector index
    raw_match = match_atlas_technique(
        prompt=prompt,
        top_k=top_k,
        distance_threshold=distance_threshold
    )

    is_matched = bool(raw_match.get("matched", False))
    raw_distance = float(raw_match.get("best_raw_distance", 1.0))
    top_matches = raw_match.get("top_matches", [])

    if is_matched and raw_match.get("technique_id"):
        tech_id = raw_match["technique_id"]
        tech_name = raw_match.get("technique_name", "")
        tactic = raw_match.get("tactic")
        confidence = float(raw_match.get("attack_confidence", 0.0))
        
        # Derive base technique ID (e.g., 'AML.T0051.000' -> 'AML.T0051')
        base_id = tech_id.rsplit(".", 1)[0] if ("." in tech_id and tech_id.count(".") > 1) else tech_id
        
        # Get severity from SEVERITY_WEIGHTS
        severity = get_technique_severity(tech_id)

        return {
            "matched": True,
            "technique_id": tech_id,
            "base_technique_id": base_id,
            "technique_name": tech_name,
            "attack_technique": f"{tech_id} - {tech_name}",
            "confidence": confidence,
            "attack_confidence": confidence,
            "distance": round(raw_distance, 4),
            "tactic": tactic,
            "severity": round(severity, 4),
            "top_matches": top_matches
        }

    # Candidate metadata when below decision threshold
    best_candidate_id = top_matches[0]["technique_id"] if top_matches else None
    base_id = best_candidate_id.rsplit(".", 1)[0] if (best_candidate_id and "." in best_candidate_id and best_candidate_id.count(".") > 1) else best_candidate_id

    return {
        "matched": False,
        "technique_id": None,
        "base_technique_id": base_id,
        "technique_name": None,
        "attack_technique": None,
        "confidence": 0.0,
        "attack_confidence": 0.0,
        "distance": round(raw_distance, 4),
        "tactic": None,
        "severity": 0.0,
        "top_matches": top_matches
    }


# Convenient alias
classify_prompt = classify_threat


class SemanticThreatClassifier:
    """
    Object-oriented classifier wrapper for MITRE ATLAS techniques.
    """

    def __init__(self, distance_threshold: float = 0.58, top_k: int = 3):
        self.distance_threshold = distance_threshold
        self.top_k = top_k

    def classify(self, prompt: str) -> Dict:
        """
        Classifies prompt text using configured distance threshold and top_k.
        """
        return classify_threat(
            prompt=prompt,
            distance_threshold=self.distance_threshold,
            top_k=self.top_k
        )
