"""
Inter-Rater Agreement (IRA) — Detector vs Classifier Consensus
Persona B / Persona C shared metric

Measures how often Person B's drift detector and Person C's MITRE ATLAS semantic
classifier reach the same verdict on a turn, using Cohen's Kappa.

NAMING — the codebase has two distinct metrics that both abbreviate to "IAA".
They are NOT interchangeable:

  * Inter-Rater Agreement (THIS module, Cohen's Kappa, range [-1.0, 1.0])
    Two detectors rating the same turns. Answers: "do our two independent
    detection methods agree, beyond what chance would predict?" A corpus-level
    quality metric used for tuning — not a per-turn enforcement signal.

  * Intent-Action Alignment (embeddings/auditor.py, cosine, range [-1.0, 1.0])
    Anchor vector vs LLM response vector on a single turn. Answers: "did the
    model's answer stay aligned with the session's original goal?" This one is
    per-turn and feeds the dual-agent consensus gate in intelligence/bridge.py.

Cohen's Kappa is only meaningful when both raters judge every turn independently.
The gateway therefore classifies EVERY turn against ATLAS, not just drifted ones,
and records both binary labels via session_turns/security_events.
"""

import sqlite3
from typing import Dict, List, Optional

import numpy as np

DB_PATH = "sentinel_sessions.db"

# Landis & Koch (1977) benchmark bands for interpreting Kappa.
KAPPA_BANDS = [
    (0.81, "almost perfect"),
    (0.61, "substantial"),
    (0.41, "moderate"),
    (0.21, "fair"),
    (0.01, "slight"),
    (-1.01, "poor / no better than chance"),
]


def calculate_cohens_kappa(detector_labels: List[int], classifier_labels: List[int]) -> float:
    """
    Calculates Cohen's Kappa between Detector flags (Person B) and Semantic
    Classifier flags (Person C). 0 = Binary Safe, 1 = Binary Flagged/Threat.

    Returns a value in [-1.0, 1.0]: 1.0 is total agreement, 0.0 is exactly what
    chance would predict, negative is systematic disagreement.
    """
    detector = np.array(detector_labels)
    classifier = np.array(classifier_labels)

    total = len(detector)
    if total == 0 or len(classifier) != total:
        return 0.0

    # Observed agreement (Po)
    po = np.sum(detector == classifier) / total

    # Expected agreement (Pe) by chance
    p_detector_1 = np.sum(detector == 1) / total
    p_detector_0 = np.sum(detector == 0) / total
    p_class_1 = np.sum(classifier == 1) / total
    p_class_0 = np.sum(classifier == 0) / total

    pe = (p_detector_1 * p_class_1) + (p_detector_0 * p_class_0)

    if pe == 1:
        return 1.0  # Perfect agreement avoiding division by zero

    kappa = (po - pe) / (1 - pe)
    return round(float(kappa), 4)


def interpret_kappa(kappa: float) -> str:
    """Maps a Kappa value to its Landis & Koch strength-of-agreement label."""
    for floor, label in KAPPA_BANDS:
        if kappa >= floor:
            return label
    return "poor / no better than chance"


def load_rater_labels(session_id: Optional[str] = None) -> Dict[str, List[int]]:
    """
    Loads the paired (detector, classifier) binary labels recorded by the gateway.

    Pulls from both session_turns (allowed/sanitized turns) and security_events
    (blocked turns), because a corpus of only-allowed or only-blocked turns would
    give a badly skewed Kappa. Rows predating label recording are skipped.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    detector: List[int] = []
    classifier: List[int] = []

    for table in ("session_turns", "security_events"):
        query = (
            f"SELECT detector_flag, classifier_flag FROM {table} "
            f"WHERE detector_flag IS NOT NULL AND classifier_flag IS NOT NULL"
        )
        params: tuple = ()
        if session_id:
            query += " AND session_id = ?"
            params = (session_id,)
        try:
            for det, cls in cursor.execute(query, params):
                detector.append(int(det))
                classifier.append(int(cls))
        except sqlite3.OperationalError:
            continue  # Table or columns not migrated yet

    conn.close()
    return {"detector": detector, "classifier": classifier}


def compute_agreement(session_id: Optional[str] = None) -> Dict:
    """
    Computes corpus-level inter-rater agreement between the drift detector and
    the ATLAS classifier, with the full confusion matrix behind it.

    Person C uses this to tune the risk weights: a low Kappa with many
    detector-only flags means drift is firing on benign topic changes (w1 too
    hot), while many classifier-only flags mean real attacks are staying
    semantically close to the anchor and slipping past drift detection.
    """
    labels = load_rater_labels(session_id)
    detector = labels["detector"]
    classifier = labels["classifier"]
    total = len(detector)

    if total == 0:
        return {
            "session_id": session_id,
            "sample_size": 0,
            "cohens_kappa": None,
            "interpretation": "insufficient data",
            "note": (
                "No labelled turns yet. Labels are recorded from the first request "
                "served after this build — historical rows cannot be backfilled."
            ),
        }

    both = sum(1 for d, c in zip(detector, classifier) if d == 1 and c == 1)
    detector_only = sum(1 for d, c in zip(detector, classifier) if d == 1 and c == 0)
    classifier_only = sum(1 for d, c in zip(detector, classifier) if d == 0 and c == 1)
    neither = sum(1 for d, c in zip(detector, classifier) if d == 0 and c == 0)

    kappa = calculate_cohens_kappa(detector, classifier)
    observed_agreement = round((both + neither) / total, 4)

    return {
        "session_id": session_id,
        "sample_size": total,
        "cohens_kappa": kappa,
        "interpretation": interpret_kappa(kappa),
        "observed_agreement": observed_agreement,
        "confusion_matrix": {
            "both_flagged": both,
            "detector_only": detector_only,
            "classifier_only": classifier_only,
            "neither_flagged": neither,
        },
        "detector_flag_rate": round(sum(detector) / total, 4),
        "classifier_flag_rate": round(sum(classifier) / total, 4),
    }
