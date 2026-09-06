# Sentinel ATLAS Intelligence Package
# Person C - Nandu Suraj (The Analyst)

"""
Sentinel ATLAS Threat Intelligence and Risk Scoring Engine

Exposes:
- calculate_composite_risk: High-level pipeline hook for composite risk calculation
- classify_threat / classify_prompt: Semantic threat classifier for MITRE ATLAS techniques
- SEVERITY_WEIGHTS: Mapping of MITRE ATLAS techniques to severity values [0.0, 1.0]
- get_technique_severity: Severity lookup helper with sub-technique fallback
- match_atlas_technique: Direct ChromaDB vector matcher
- build_atlas_index: Builder for the persistent ChromaDB collection
"""

from intelligence.risk import (
    calculate_composite_risk,
    compute_history_penalty,
    determine_risk_tier,
    DEFAULT_WEIGHTS,
    RISK_TIERS,
)

from intelligence.classifier import (
    classify_threat,
    classify_prompt,
    SemanticThreatClassifier,
)

from intelligence.atlas_data import (
    SEVERITY_WEIGHTS,
    get_technique_severity,
    get_atlas_techniques,
    get_technique_by_id,
    get_technique_dict,
)

from intelligence.atlas_index import (
    match_atlas_technique,
    build_atlas_index,
    get_atlas_collection,
)

__all__ = [
    "calculate_composite_risk",
    "compute_history_penalty",
    "determine_risk_tier",
    "DEFAULT_WEIGHTS",
    "RISK_TIERS",
    "classify_threat",
    "classify_prompt",
    "SemanticThreatClassifier",
    "SEVERITY_WEIGHTS",
    "get_technique_severity",
    "get_atlas_techniques",
    "get_technique_by_id",
    "get_technique_dict",
    "match_atlas_technique",
    "build_atlas_index",
    "get_atlas_collection",
]
