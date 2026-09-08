"""
Detection Engine Package for Sentinel ATLAS
Includes Topic Engine, Drift Engine, Threat Persistence,
Prompt Sensitivity, Intent-Action Alignment, and Composite Risk.
"""

from detection.topic_engine import TopicEngine, detect_topic_change
from detection.drift import SemanticDriftEngine, calculate_semantic_drift
from detection.sensitivity import calculate_prompt_sensitivity
from detection.persistence import calculate_threat_persistence
from detection.risk import calculate_transparent_risk, DEFAULT_CONFIG_WEIGHTS, determine_action
from detection.alignment import calculate_intent_action_alignment

__all__ = [
    "TopicEngine",
    "detect_topic_change",
    "SemanticDriftEngine",
    "calculate_semantic_drift",
    "calculate_prompt_sensitivity",
    "calculate_threat_persistence",
    "calculate_transparent_risk",
    "DEFAULT_CONFIG_WEIGHTS",
    "determine_action",
    "calculate_intent_action_alignment",
]
