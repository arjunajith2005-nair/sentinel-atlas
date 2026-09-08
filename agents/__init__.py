"""
Agents Package for Sentinel ATLAS
Includes Worker Agent (target model) and Auditor Agent (security evaluator).
"""

from agents.worker import WorkerAgent
from agents.auditor import AuditorAgent

__all__ = ["WorkerAgent", "AuditorAgent"]
