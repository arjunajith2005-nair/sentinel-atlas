import json
import logging
from datetime import datetime

logging.basicConfig(
    filename="sentinel_audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def log_security_event(event_type: str, session_id: str, details: dict):
    mitre_map = {
        "rule_engine_injection": {"id": "AML.T0051", "name": "LLM Direct Prompt Injection"},
        "rule_engine_secret": {"id": "AML.T0024", "name": "Exfiltration via LLM Inference"},
        "vector_drift": {"id": "AML.T0051.001", "name": "LLM Context Manipulation"}
    }
    mitre_info = mitre_map.get(event_type, {"id": "AML.T0000", "name": "Unknown Threat"})
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "session_id": session_id,
        "event_type": event_type,
        "mitre_atlas": mitre_info,
        "details": details
    }
    logging.info(json.dumps(log_entry))