import re

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)disregard\s+(all\s+)?prior\s+prompts",
    r"(?i)system\s+prompt\s+override",
    r"(?i)you\s+are\s+now\s+in\s+developer\s+mode",
    r"(?i)jailbreak",
]

SECRET_PATTERNS = [
    r"(?i)AKIA[0-9A-Z]{16}",                             # AWS Access Key ID
    r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", # JWT Token
    r"sk-[a-zA-Z0-9]{20,}",                              # API Keys (OpenAI/Generic)
]

def evaluate_security_rules(prompt: str) -> dict:
    # 1. Check Prompt Injection
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, prompt):
            return {
                "flagged": True,
                "reason": "Security Policy Triggered: Prompt injection attempt detected."
            }

    # 2. Check Secret/Token Exposure
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, prompt):
            return {
                "flagged": True,
                "reason": "Security Policy Triggered: High-entropy secret key or API token detected in prompt."
            }

    return {"flagged": False, "reason": None}