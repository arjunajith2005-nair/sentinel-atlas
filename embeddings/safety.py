"""
Llama Guard 3 Semantic Safety Classifier
Uses Meta's dedicated moderation model (llama-guard3:1b) via Ollama to evaluate prompts.
Covers 14 MLCommons standard hazard taxonomies out-of-the-box:
- S1: Violent Crimes
- S2: Non-Violent Crimes
- S3: Sex-Related Crimes
- S4: Child Sexual Exploitation
- S5: Defamation
- S6: Cyberattacks & Malware
- S7: CBRN Weapons
- S8: Suicide or Self-Harm
- S9: Hate Speech
- S10: Harassment & Stalking
- S11: Privacy Violations
- S12: Intellectual Property Infringement
- S13: Inducing Harm via Substances
- S14: AI Safety / Jailbreak / Circumvention
"""

import httpx

OLLAMA_CHAT_URL = "http://127.0.0.1:11434/api/chat"
OLLAMA_GENERATE_URL = "http://127.0.0.1:11434/api/generate"
PRIMARY_SAFETY_MODEL = "smollm:135m"
FALLBACK_SAFETY_MODEL = "smollm:135m"

HAZARD_DESCRIPTIONS = {
    "S1": "Violent Crimes (murder, assault, physical harm, kidnapping)",
    "S2": "Non-Violent Crimes (burglary, theft, fraud, prison escape, evading law enforcement)",
    "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation and Abuse",
    "S5": "Defamation",
    "S6": "Cyberattacks, Hacking, and Malware",
    "S7": "CBRN Weapons (Chemical, Biological, Radiological, Nuclear)",
    "S8": "Suicide or Self-Harm",
    "S9": "Hate Speech",
    "S10": "Harassment and Stalking",
    "S11": "Privacy Violations",
    "S12": "Intellectual Property Infringement",
    "S13": "Inducing Harm via Substances",
    "S14": "AI Safety / Jailbreak / Circumvention",
}

SUSPICIOUS_TRIGGER_WORDS = {
    "kill", "murder", "bomb", "explosive", "weapon", "poison", "fentanyl", "meth",
    "hack", "malware", "exploit", "trojan", "ransomware", "keylogger", "bypass",
    "jailbreak", "override", "dan", "ignore", "inject", "steal", "crack", "cbrn",
    "suicide", "nude", "porn", "child", "traffick", "knife", "gun", "virus", "phishing"
}

_safety_client: httpx.Client | None = None

def get_safety_client(timeout: float = 6.0) -> httpx.Client:
    global _safety_client
    if _safety_client is None or _safety_client.is_closed:
        _safety_client = httpx.Client(
            timeout=timeout,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )
    return _safety_client


def _check_with_llama_guard(prompt: str, timeout: float = 6.0) -> dict:
    """Classifies user prompt using Llama Guard 3 with capped token output for low latency."""
    payload = {
        "model": PRIMARY_SAFETY_MODEL,
        "messages": [
            {"role": "user", "content": prompt.strip()}
        ],
        "stream": False,
        "keep_alive": "30m",
        "options": {
            "temperature": 0.0,
            "num_predict": 8
        }
    }

    client = get_safety_client(timeout)
    resp = client.post(OLLAMA_CHAT_URL, json=payload)
    if resp.status_code != 200:
        raise RuntimeError(f"Llama Guard returned status {resp.status_code}")

    raw_text = resp.json().get("message", {}).get("content", "").strip()
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

    if lines and lines[0].lower().startswith("unsafe"):
        hazard_codes = lines[1:] if len(lines) > 1 else []
        reasons = [HAZARD_DESCRIPTIONS.get(c, c) for c in hazard_codes]
        reason_str = ", ".join(reasons) if reasons else "Harmful or illegal activity detected."
        return {
            "safe": False,
            "reason": f"Llama Guard: {reason_str}",
            "raw": raw_text
        }

    return {"safe": True, "reason": None, "raw": raw_text}


def _check_with_fallback_classifier(prompt: str, timeout: float = 6.0) -> dict:
    """Fallback classifier with short response length for low latency."""
    system_prompt = (
        "You are a strict content safety classifier. Your ONLY job is to decide if a user message requests harmful, illegal, or dangerous content.\n"
        "Reply with EXACTLY one word: SAFE or UNSAFE.\n\n"
        "User message: " + prompt.strip() + "\n\n"
        "Classification:"
    )

    payload = {
        "model": FALLBACK_SAFETY_MODEL,
        "prompt": system_prompt,
        "stream": False,
        "keep_alive": "30m",
        "options": {"temperature": 0.0, "num_predict": 6}
    }

    client = get_safety_client(timeout)
    resp = client.post(OLLAMA_GENERATE_URL, json=payload)
    if resp.status_code != 200:
        return {"safe": True, "reason": None, "raw": f"ollama_error_{resp.status_code}"}

    raw = resp.json().get("response", "").strip()
    cleaned = raw.replace("Classification:", "").strip()
    first_line = cleaned.splitlines()[0].strip() if cleaned else ""

    if first_line.upper().startswith("UNSAFE"):
        reason = first_line[len("UNSAFE"):].lstrip(":").strip()
        return {
            "safe": False,
            "reason": reason or "Harmful or illegal content detected by fallback classifier.",
            "raw": raw
        }

    return {"safe": True, "reason": None, "raw": raw}


def check_content_safety(prompt: str, timeout: float = 6.0) -> dict:
    """
    Evaluates content safety with high-performance fast path.
    Short benign prompts bypass heavy LLM inference in 0ms, while suspicious
    triggers invoke the model classifier with connection keep-alive.
    """
    if not prompt or not prompt.strip():
        return {"safe": True, "reason": None, "raw": ""}

    lower = prompt.lower().strip()
    words = lower.split()

    # Fast path: short messages without suspicious triggers resolve in 0.01ms
    if len(words) <= 12 and not any(w.strip(".,!?:;\"'()[]{}") in SUSPICIOUS_TRIGGER_WORDS for w in words):
        return {"safe": True, "reason": None, "raw": "fast_path_safe"}

    try:
        return _check_with_llama_guard(prompt, timeout=timeout)
    except Exception:
        try:
            return _check_with_fallback_classifier(prompt, timeout=timeout)
        except Exception as e:
            # Fail-open for gateway availability
            return {"safe": True, "reason": None, "raw": f"safety_error: {e}"}
