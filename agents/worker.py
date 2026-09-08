"""
Worker Agent Abstraction
Section 15 — Sentinel ATLAS

Represents the target AI agent receiving user prompts and producing
text responses or proposed tool actions.
"""

import httpx
from typing import Dict, List, Optional, Any
from gateway.proxy import OLLAMA_URL, MODEL_NAME


class WorkerAgent:
    """Pluggable Worker Agent abstraction."""

    def __init__(self, ollama_url: str = OLLAMA_URL, model_name: str = MODEL_NAME, timeout: float = 30.0):
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.timeout = timeout

    async def generate_response(
        self,
        prompt: str,
        system_context: Optional[str] = None,
        conversation_history: Optional[List[Dict]] = None,
        available_tools: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Generates a response or proposed action.
        Returns:
            Dict: {
                "text": str,
                "tool_call": Optional[Dict],
                "model": str,
                "status": str
            }
        """
        messages = []
        if system_context:
            messages.append({"role": "system", "content": system_context})
            
        if conversation_history:
            for turn in conversation_history[-4:]:
                messages.append({"role": "user", "content": turn.get("message_text", "")})
                resp = turn.get("llm_response")
                if resp:
                    messages.append({"role": "assistant", "content": resp})

        messages.append({"role": "user", "content": prompt})

        # Try live Ollama inference
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3}
                }
                res = await client.post(self.ollama_url, json=payload)
                if res.status_code == 200:
                    text = res.json().get("response", "").strip()
                    return {
                        "text": text or "Response generated successfully.",
                        "tool_call": None,
                        "model": self.model_name,
                        "status": "success"
                    }
        except Exception:
            pass

        # Clean deterministic fallback for development / offline environments
        fallback_text = (
            f"I have processed your request regarding '{prompt[:50]}...'. "
            "Here is the relevant analytical output adhering to secure gateway guidelines."
        )
        return {
            "text": fallback_text,
            "tool_call": None,
            "model": f"{self.model_name}-offline",
            "status": "fallback"
        }
