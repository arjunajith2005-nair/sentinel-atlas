import httpx
import os

TARGET_LLM_URL = "http://127.0.0.1:11434/api/generate"

# Shared persistent async client with keep-alive connection pooling
_client: httpx.AsyncClient | None = None

def get_http_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=45.0,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
        )
    return _client

async def forward_to_llm(user_message: str) -> str:
    payload = {
        "model": "smollm:135m",
        "prompt": user_message,
        "stream": False,
        "keep_alive": "30m",
        "options": {
            "num_predict": 180,
            "temperature": 0.6,
            "top_k": 40,
            "top_p": 0.9,
            "repeat_penalty": 1.15
        }
    }
    
    client = get_http_client()
    try:
        response = await client.post(TARGET_LLM_URL, json=payload)
        if response.status_code == 200:
            return response.json().get("response", "No response text.")
        return f"LLM Error: Status {response.status_code}"
    except Exception as e:
        # Captures exact exception type if connection fails
        return f"System failover: Could not reach Ollama. ({type(e).__name__}: {str(e)})"