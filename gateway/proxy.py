import httpx
import os

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
TARGET_LLM_URL = OLLAMA_URL
MODEL_NAME = os.getenv("MODEL_NAME", "llama3.2:1b")

async def forward_to_llm(user_message: str) -> str:
    payload = {
        "model": MODEL_NAME,
        "prompt": user_message,
        "stream": False  # Crucial to return a single JSON object instead of streaming
    }

    
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.post(TARGET_LLM_URL, json=payload)
            if response.status_code == 200:
                return response.json().get("response", "No response text.")
            return f"LLM Error: Status {response.status_code}"
        except Exception as e:
            # Captures exact exception type if connection fails
            return f"System failover: Could not reach Ollama. ({type(e).__name__}: {str(e)})"