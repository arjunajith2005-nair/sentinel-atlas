import httpx
import os

# Point to local Ollama API
TARGET_LLM_URL = os.getenv("TARGET_LLM_URL", "http://127.0.0.1:11434/api/generate")

async def forward_to_llm(user_message: str) -> str:
    """
    Forwards user prompt to local Ollama instance (llama3.2:1b).
    Includes extended timeout for model inference.
    """
    payload = {
        "model": "llama3.2:1b",
        "prompt": user_message,
        "stream": False
    }
    
    # Set 60-second timeout to allow local LLM inference time
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.post(TARGET_LLM_URL, json=payload)
            if response.status_code == 200:
                data = response.json()
                return data.get("response", "No response text received from LLM.")
            else:
                return f"LLM Error: Received status code {response.status_code}"
        except Exception as e:
            return f"System failover: Could not reach Ollama at {TARGET_LLM_URL}. Error: {str(e)}"