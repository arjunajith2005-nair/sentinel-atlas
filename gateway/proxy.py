import httpx
import os

# Pointing to local Ollama running on your Windows machine
TARGET_LLM_URL = os.getenv("TARGET_LLM_URL", "http://localhost:11434/api/generate")

async def forward_to_llm(user_message: str) -> str:
    """
    Forwards user input to the local Ollama instance.
    Includes failover handling so your app won't crash if Ollama drops out.
    """
    payload = {
        "model": "llama3.2:1b",  # Using 1B lightweight model for Core i3
        "prompt": user_message,
        "stream": False
    }

    try:
        # 60s timeout accommodates CPU-only inference on i3
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(TARGET_LLM_URL, json=payload)
            response.raise_for_status()
            
            data = response.json()
            return data.get("response", "No response generated.")

    except Exception as e:
        # FAILOVER LOGIC: Return fallback message if local model fails
        print(f"[FAILOVER TRIGGERED] Proxy error: {str(e)}")
        return "System failover: Proxy caught an error, but kept the server alive."