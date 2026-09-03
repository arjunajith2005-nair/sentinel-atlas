from fastapi import FastAPI
from pydantic import BaseModel
from gateway.proxy import forward_to_llm

app = FastAPI(
    title="Sentinel ATLAS - Reverse Proxy",
    description="Gateway server running on Windows i3 setup."
)

class ChatRequest(BaseModel):
    message: str

@app.get("/")
def health_check():
    return {"status": "Sentinel ATLAS Active"}

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    llm_response = await forward_to_llm(request.message)
    return {
        "status": "success",
        "user_message": request.message,
        "llm_response": llm_response
    }

if __name__ == "__main__":
    import uvicorn
    # Starts server on http://127.0.0.1:8000
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)