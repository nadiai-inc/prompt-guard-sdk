"""
NadiAI Prompt Guard - FastAPI Integration Example
=================================================
Shows how to integrate the SDK with a FastAPI application.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from nadiai_prompt_guard import PromptGuard, ScanResult

# Initialize FastAPI app
app = FastAPI(title="LLM API with Security Scanning")

# Initialize PromptGuard once at startup (loads models)
guard = PromptGuard(
    enable_injection=True,
    enable_harmful=True,
    enable_pii=True,
    injection_threshold=0.5,
    harmful_threshold=0.5,
    block_threshold=0.7,
)


class ChatRequest(BaseModel):
    message: str
    user_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    security_passed: bool
    risk_score: float


class ScanRequest(BaseModel):
    text: str


class ScanResponse(BaseModel):
    blocked: bool
    risk_score: float
    threats: List[dict]
    scan_duration_ms: float


@app.on_event("startup")
async def startup():
    """Pre-load models on startup for faster first request"""
    print("Loading security models...")
    guard.load_models()
    print("Models loaded!")


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Chat endpoint with built-in security scanning.
    Scans user input before processing.
    """
    # Scan the user's message
    scan_result = guard.scan(request.message)

    if scan_result.blocked:
        # Log the threat for monitoring
        print(f"Blocked message from user {request.user_id}: {scan_result.threats}")

        raise HTTPException(
            status_code=400,
            detail={
                "error": "Message blocked by security scan",
                "risk_score": scan_result.risk_score,
                "threats": [t.to_dict() for t in scan_result.threats]
            }
        )

    # Process the message (your LLM call would go here)
    llm_response = f"Echo: {request.message}"  # Replace with actual LLM call

    return ChatResponse(
        response=llm_response,
        security_passed=True,
        risk_score=scan_result.risk_score
    )


@app.post("/scan", response_model=ScanResponse)
async def scan_text(request: ScanRequest):
    """
    Direct scanning endpoint for testing or batch processing.
    """
    result = guard.scan(request.text)

    return ScanResponse(
        blocked=result.blocked,
        risk_score=result.risk_score,
        threats=[t.to_dict() for t in result.threats],
        scan_duration_ms=result.scan_duration_ms
    )


@app.get("/health")
async def health():
    """Health check endpoint"""
    status = guard.get_status()
    return {
        "status": "healthy",
        "scanner": status
    }


# Run with: uvicorn fastapi_integration:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
