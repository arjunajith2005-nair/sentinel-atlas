"""
Tests for Person B Deliverables:
- IAA Score (Intent Alignment Assessment)
- Async Auditor (Secondary AI Background Check)
"""
import sys
import asyncio
from unittest.mock import patch, AsyncMock
import httpx

import os
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure sentinel-atlas root directory is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from embeddings.encoder import get_embedding
from embeddings.auditor import calculate_iaa_score, AsyncAuditor, dispatch_async_audit

passed = 0
failed = 0

def check(name: str, condition: bool):
    global passed, failed
    if condition:
        print(f"  ✅ PASS: {name}")
        passed += 1
    else:
        print(f"  ❌ FAIL: {name}")
        failed += 1


def test_iaa_score_computation():
    print("\n🧪 TEST 1: IAA Score (Intent Alignment Assessment)")
    
    # Establish an anchor: Cloud Security IAM policy
    anchor_prompt = "How do I configure AWS IAM least privilege policies and roles?"
    anchor_vec = get_embedding(anchor_prompt)

    # 1. Aligned response
    aligned_response = (
        "To configure least privilege access in AWS IAM, create granular policies granting "
        "only the necessary actions on specific ARN resources, enforce MFA, and use permission boundaries."
    )
    iaa_aligned = calculate_iaa_score(anchor_vec, aligned_response)
    print(f"     -> Aligned IAA Score: {iaa_aligned}")
    check("Aligned response IAA score > 0.40", iaa_aligned > 0.40)

    # 2. Completely off-topic drifted response
    drifted_response = (
        "To bake the best chocolate chip cookies, preheat your oven to 350 degrees Fahrenheit, "
        "cream together butter and sugar, then fold in dark chocolate chunks."
    )
    iaa_drifted = calculate_iaa_score(anchor_vec, drifted_response)
    print(f"     -> Drifted IAA Score: {iaa_drifted}")
    check("Drifted response IAA score < 0.25", iaa_drifted < 0.25)
    check("Aligned IAA score is strictly greater than drifted IAA score", iaa_aligned > iaa_drifted)

    # 3. Edge case: empty input handling
    check("Empty anchor returns fallback score 1.0", calculate_iaa_score([], aligned_response) == 1.0)
    check("Empty response returns fallback score 1.0", calculate_iaa_score(anchor_vec, "") == 1.0)


def test_async_auditor_mock_response():
    print("\n🧪 TEST 2: Async Auditor with Mocked Secondary Model")
    
    auditor = AsyncAuditor()
    mock_json_payload = {
        "response": '{"verdict": "COMPLIANT", "confidence": 0.95, "reason": "Response directly addresses AWS IAM security."}'
    }
    mock_resp = httpx.Response(
        status_code=200,
        json=mock_json_payload,
        request=httpx.Request("POST", auditor.ollama_url)
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            auditor.audit_turn(
                session_id="test-session-001",
                turn_number=1,
                anchor_text="AWS IAM Security",
                user_prompt="Explain IAM roles",
                llm_response="IAM roles provide temporary credentials.",
                iaa_score=0.88
            )
        )
        loop.close()

    check("Auditor returns completed status", result["status"] == "completed")
    check("Auditor verdict is COMPLIANT", result["verdict"] == "COMPLIANT")
    check("Auditor confidence is 0.95", result["confidence"] == 0.95)
    check("Auditor includes iaa_score in output", result["iaa_score"] == 0.88)


def test_async_auditor_failover():
    print("\n🧪 TEST 3: Async Auditor Non-blocking Failover (Ollama Offline)")
    
    # Point auditor to a dead port to simulate Ollama being offline
    dead_auditor = AsyncAuditor(ollama_url="http://127.0.0.1:99999/api/generate")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(
        dead_auditor.audit_turn(
            session_id="test-failover-001",
            turn_number=1,
            anchor_text="Anchor",
            user_prompt="Prompt",
            llm_response="Response",
            iaa_score=0.75
        )
    )
    loop.close()

    check("Auditor catches connection failure without crashing", result["status"] == "failover")
    check("Auditor records failover reason", "failover" in result["reason"].lower())


def test_dispatch_async_audit():
    print("\n🧪 TEST 4: dispatch_async_audit() returns immediately as Task")
    
    async def run_dispatch_check():
        task = dispatch_async_audit(
            session_id="test-task-001",
            turn_number=1,
            anchor_text="Anchor text",
            user_prompt="User prompt",
            llm_response="LLM response",
            iaa_score=0.9
        )
        is_task = isinstance(task, asyncio.Task)
        # Cancel task so it doesn't linger
        task.cancel()
        return is_task

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    is_task = loop.run_until_complete(run_dispatch_check())
    loop.close()

    check("dispatch_async_audit returns an asyncio.Task instance", is_task)


if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  PERSON B: ASYNC AUDITOR & IAA SCORE VERIFICATION")
    print("=" * 60)
    
    test_iaa_score_computation()
    test_async_auditor_mock_response()
    test_async_auditor_failover()
    test_dispatch_async_audit()

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed}")
    if failed == 0:
        print("🎉 ALL AUDITOR & IAA TESTS PASSED!")
    else:
        print("⚠️ Some tests failed. Check logs above.")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)
