"""
Sentinel ATLAS: Dual-Agent Consensus Verdict Parser Suite

Regression cover for intelligence/bridge.py::parse_auditor_verdict.

Context: the Auditor Agent's reply used to be substring-searched for
"MISALIGNED" / "JAILBREAK" / "ATTACK". In a security assistant those words show
up constantly in correct answers, and a 135M auditor frequently ignores the
reply format altogether — both produced false MISALIGNED verdicts, which block
the user's NEXT turn and therefore look unrelated to whatever caused them.
"""

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from intelligence.bridge import parse_auditor_verdict

passed = 0
failed = 0


def check(label, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✅ PASS: {label}")
    else:
        failed += 1
        print(f"  ❌ FAIL: {label}")


def verdict(raw):
    return parse_auditor_verdict(raw)[0]


print("=" * 75)
print("  DUAL-AGENT CONSENSUS VERDICT PARSER SUITE")
print("=" * 75)

# -------------------------------------------------------------
print("\n🧪 TEST 1: Well-formed verdicts are honoured")
# -------------------------------------------------------------
check("'ALIGNED: reason' -> ALIGNED",
      verdict("ALIGNED: response stays on the IAM security topic.") == "ALIGNED")
check("'MISALIGNED: reason' -> MISALIGNED",
      verdict("MISALIGNED: the worker leaked its system prompt.") == "MISALIGNED")
check("Bare 'aligned' token -> ALIGNED", verdict("aligned") == "ALIGNED")
check("Bare 'MISALIGNED' token -> MISALIGNED", verdict("MISALIGNED") == "MISALIGNED")

# -------------------------------------------------------------
print("\n🧪 TEST 2: Formatting noise around the verdict is tolerated")
# -------------------------------------------------------------
check("'Verdict:' prefix stripped",
      verdict("Verdict: MISALIGNED - assisted an injection attempt") == "MISALIGNED")
check("Markdown bold stripped", verdict("**MISALIGNED**: leaked prompt") == "MISALIGNED")
check("Quotes stripped", verdict('"ALIGNED": fine') == "ALIGNED")
check("Hyphen/space token form", verdict("  mis-aligned : spaced") == "MISALIGNED")
check("Leading blank lines skipped", verdict("\n\n  ALIGNED: ok") == "ALIGNED")

# -------------------------------------------------------------
print("\n🧪 TEST 3: Security vocabulary no longer triggers false MISALIGNED")
# -------------------------------------------------------------
# Each of these would have been flagged MISALIGNED by the old substring match.
check("'jailbreak' inside an ALIGNED reason stays ALIGNED",
      verdict("ALIGNED: the answer discusses jailbreak defences, which is on-topic.") == "ALIGNED")
check("'attack' inside an ALIGNED reason stays ALIGNED",
      verdict("ALIGNED: explains how to defend against a prompt injection attack.") == "ALIGNED")
check("'misaligned' appearing mid-sentence does not flag",
      verdict("ALIGNED: nothing here is misaligned with the session goal.") == "ALIGNED")

# -------------------------------------------------------------
print("\n🧪 TEST 4: Unusable replies are UNPARSEABLE, not MISALIGNED")
# -------------------------------------------------------------
# The literal output observed from smollm:135m in a live run:
observed = ("Here is the code that implements the policies:\n"
            "```python\ndef verify_ABAC_attack():\n    pass\n```")
check("Observed live failure -> UNPARSEABLE", verdict(observed) == "UNPARSEABLE")
check("Prose mentioning 'attack' -> UNPARSEABLE",
      verdict("The response explains how to defend against an attack.") == "UNPARSEABLE")
check("Empty response -> UNPARSEABLE", verdict("") == "UNPARSEABLE")
check("Whitespace-only response -> UNPARSEABLE", verdict("   \n  ") == "UNPARSEABLE")
check("Refusal -> UNPARSEABLE", verdict("I cannot determine this.") == "UNPARSEABLE")
check("UNPARSEABLE is never MISALIGNED",
      all(verdict(r) != "MISALIGNED"
          for r in [observed, "", "   ", "I cannot determine this.",
                    "The attack was blocked.", "jailbreak"]))

# -------------------------------------------------------------
print("\n🧪 TEST 5: Reasons are populated and bounded")
# -------------------------------------------------------------
v, r = parse_auditor_verdict("MISALIGNED: " + "x" * 500)
check("Reason truncated to 150 chars", len(r) <= 150)
v, r = parse_auditor_verdict("ALIGNED")
check("Bare verdict still gets a default reason", bool(r.strip()))
v, r = parse_auditor_verdict("total nonsense here")
check("UNPARSEABLE reason quotes the offending reply", "did not begin with a verdict" in r)

print("\n" + "=" * 75)
print(f"  Results: {passed} passed, {failed} failed out of {passed + failed}")
print("  🎉 ALL CONSENSUS PARSER TESTS PASSED!" if failed == 0 else "  ⚠️ Some tests failed.")
print("=" * 75)

sys.exit(0 if failed == 0 else 1)
