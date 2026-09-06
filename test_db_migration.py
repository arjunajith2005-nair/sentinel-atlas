"""
Test Case: Database Schema Migration — session/db.py
Run:  python test_db_migration.py
"""
from session.db import (
    init_db, save_turn, get_session_history,
    update_turn_scores, mark_false_positive, upgrade_schema,
)
import sqlite3
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DB_PATH = "sentinel_sessions.db"
TEST_SESSION = "test-raif-001"

# ── helpers ──
def count_columns():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(session_turns)")
    cols = [row[1] for row in cursor.fetchall()]
    conn.close()
    return cols

def cleanup():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"DELETE FROM session_turns WHERE session_id = '{TEST_SESSION}'")
    conn.commit()
    conn.close()

passed = 0
failed = 0

def check(name, condition):
    global passed, failed
    if condition:
        print(f"  ✅ PASS: {name}")
        passed += 1
    else:
        print(f"  ❌ FAIL: {name}")
        failed += 1


# ══════════════════════════════════════════
print("\n🧪 TEST 1: Schema has all 11 columns")
# ══════════════════════════════════════════
init_db()
cols = count_columns()
check("Total column count is 13", len(cols) == 13)
check("drift_score exists",       "drift_score" in cols)
check("risk_score exists",        "risk_score" in cols)
check("attack_technique exists",  "attack_technique" in cols)
check("attack_confidence exists", "attack_confidence" in cols)
check("false_positive exists",    "false_positive" in cols)


# ══════════════════════════════════════════
print("\n🧪 TEST 2: save_turn() — backward compatible (no new params)")
# ══════════════════════════════════════════
save_turn(TEST_SESSION, 1, "What is Python?", [0.1, 0.2, 0.3])
history = get_session_history(TEST_SESSION)
turn = history[0]
check("Turn saved",                    turn["turn_number"] == 1)
check("Message text correct",         turn["message_text"] == "What is Python?")
check("drift_score defaults to None", turn["drift_score"] is None)
check("risk_score defaults to None",  turn["risk_score"] is None)
check("false_positive defaults to False", turn["false_positive"] == False)


# ══════════════════════════════════════════
print("\n🧪 TEST 3: save_turn() — with drift_score")
# ══════════════════════════════════════════
save_turn(TEST_SESSION, 2, "Now tell me about hacking", [0.4, 0.5, 0.6], drift_score=0.72)
history = get_session_history(TEST_SESSION)
turn2 = history[1]
check("Turn 2 saved",       turn2["turn_number"] == 2)
check("drift_score = 0.72", turn2["drift_score"] == 0.72)


# ══════════════════════════════════════════
print("\n🧪 TEST 4: update_turn_scores() — add risk + attack after saving")
# ══════════════════════════════════════════
update_turn_scores(
    TEST_SESSION, 2,
    risk_score=0.88,
    attack_technique="AML.T0051 - Prompt Injection",
    attack_confidence=0.91,
)
history = get_session_history(TEST_SESSION)
turn2 = history[1]
check("risk_score updated to 0.88",    turn2["risk_score"] == 0.88)
check("attack_technique set",          turn2["attack_technique"] == "AML.T0051 - Prompt Injection")
check("attack_confidence set to 0.91", turn2["attack_confidence"] == 0.91)
check("drift_score unchanged at 0.72", turn2["drift_score"] == 0.72)  # wasn't overwritten


# ══════════════════════════════════════════
print("\n🧪 TEST 5: mark_false_positive()")
# ══════════════════════════════════════════
mark_false_positive(TEST_SESSION, 2, True)
history = get_session_history(TEST_SESSION)
check("false_positive = True after marking", history[1]["false_positive"] == True)

mark_false_positive(TEST_SESSION, 2, False)
history = get_session_history(TEST_SESSION)
check("false_positive = False after unmarking", history[1]["false_positive"] == False)


# ══════════════════════════════════════════
print("\n🧪 TEST 6: get_session_history() returns all fields")
# ══════════════════════════════════════════
history = get_session_history(TEST_SESSION)
required_keys = ["turn_number", "message_text", "embedding",
                 "drift_score", "risk_score", "attack_technique",
                 "attack_confidence", "false_positive"]
for key in required_keys:
    check(f"'{key}' present in history dict", key in history[0])


# ══════════════════════════════════════════
print("\n🧪 TEST 7: upgrade_schema() is safe to run twice")
# ══════════════════════════════════════════
try:
    upgrade_schema()
    upgrade_schema()  # should not crash
    check("Running upgrade_schema() twice doesn't crash", True)
except Exception as e:
    check(f"Running upgrade_schema() twice doesn't crash — got {e}", False)


# ── cleanup & summary ──
cleanup()
print(f"\n{'='*50}")
print(f"  Results: {passed} passed, {failed} failed out of {passed + failed}")
if failed == 0:
    print("  🎉 ALL TESTS PASSED!")
else:
    print("  ⚠️  Some tests failed — check above")
print(f"{'='*50}\n")
