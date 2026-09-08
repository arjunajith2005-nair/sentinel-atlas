import sqlite3
import json

DB_PATH = "sentinel_sessions.db"


def init_db():
    """
    Initializes SQLite tables for tracking sessions, messages, topics,
    risk events, atlas matches, alerts, auditor decisions, overrides,
    and telemetry per Section 26 of the Sentinel ATLAS specification.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Sessions table (session-level state)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            status TEXT DEFAULT 'ACTIVE',
            session_risk REAL DEFAULT 0.0,
            intent_anchor TEXT DEFAULT '[]',
            current_topic_id TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Main conversation tracking table (message-level state)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS session_turns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            turn_number INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            embedding TEXT NOT NULL,
            similarity_score REAL DEFAULT 1.0,
            llm_response TEXT DEFAULT '',
            drift_score REAL DEFAULT NULL,
            risk_score REAL DEFAULT NULL,
            attack_technique TEXT DEFAULT NULL,
            attack_confidence REAL DEFAULT NULL,
            topic_id TEXT DEFAULT NULL,
            topic_change_score REAL DEFAULT 0.0,
            false_positive INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Topics table (topic segmentation and local anchors)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS topics (
            topic_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            topic_anchor TEXT NOT NULL,
            topic_name TEXT DEFAULT 'General',
            first_turn INTEGER DEFAULT 1,
            last_turn INTEGER DEFAULT 1,
            is_benign INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Risk events table (transparent breakdown per turn)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            turn_number INTEGER NOT NULL,
            risk_score REAL NOT NULL,
            components TEXT NOT NULL,
            decision TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ATLAS matches table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS atlas_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            turn_number INTEGER NOT NULL,
            technique_id TEXT,
            technique_name TEXT,
            confidence REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            turn_number INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Auditor decisions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auditor_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            turn_number INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            confidence REAL,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Overrides table (analyst human-in-the-loop actions)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            analyst_id TEXT DEFAULT 'SOC_ANALYST',
            reason TEXT NOT NULL,
            previous_status TEXT DEFAULT 'REVOKED',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Security events table for tracking blocked prompts and drift incidents (legacy compatible)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            turn_number INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            similarity_score REAL NOT NULL,
            threshold REAL NOT NULL,
            reason TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Dual-Agent consensus events table (ATLAS Bridge Worker vs Auditor)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS consensus_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            turn_number INTEGER NOT NULL,
            iaa_score REAL NOT NULL,
            auditor_verdict TEXT NOT NULL,
            auditor_reason TEXT,
            enforced INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

    # Upgrade existing databases that have the old schema
    upgrade_schema()


def upgrade_schema():
    """
    Adds new columns to an existing session_turns table if they don't exist.
    Safe to run multiple times — skips columns that are already present.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check which columns already exist in session_turns
    cursor.execute("PRAGMA table_info(session_turns)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    new_columns = [
        ("similarity_score", "REAL DEFAULT 1.0"),
        ("llm_response", "TEXT DEFAULT ''"),
        ("drift_score", "REAL DEFAULT NULL"),
        ("risk_score", "REAL DEFAULT NULL"),
        ("attack_technique", "TEXT DEFAULT NULL"),
        ("attack_confidence", "REAL DEFAULT NULL"),
        ("topic_id", "TEXT DEFAULT NULL"),
        ("topic_change_score", "REAL DEFAULT 0.0"),
        ("false_positive", "INTEGER DEFAULT 0"),
    ]

    for col_name, col_type in new_columns:
        if col_name not in existing_columns:
            cursor.execute(
                f"ALTER TABLE session_turns ADD COLUMN {col_name} {col_type}"
            )

    conn.commit()
    conn.close()


def save_turn(
    session_id: str,
    turn_number: int,
    message_text: str,
    embedding: list[float],
    similarity_score: float = 1.0,
    llm_response: str = "",
    drift_score: float | None = None,
    risk_score: float | None = None,
    attack_technique: str | None = None,
    attack_confidence: float | None = None,
):
    """
    Saves a conversation turn with its vector embedding, similarity score,
    LLM response, and optional security scores.
    Backward-compatible: existing callers can omit the new parameters.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    embedding_json = json.dumps(embedding)

    cursor.execute("""
        INSERT INTO session_turns
            (session_id, turn_number, message_text, embedding,
             similarity_score, llm_response,
             drift_score, risk_score, attack_technique, attack_confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session_id, turn_number, message_text, embedding_json,
        similarity_score, llm_response,
        drift_score, risk_score, attack_technique, attack_confidence,
    ))

    conn.commit()
    conn.close()


def save_blocked_turn(session_id: str, turn_number: int, message_text: str, similarity_score: float, threshold: float = 0.35, reason: str = "Intent drift detected"):
    """
    Logs an intercepted/blocked attempt to the security_events audit table.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO security_events (session_id, turn_number, message_text, similarity_score, threshold, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session_id, turn_number, message_text, similarity_score, threshold, reason))
    conn.commit()
    conn.close()


def update_turn_scores(
    session_id: str,
    turn_number: int,
    drift_score: float | None = None,
    risk_score: float | None = None,
    attack_technique: str | None = None,
    attack_confidence: float | None = None,
):
    """
    Updates security scores on an already-saved turn.
    Only overwrites fields that are explicitly passed (not None).
    Used by Person C (Analyst) to write risk/attack data after the turn is saved.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    updates = []
    values = []

    if drift_score is not None:
        updates.append("drift_score = ?")
        values.append(drift_score)
    if risk_score is not None:
        updates.append("risk_score = ?")
        values.append(risk_score)
    if attack_technique is not None:
        updates.append("attack_technique = ?")
        values.append(attack_technique)
    if attack_confidence is not None:
        updates.append("attack_confidence = ?")
        values.append(attack_confidence)

    if not updates:
        conn.close()
        return

    values.extend([session_id, turn_number])
    cursor.execute(
        f"UPDATE session_turns SET {', '.join(updates)} "
        f"WHERE session_id = ? AND turn_number = ?",
        values,
    )

    conn.commit()
    conn.close()


def mark_false_positive(session_id: str, turn_number: int, is_false_positive: bool = True):
    """
    Marks (or unmarks) a turn as a false positive.
    Used by Person D's dashboard when a human overrides a false alarm.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE session_turns
        SET false_positive = ?
        WHERE session_id = ? AND turn_number = ?
    """, (1 if is_false_positive else 0, session_id, turn_number))

    conn.commit()
    conn.close()


def get_session_history(session_id: str):
    """
    Retrieves all past turns for a specific session ID,
    including security telemetry fields.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT turn_number, message_text, embedding,
               drift_score, risk_score, attack_technique,
               attack_confidence, false_positive
        FROM session_turns
        WHERE session_id = ? ORDER BY turn_number ASC
    """, (session_id,))
    rows = cursor.fetchall()
    conn.close()

    history = []
    for (turn_num, text, emb_str, drift, risk,
         technique, confidence, fp) in rows:
        history.append({
            "turn_number": turn_num,
            "message_text": text,
            "embedding": json.loads(emb_str),
            "drift_score": drift,
            "risk_score": risk,
            "attack_technique": technique,
            "attack_confidence": confidence,
            "false_positive": bool(fp),
        })
    return history


def get_all_sessions():
    """
    Returns a list of distinct session IDs and turn counts for dashboard navigation.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT session_id, COUNT(*) as turn_count, MAX(timestamp) as last_activity
        FROM session_turns
        GROUP BY session_id
        ORDER BY last_activity DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_security_events(session_id: str = None):
    """
    Retrieves security incidents, optionally filtered by session_id.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if session_id:
        cursor.execute("""
            SELECT id, session_id, turn_number, message_text, similarity_score, threshold, reason, timestamp
            FROM security_events WHERE session_id = ? ORDER BY timestamp DESC
        """, (session_id,))
    else:
        cursor.execute("""
            SELECT id, session_id, turn_number, message_text, similarity_score, threshold, reason, timestamp
            FROM security_events ORDER BY timestamp DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def save_consensus_event(session_id: str, turn_number: int, iaa_score: float, auditor_verdict: str, auditor_reason: str):
    """
    Logs an Intent-Action Alignment (IAA) dual-agent evaluation result.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO consensus_events (session_id, turn_number, iaa_score, auditor_verdict, auditor_reason, enforced)
        VALUES (?, ?, ?, ?, ?, 0)
    """, (session_id, turn_number, iaa_score, auditor_verdict, auditor_reason))
    conn.commit()
    conn.close()


def get_pending_consensus_alert(session_id: str):
    """
    Checks if there is a pending, un-enforced MISALIGNED verdict from the Auditor Agent for this session.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, turn_number, iaa_score, auditor_verdict, auditor_reason, timestamp
        FROM consensus_events
        WHERE session_id = ? AND auditor_verdict = 'MISALIGNED' AND enforced = 0
        ORDER BY id DESC LIMIT 1
    """, (session_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "id": row[0],
            "turn_number": row[1],
            "iaa_score": row[2],
            "auditor_verdict": row[3],
            "auditor_reason": row[4],
            "timestamp": row[5]
        }
    return None


def mark_consensus_enforced(session_id: str):
    """
    Marks all pending consensus alerts for a session as enforced.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE consensus_events
        SET enforced = 1
        WHERE session_id = ? AND enforced = 0
    """, (session_id,))
    conn.commit()
    conn.close()


def get_consensus_history(session_id: str = None):
    """
    Retrieves dual-agent consensus audit history.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if session_id:
        cursor.execute("""
            SELECT id, session_id, turn_number, iaa_score, auditor_verdict, auditor_reason, enforced, timestamp
            FROM consensus_events WHERE session_id = ? ORDER BY timestamp DESC
        """, (session_id,))
    else:
        cursor.execute("""
            SELECT id, session_id, turn_number, iaa_score, auditor_verdict, auditor_reason, enforced, timestamp
            FROM consensus_events ORDER BY timestamp DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return rows


# ============================================================================
# Section 26 Extended Schema Helper Functions
# ============================================================================

def get_or_create_session(session_id: str) -> dict:
    """Gets an existing session or initializes a new one with default ACTIVE status."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT session_id, status, session_risk, intent_anchor, current_topic_id, created_at, updated_at FROM sessions WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    if not row:
        cursor.execute(
            "INSERT INTO sessions (session_id, status, session_risk, intent_anchor, current_topic_id) VALUES (?, 'ACTIVE', 0.0, '[]', NULL)",
            (session_id,)
        )
        conn.commit()
        cursor.execute("SELECT session_id, status, session_risk, intent_anchor, current_topic_id, created_at, updated_at FROM sessions WHERE session_id = ?", (session_id,))
        row = cursor.fetchone()
    conn.close()
    return {
        "session_id": row[0],
        "status": row[1],
        "session_risk": row[2],
        "intent_anchor": json.loads(row[3]) if row[3] else [],
        "current_topic_id": row[4],
        "created_at": row[5],
        "updated_at": row[6]
    }


def update_session(session_id: str, status: str = None, session_risk: float = None, intent_anchor: list = None, current_topic_id: str = None):
    """Updates session status, risk score, intent anchor vector, or active topic."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    updates = ["updated_at = CURRENT_TIMESTAMP"]
    vals = []
    if status is not None:
        updates.append("status = ?")
        vals.append(status)
    if session_risk is not None:
        updates.append("session_risk = ?")
        vals.append(session_risk)
    if intent_anchor is not None:
        updates.append("intent_anchor = ?")
        vals.append(json.dumps(intent_anchor))
    if current_topic_id is not None:
        updates.append("current_topic_id = ?")
        vals.append(current_topic_id)
    vals.append(session_id)
    cursor.execute(f"UPDATE sessions SET {', '.join(updates)} WHERE session_id = ?", vals)
    conn.commit()
    conn.close()


def get_session(session_id: str) -> dict | None:
    """Retrieves metadata for a single session ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT session_id, status, session_risk, intent_anchor, current_topic_id, created_at, updated_at FROM sessions WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "session_id": row[0],
        "status": row[1],
        "session_risk": row[2],
        "intent_anchor": json.loads(row[3]) if row[3] else [],
        "current_topic_id": row[4],
        "created_at": row[5],
        "updated_at": row[6]
    }


def save_topic(topic_id: str, session_id: str, topic_anchor: list, topic_name: str = "General", first_turn: int = 1, last_turn: int = 1, is_benign: int = 1):
    """Registers or updates a local topic anchor."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO topics (topic_id, session_id, topic_anchor, topic_name, first_turn, last_turn, is_benign)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(topic_id) DO UPDATE SET
            last_turn = excluded.last_turn,
            topic_name = excluded.topic_name,
            is_benign = excluded.is_benign
    """, (topic_id, session_id, json.dumps(topic_anchor), topic_name, first_turn, last_turn, is_benign))
    conn.commit()
    conn.close()


def get_session_topics(session_id: str) -> list[dict]:
    """Returns all topics created for a given session."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT topic_id, session_id, topic_anchor, topic_name, first_turn, last_turn, is_benign, created_at
        FROM topics WHERE session_id = ? ORDER BY first_turn ASC
    """, (session_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "topic_id": r[0],
        "session_id": r[1],
        "topic_anchor": json.loads(r[2]),
        "topic_name": r[3],
        "first_turn": r[4],
        "last_turn": r[5],
        "is_benign": bool(r[6]),
        "created_at": r[7]
    } for r in rows]


def save_risk_event(session_id: str, turn_number: int, risk_score: float, components: dict, decision: str):
    """Logs detailed risk scoring breakdown for an individual turn."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO risk_events (session_id, turn_number, risk_score, components, decision)
        VALUES (?, ?, ?, ?, ?)
    """, (session_id, turn_number, risk_score, json.dumps(components), decision))
    conn.commit()
    conn.close()


def get_session_risk_history(session_id: str) -> list[dict]:
    """Returns risk progression events for a session."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT turn_number, risk_score, components, decision, timestamp
        FROM risk_events WHERE session_id = ? ORDER BY turn_number ASC
    """, (session_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "turn_number": r[0],
        "risk_score": r[1],
        "components": json.loads(r[2]) if r[2] else {},
        "decision": r[3],
        "timestamp": r[4]
    } for r in rows]


def save_atlas_match(session_id: str, turn_number: int, technique_id: str, technique_name: str, confidence: float):
    """Logs candidate MITRE ATLAS technique matches."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO atlas_matches (session_id, turn_number, technique_id, technique_name, confidence)
        VALUES (?, ?, ?, ?, ?)
    """, (session_id, turn_number, technique_id, technique_name, confidence))
    conn.commit()
    conn.close()


def get_atlas_matches(session_id: str = None) -> list[dict]:
    """Retrieves MITRE ATLAS technique matches, optionally filtered by session."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if session_id:
        cursor.execute("""
            SELECT session_id, turn_number, technique_id, technique_name, confidence, timestamp
            FROM atlas_matches WHERE session_id = ? ORDER BY timestamp DESC
        """, (session_id,))
    else:
        cursor.execute("""
            SELECT session_id, turn_number, technique_id, technique_name, confidence, timestamp
            FROM atlas_matches ORDER BY timestamp DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return [{
        "session_id": r[0],
        "turn_number": r[1],
        "technique_id": r[2],
        "technique_name": r[3],
        "confidence": r[4],
        "timestamp": r[5]
    } for r in rows]


def save_alert(session_id: str, turn_number: int, alert_type: str, severity: str, details: str):
    """Logs an operational security alert."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (session_id, turn_number, alert_type, severity, details)
        VALUES (?, ?, ?, ?, ?)
    """, (session_id, turn_number, alert_type, severity, details))
    conn.commit()
    conn.close()


def get_alerts(session_id: str = None) -> list[dict]:
    """Retrieves security alerts."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if session_id:
        cursor.execute("""
            SELECT id, session_id, turn_number, alert_type, severity, details, timestamp
            FROM alerts WHERE session_id = ? ORDER BY timestamp DESC
        """, (session_id,))
    else:
        cursor.execute("""
            SELECT id, session_id, turn_number, alert_type, severity, details, timestamp
            FROM alerts ORDER BY timestamp DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return [{
        "id": r[0],
        "session_id": r[1],
        "turn_number": r[2],
        "alert_type": r[3],
        "severity": r[4],
        "details": r[5],
        "timestamp": r[6]
    } for r in rows]


def save_auditor_decision(session_id: str, turn_number: int, verdict: str, confidence: float, reason: str):
    """Records an Auditor Agent structured decision."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO auditor_decisions (session_id, turn_number, verdict, confidence, reason)
        VALUES (?, ?, ?, ?, ?)
    """, (session_id, turn_number, verdict, confidence, reason))
    conn.commit()
    conn.close()


def get_auditor_decisions(session_id: str = None) -> list[dict]:
    """Returns auditor evaluations."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if session_id:
        cursor.execute("""
            SELECT turn_number, verdict, confidence, reason, timestamp
            FROM auditor_decisions WHERE session_id = ? ORDER BY turn_number DESC
        """, (session_id,))
    else:
        cursor.execute("""
            SELECT session_id, turn_number, verdict, confidence, reason, timestamp
            FROM auditor_decisions ORDER BY timestamp DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    if session_id:
        return [{"turn_number": r[0], "verdict": r[1], "confidence": r[2], "reason": r[3], "timestamp": r[4]} for r in rows]
    return [{"session_id": r[0], "turn_number": r[1], "verdict": r[2], "confidence": r[3], "reason": r[4], "timestamp": r[5]} for r in rows]


def record_override(session_id: str, analyst_id: str = "SOC_ANALYST", reason: str = "Manual override by security analyst") -> dict:
    """
    Unblocks / restores a session by recording an analyst override and updating status to ACTIVE.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM sessions WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    prev_status = row[0] if row else "UNKNOWN"

    cursor.execute(
        "INSERT INTO overrides (session_id, analyst_id, reason, previous_status) VALUES (?, ?, ?, ?)",
        (session_id, analyst_id, reason, prev_status)
    )
    cursor.execute("UPDATE sessions SET status = 'ACTIVE', session_risk = 0.0, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()

    return {
        "session_id": session_id,
        "analyst_id": analyst_id,
        "previous_status": prev_status,
        "new_status": "ACTIVE",
        "reason": reason
    }


def get_overrides(session_id: str = None) -> list[dict]:
    """Retrieves audit trail of human analyst overrides."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if session_id:
        cursor.execute("""
            SELECT id, session_id, analyst_id, reason, previous_status, timestamp
            FROM overrides WHERE session_id = ? ORDER BY timestamp DESC
        """, (session_id,))
    else:
        cursor.execute("""
            SELECT id, session_id, analyst_id, reason, previous_status, timestamp
            FROM overrides ORDER BY timestamp DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return [{
        "id": r[0],
        "session_id": r[1],
        "analyst_id": r[2],
        "reason": r[3],
        "previous_status": r[4],
        "timestamp": r[5]
    } for r in rows]


def reset_session_state(session_id: str) -> dict:
    """
    Wipes conversational turns and local topic state for a session while logging the event.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM session_turns WHERE session_id = ?", (session_id,))
    cursor.execute("UPDATE sessions SET status = 'RESET', session_risk = 0.0, intent_anchor = '[]', current_topic_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()
    return {"status": "RESET", "session_id": session_id}


def get_session_trajectory(session_id: str) -> list[dict]:
    """
    Returns step-by-step turn progression including message, drift, risk, topic, and technique.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT turn_number, message_text, similarity_score, drift_score, risk_score, attack_technique, attack_confidence, topic_id, timestamp
        FROM session_turns WHERE session_id = ? ORDER BY turn_number ASC
    """, (session_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "turn": r[0],
        "prompt": r[1],
        "similarity": r[2],
        "drift_score": r[3],
        "risk_score": r[4],
        "technique": r[5] or "None",
        "attack_confidence": r[6] or 0.0,
        "topic_id": r[7] or "topic_1",
        "timestamp": r[8]
    } for r in rows]