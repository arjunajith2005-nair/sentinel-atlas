import sqlite3
import json

DB_PATH = "sentinel_sessions.db"


def init_db():
    """
    Initializes SQLite tables for tracking sessions, messages, embeddings,
    telemetry, risk scoring, attack technique tagging, false-positive tracking,
    and blocked security events.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Main conversation tracking table
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
            false_positive INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Security events table for tracking blocked prompts and drift incidents
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

    # Check which columns already exist
    cursor.execute("PRAGMA table_info(session_turns)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    new_columns = [
        ("similarity_score", "REAL DEFAULT 1.0"),
        ("llm_response", "TEXT DEFAULT ''"),
        ("drift_score", "REAL DEFAULT NULL"),
        ("risk_score", "REAL DEFAULT NULL"),
        ("attack_technique", "TEXT DEFAULT NULL"),
        ("attack_confidence", "REAL DEFAULT NULL"),
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