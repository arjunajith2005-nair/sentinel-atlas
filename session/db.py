import sqlite3
import json

DB_PATH = "sentinel_sessions.db"

def init_db():
    """
    Initializes SQLite tables for tracking sessions, messages, embeddings, and blocked security events.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS session_turns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            turn_number INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            embedding TEXT NOT NULL,
            similarity_score REAL DEFAULT 1.0,
            llm_response TEXT DEFAULT '',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Ensure backwards compatibility by adding missing columns to session_turns if older schema exists
    cursor.execute("PRAGMA table_info(session_turns)")
    columns = [row[1] for row in cursor.fetchall()]
    if "similarity_score" not in columns:
        cursor.execute("ALTER TABLE session_turns ADD COLUMN similarity_score REAL DEFAULT 1.0")
    if "llm_response" not in columns:
        cursor.execute("ALTER TABLE session_turns ADD COLUMN llm_response TEXT DEFAULT ''")

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

def save_turn(session_id: str, turn_number: int, message_text: str, embedding: list[float], similarity_score: float = 1.0, llm_response: str = ""):
    """
    Saves a conversation turn, its vector embedding, similarity score, and LLM response to SQLite.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    embedding_json = json.dumps(embedding)
    
    cursor.execute("""
        INSERT INTO session_turns (session_id, turn_number, message_text, embedding, similarity_score, llm_response)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session_id, turn_number, message_text, embedding_json, similarity_score, llm_response))
    
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

def get_session_history(session_id: str):
    """
    Retrieves all past valid turns for a specific session ID to construct conversational anchor context.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT turn_number, message_text, embedding FROM session_turns
        WHERE session_id = ? ORDER BY turn_number ASC
    """, (session_id,))
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for turn_num, text, emb_str in rows:
        history.append({
            "turn_number": turn_num,
            "message_text": text,
            "embedding": json.loads(emb_str)
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