import sqlite3
import json

DB_PATH = "sentinel_sessions.db"

def init_db():
    """
    Initializes SQLite table for tracking sessions, messages, and embeddings.
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
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_turn(session_id: str, turn_number: int, message_text: str, embedding: list[float]):
    """
    Saves a conversation turn and its vector embedding to SQLite.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    embedding_json = json.dumps(embedding)
    
    cursor.execute("""
        INSERT INTO session_turns (session_id, turn_number, message_text, embedding)
        VALUES (?, ?, ?, ?)
    """, (session_id, turn_number, message_text, embedding_json))
    
    conn.commit()
    conn.close()

def get_session_history(session_id: str):
    """
    Retrieves all past turns for a specific session ID.
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