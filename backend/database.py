import sqlite3
import os

DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "database", "identityshield.db"))

def get_db_connection():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            protected_email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # 2. Aliases table (linked strictly to user)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            alias_email TEXT UNIQUE NOT NULL,
            service_name TEXT NOT NULL,
            service_domain TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Active', 'Disabled', 'Exposed', 'Monitoring', 'Rotated')),
            risk_level TEXT NOT NULL CHECK(risk_level IN ('Low', 'Medium', 'High', 'Critical')),
            risk_score INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    # 3. Email Activity log
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            risk_score INTEGER NOT NULL DEFAULT 0,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY(alias_id) REFERENCES aliases(id) ON DELETE CASCADE
        );
    """)

    # 4. Exposure Alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exposure_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            reason TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
            risk_score INTEGER NOT NULL DEFAULT 0,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            first_detected TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Investigate', 'Monitoring', 'Resolved')),
            is_simulated INTEGER DEFAULT 0,
            FOREIGN KEY(alias_id) REFERENCES aliases(id) ON DELETE CASCADE
        );
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database schema successfully verified at:", DATABASE_PATH)