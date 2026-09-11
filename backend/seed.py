import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "identityshield.db")

def seed():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM exposure_alerts;")
    cursor.execute("DELETE FROM aliases;")
    cursor.execute("DELETE FROM users;")

    # Demo user
    pw_hash = generate_password_hash("Password123!")
    cursor.execute("""
        INSERT INTO users (name, username, email, password_hash, protected_email)
        VALUES ('Alex Vance', 'demo', 'alex.vance@personal-vault.net', ?, 'alex-82KF@identityshield.local')
    """, (pw_hash,))
    user_id = cursor.lastrowid

    # Seed Aliases
    aliases = [
        (user_id, "amazon-91AX@identityshield.local", "Amazon Prime", "amazon.com", "Active", "Low", 12),
        (user_id, "news-82KF@identityshield.local", "TechBrief Newsletter", "news.tech", "Active", "Low", 8),
        (user_id, "event-73PQ@identityshield.local", "Dev Summit Events", "events.dev", "Monitoring", "Medium", 45),
        (user_id, "shop-41LM@identityshield.local", "Shopping Portal", "modatrend.shop", "Exposed", "High", 72),
        (user_id, "trial-30KP@identityshield.local", "FreeTrial Streaming", "streamtrial.tv", "Disabled", "Low", 5)
    ]
    cursor.executemany("""
        INSERT INTO aliases (user_id, alias_email, service_name, service_domain, status, risk_level, risk_score)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, aliases)

    cursor.execute("SELECT id FROM aliases WHERE alias_email = 'shop-41LM@identityshield.local'")
    shop_id = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM aliases WHERE alias_email = 'event-73PQ@identityshield.local'")
    dev_id = cursor.fetchone()[0]

    alerts = [
        (shop_id, "unknown@marketing-example.com", "Unexpected sender activity detected on a service-specific identity.", "High", 72, "September 10, 2026", "Investigate", 1),
        (dev_id, "partner-leads@sponsor-exhibitor.org", "Attendee directory list sharing detected.", "Medium", 45, "September 09, 2026", "Monitoring", 1)
    ]
    cursor.executemany("""
        INSERT INTO exposure_alerts (alias_id, sender, reason, severity, risk_score, first_detected, status, is_simulated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, alerts)

    conn.commit()
    conn.close()
    print("Database seeded. Demo user: demo / Password123!")

if __name__ == "__main__":
    seed()