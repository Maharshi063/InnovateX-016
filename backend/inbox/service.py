import sqlite3
from typing import Dict, Any, Tuple, Optional
from .otp_detector import detect_otp, sanitize_html_payload

class MailReceiver:
    """
    Provider-agnostic inbound email processing pipeline.
    Validates, extracts sender/recipient, matches recipient to alias owner,
    executes OTP detection, and persists message record in SQLite.
    """

    def __init__(self, db_factory):
        self.get_db = db_factory

    def process_incoming_email(self, payload: Dict[str, Any]) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Processes normalized payload dictionary:
        {
          "recipient": "amazon-82KF@domain.com",
          "sender": "no-reply@amazon.com",
          "subject": "Verification Code",
          "body_text": "...",
          "body_html": "...",
          "is_simulated": False
        }
        Returns: (success: bool, message: str, stored_record: Optional[dict])
        """
        raw_recipient = payload.get("recipient", "").strip().lower()
        sender = payload.get("sender", "").strip()
        subject = payload.get("subject", "").strip() or "(No Subject)"
        body_text = payload.get("body_text", "").strip()
        raw_html = payload.get("body_html", "")
        is_simulated = 1 if payload.get("is_simulated") else 0

        if not raw_recipient:
            return False, "Recipient email address is required.", None

        if not sender:
            return False, "Sender email address is required.", None

        # Clean HTML payload
        body_html = sanitize_html_payload(raw_html) if raw_html else ""

        # Normalize plain text preview
        preview = (body_text or re_sub_html(body_html))[:160].strip()

        # Context-aware OTP Detection
        otp_detected, otp_code = detect_otp(subject, body_text or preview)

        # Database lookup: match alias by address
        conn = self.get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT a.id as alias_id, a.user_id, a.service_name, a.status, u.username
            FROM aliases a
            JOIN users u ON a.user_id = u.id
            WHERE LOWER(a.alias_email) = ?
        """, (raw_recipient,))
        alias_record = cursor.fetchone()

        if not alias_record:
            conn.close()
            return False, f"Delivery rejected: no active alias found matching recipient '{raw_recipient}'.", None

        # Reject delivery if alias has been disabled or deleted by user
        if alias_record["status"] == "Disabled":
            conn.close()
            return False, f"Delivery rejected: alias '{raw_recipient}' is currently disabled.", None

        alias_id = alias_record["alias_id"]
        user_id = alias_record["user_id"]

        cursor.execute("""
            INSERT INTO messages (
                alias_id, user_id, sender, recipient, subject,
                body_text, body_html, preview, otp_detected, otp_code,
                is_read, is_simulated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        """, (
            alias_id, user_id, sender, raw_recipient, subject,
            body_text, body_html, preview, 1 if otp_detected else 0, otp_code,
            is_simulated
        ))
        message_id = cursor.lastrowid
        conn.commit()

        cursor.execute("SELECT * FROM messages WHERE id = ?", (message_id,))
        saved_row = dict(cursor.fetchone())
        conn.close()

        # Operational log without logging the actual OTP code or sensitive content
        print(f"[INBOUND] Received message ID {message_id} for Alias ID {alias_id} (OTP: {otp_detected})")

        return True, "Message ingested successfully.", saved_row

def re_sub_html(html_str: str) -> str:
    import re
    return re.sub(r"<[^>]*>", " ", html_str or "")