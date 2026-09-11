import os
import random
import string
import re
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Import URL Security Analysis Engine
from url_security.analyzer import analyze_url

# Import Inbound Mail Processing Engine
from inbox.service import MailReceiver

app = Flask(__name__, static_folder="../", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "identityshield_dev_secret_key_2026_x89a")

# Inbound email configuration (Domain can be overridden via environment variables)
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "identityshield.local").lower()
MAIL_WEBHOOK_SECRET = os.environ.get("MAIL_WEBHOOK_SECRET", "identityshield_webhook_secret_key")

# CORS configuration for development and Live Server (ports 5500 and 5000)
CORS(app, supports_credentials=True, origins=[
    "http://127.0.0.1:5500", "http://localhost:5500",
    "http://127.0.0.1:5000", "http://localhost:5000"
])

DB_PATH = os.path.join(os.path.dirname(__file__), "identityshield.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_db()
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

    # 2. Aliases table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            alias_email TEXT UNIQUE NOT NULL,
            service_name TEXT NOT NULL,
            service_domain TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 8,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    # 3. Exposure Alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exposure_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            reason TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            first_detected TEXT NOT NULL,
            status TEXT NOT NULL,
            is_simulated INTEGER DEFAULT 0,
            FOREIGN KEY(alias_id) REFERENCES aliases(id) ON DELETE CASCADE
        );
    """)

    # 4. Inbound Messages table (Inbox capability)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alias_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_text TEXT,
            body_html TEXT,
            preview TEXT,
            otp_detected INTEGER DEFAULT 0,
            otp_code TEXT,
            is_read INTEGER DEFAULT 0,
            is_simulated INTEGER DEFAULT 0,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(alias_id) REFERENCES aliases(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    conn.commit()
    conn.close()

init_db()

# Initialize Inbound Email Receiver Service
mail_receiver = MailReceiver(get_db)

@app.route("/")
def serve_index():
    return app.send_static_file("index.html")

# ----------------- AUTHENTICATION ROUTES ----------------- #

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not username or not email or not password:
        return jsonify({"success": False, "error": "All fields are required."}), 400

    # 100% Anonymous Random Root Identity (No username correlation)
    rand_prefix = random.choice(["shield", "vault", "proxy", "relay", "anon"])
    rand_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    protected_email = f"{rand_prefix}-{rand_code}@{MAIL_DOMAIN}"
    
    pw_hash = generate_password_hash(password)

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (name, username, email, password_hash, protected_email)
            VALUES (?, ?, ?, ?, ?)
        """, (name, username, email, pw_hash, protected_email))
        user_id = cursor.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "error": "Username or email is already taken."}), 409

    session['user_id'] = user_id
    conn.close()

    return jsonify({
        "success": True,
        "user": {
            "id": user_id, "name": name, "username": username,
            "email": email, "protected_identity": protected_email
        }
    }), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    login_id = data.get("username", "").strip()
    password = data.get("password", "")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (login_id, login_id.lower()))
    user = cursor.fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "error": "Invalid credentials provided."}), 401

    session['user_id'] = user["id"]

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"], "name": user["name"], "username": user["username"],
            "email": user["email"], "protected_identity": user["protected_email"]
        }
    }), 200

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Signed out successfully."}), 200

@app.route("/api/profile", methods=["GET"])
def profile():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, username, email, protected_email FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"], "name": user["name"], "username": user["username"],
            "email": user["email"], "protected_identity": user["protected_email"]
        }
    }), 200

# ----------------- ALIAS MANAGEMENT ROUTES ----------------- #

@app.route("/api/aliases", methods=["GET"])
def get_aliases():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, alias_email as alias, service_name as service, service_domain as domain,
               status, risk_level as risk, risk_score as score, created_at as created
        FROM aliases WHERE user_id = ? ORDER BY id DESC
    """, (session['user_id'],))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({"success": True, "aliases": rows}), 200

@app.route("/api/aliases", methods=["POST"])
def create_alias():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    service_name = data.get("service_name", "").strip()
    service_domain = data.get("service_domain", "").strip()

    if not service_name:
        return jsonify({"success": False, "error": "Service name required"}), 400

    clean_prefix = re.sub(r'[^a-zA-Z0-9]', '', service_name).lower()[:6] or "svc"
    clean_domain = service_domain if service_domain else f"{clean_prefix}.com"
    rand_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
    # Uses configurable receiving MAIL_DOMAIN
    alias_email = f"{clean_prefix}-{rand_code}@{MAIL_DOMAIN}"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO aliases (user_id, alias_email, service_name, service_domain, status, risk_level, risk_score)
        VALUES (?, ?, ?, ?, 'Active', 'Low', 8)
    """, (session['user_id'], alias_email, service_name, clean_domain))
    new_id = cursor.lastrowid
    conn.commit()

    cursor.execute("""
        SELECT id, alias_email as alias, service_name as service, service_domain as domain,
               status, risk_level as risk, risk_score as score, created_at as created
        FROM aliases WHERE id = ?
    """, (new_id,))
    created = dict(cursor.fetchone())
    conn.close()

    return jsonify({"success": True, "message": f"Alias created for {service_name}", "alias": created}), 201

@app.route("/api/aliases/<int:alias_id>", methods=["PATCH"])
def update_alias(alias_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    action = data.get("action")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM aliases WHERE id = ? AND user_id = ?", (alias_id, session['user_id']))
    alias = cursor.fetchone()

    if not alias:
        conn.close()
        return jsonify({"success": False, "error": "Alias not found"}), 404

    if action == "toggle_status":
        next_status = "Disabled" if alias["status"] != "Disabled" else "Active"
        cursor.execute("UPDATE aliases SET status = ? WHERE id = ?", (next_status, alias_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"Alias status changed to {next_status}"})

    elif action == "rotate":
        clean_prefix = alias["alias_email"].split("-")[0]
        rand_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        domain_part = alias["alias_email"].split("@")[-1]
        new_alias = f"{clean_prefix}-{rand_code}@{domain_part}"
        cursor.execute("UPDATE aliases SET alias_email = ?, status = 'Active', risk_level = 'Low', risk_score = 8 WHERE id = ?", (new_alias, alias_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Alias successfully rotated", "alias": new_alias})

    conn.close()
    return jsonify({"success": False, "error": "Invalid action"}), 400

# ----------------- EXPOSURE & DASHBOARD ROUTES ----------------- #

@app.route("/api/exposure", methods=["GET"])
def get_exposure():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.id, e.alias_id as aliasId, a.service_name as service, a.alias_email as alias,
               e.sender, e.risk_score as riskScore, e.severity, e.detected_at as detected,
               e.first_detected as firstDetected, e.status, e.reason
        FROM exposure_alerts e
        JOIN aliases a ON e.alias_id = a.id
        WHERE a.user_id = ?
        ORDER BY e.id DESC
    """, (session['user_id'],))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "events": rows}), 200

@app.route("/api/exposure/<int:event_id>", methods=["GET"])
def get_exposure_detail(event_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.id, e.alias_id as aliasId, a.service_name as service, a.alias_email as alias,
               e.sender, e.risk_score as riskScore, e.severity, e.detected_at as detected,
               e.first_detected as firstDetected, e.status, e.reason
        FROM exposure_alerts e
        JOIN aliases a ON e.alias_id = a.id
        WHERE e.id = ? AND a.user_id = ?
    """, (event_id, session['user_id']))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "Event not found"}), 404

    return jsonify({"success": True, "event": dict(row)}), 200

@app.route("/api/exposure/simulate", methods=["POST"])
def simulate_exposure():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    alias_id = data.get("alias_id")
    severity = data.get("severity", "High")
    sender = data.get("sender", "unknown@marketing-syndicate-example.com")
    activity_type = data.get("activity_type", "Domain mismatch")

    risk_score = 88 if severity == "Critical" else 72 if severity == "High" else 45
    reason = f"[SIMULATED] {activity_type} detected on dedicated alias."
    first_detected = datetime.utcnow().strftime("%B %d, %Y")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO exposure_alerts (alias_id, sender, reason, severity, risk_score, first_detected, status, is_simulated)
        VALUES (?, ?, ?, ?, ?, ?, 'Investigate', 1)
    """, (alias_id, sender, reason, severity, risk_score, first_detected))

    cursor.execute("UPDATE aliases SET status = 'Exposed', risk_level = ?, risk_score = ? WHERE id = ?", (severity, risk_score, alias_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Simulated exposure event recorded."}), 201

@app.route("/api/dashboard", methods=["GET"])
def get_dashboard():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    uid = session['user_id']
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT protected_email FROM users WHERE id = ?", (uid,))
    protected_id = cursor.fetchone()["protected_email"]

    cursor.execute("SELECT COUNT(*) as c FROM aliases WHERE user_id = ?", (uid,))
    total = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM aliases WHERE user_id = ? AND status = 'Active'", (uid,))
    active = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM aliases WHERE user_id = ? AND status = 'Disabled'", (uid,))
    disabled = cursor.fetchone()["c"]

    cursor.execute("""
        SELECT COUNT(*) as c FROM exposure_alerts e
        JOIN aliases a ON e.alias_id = a.id WHERE a.user_id = ?
    """, (uid,))
    alerts = cursor.fetchone()["c"]

    cursor.execute("""
        SELECT COUNT(*) as c FROM exposure_alerts e
        JOIN aliases a ON e.alias_id = a.id
        WHERE a.user_id = ? AND (e.severity = 'High' OR e.severity = 'Critical')
    """, (uid,))
    high_risk = cursor.fetchone()["c"]

    score = max(100 - (high_risk * 15) - (alerts * 5) + (disabled * 3), 20)

    cursor.execute("""
        SELECT a.service_name as service, e.severity, e.detected_at, e.sender
        FROM exposure_alerts e
        JOIN aliases a ON e.alias_id = a.id
        WHERE a.user_id = ? ORDER BY e.id DESC LIMIT 3
    """, (uid,))
    recent = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({
        "success": True,
        "data": {
            "protected_identity": protected_id,
            "services_protected": total + 5,
            "active_aliases": active,
            "disabled_aliases": disabled,
            "exposure_alerts": alerts,
            "high_risk": high_risk,
            "privacy_score": score,
            "recent_activity": recent
        }
    }), 200

@app.route("/api/summary", methods=["GET"])
def get_summary():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    uid = session['user_id']
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM aliases WHERE user_id = ?", (uid,))
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as active FROM aliases WHERE user_id = ? AND status = 'Active'", (uid,))
    active = cursor.fetchone()["active"]

    cursor.execute("SELECT COUNT(*) as disabled FROM aliases WHERE user_id = ? AND status = 'Disabled'", (uid,))
    disabled = cursor.fetchone()["disabled"]

    cursor.execute("""
        SELECT COUNT(*) as alerts,
               SUM(CASE WHEN e.severity IN ('High', 'Critical') THEN 1 ELSE 0 END) as high_risk
        FROM exposure_alerts e
        JOIN aliases a ON e.alias_id = a.id WHERE a.user_id = ?
    """, (uid,))
    alert_row = cursor.fetchone()
    conn.close()

    alerts = alert_row["alerts"] or 0
    high_risk = alert_row["high_risk"] or 0
    score = max(100 - (high_risk * 15) - (alerts * 5) + (disabled * 3), 20)

    return jsonify({
        "success": True,
        "summary": {
            "account_age": "Active Session",
            "services_protected": total + 5,
            "active_identities": active,
            "disabled_identities": disabled,
            "exposure_events": alerts,
            "high_risk_events": high_risk,
            "privacy_score": score
        }
    }), 200

# ----------------- URL SECURITY ANALYSIS ROUTE ----------------- #

@app.route("/api/url-analysis", methods=["POST"])
def url_analysis():
    if 'user_id' not in session:
        return jsonify({
            "success": False,
            "error": "Authentication required to analyze URLs."
        }), 401

    data = request.get_json() or {}
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({
            "success": False,
            "error": "A target URL is required in the request payload."
        }), 400

    success, error_msg, analysis_data = analyze_url(target_url)

    if not success or analysis_data is None:
        return jsonify({
            "success": False,
            "error": error_msg or "Invalid URL format."
        }), 400

    return jsonify({
        "success": True,
        "data": analysis_data
    }), 200

# ----------------- INBOX & EMAIL RECEIVING ROUTES ----------------- #

@app.route("/api/inbox", methods=["GET"])
def get_inbox():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    user_id = session['user_id']
    alias_filter = request.args.get("alias_id", type=int)

    conn = get_db()
    cursor = conn.cursor()

    if alias_filter:
        cursor.execute("""
            SELECT m.id, m.alias_id, m.sender, m.recipient, m.subject, m.preview,
                   m.otp_detected, m.otp_code, m.is_read, m.is_simulated, m.received_at,
                   a.service_name
            FROM messages m
            JOIN aliases a ON m.alias_id = a.id
            WHERE m.user_id = ? AND m.alias_id = ?
            ORDER BY m.id DESC
        """, (user_id, alias_filter))
    else:
        cursor.execute("""
            SELECT m.id, m.alias_id, m.sender, m.recipient, m.subject, m.preview,
                   m.otp_detected, m.otp_code, m.is_read, m.is_simulated, m.received_at,
                   a.service_name
            FROM messages m
            JOIN aliases a ON m.alias_id = a.id
            WHERE m.user_id = ?
            ORDER BY m.id DESC
        """, (user_id,))

    rows = [dict(r) for r in cursor.fetchall()]

    # Calculate total unread count for user
    cursor.execute("SELECT COUNT(*) as unread FROM messages WHERE user_id = ? AND is_read = 0", (user_id,))
    unread_count = cursor.fetchone()["unread"]

    conn.close()

    return jsonify({
        "success": True,
        "data": {
            "messages": rows,
            "unread_count": unread_count
        }
    }), 200

@app.route("/api/inbox/<int:message_id>", methods=["GET"])
def get_inbox_message(message_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT m.*, a.service_name, a.service_domain
        FROM messages m
        JOIN aliases a ON m.alias_id = a.id
        WHERE m.id = ? AND m.user_id = ?
    """, (message_id, session['user_id']))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Message not found or access denied."}), 404

    # Automatically mark as read upon full fetch
    cursor.execute("UPDATE messages SET is_read = 1 WHERE id = ?", (message_id,))
    conn.commit()
    msg = dict(row)
    msg["is_read"] = 1
    conn.close()

    return jsonify({"success": True, "data": msg}), 200

@app.route("/api/inbox/<int:message_id>/read", methods=["PATCH"])
def mark_inbox_message_read(message_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM messages WHERE id = ? AND user_id = ?", (message_id, session['user_id']))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"success": False, "error": "Message not found."}), 404

    cursor.execute("UPDATE messages SET is_read = 1 WHERE id = ?", (message_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Marked as read."}), 200

@app.route("/api/inbox/<int:message_id>", methods=["DELETE"])
def delete_inbox_message(message_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM messages WHERE id = ? AND user_id = ?", (message_id, session['user_id']))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"success": False, "error": "Message not found or access denied."}), 404

    cursor.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Message removed from inbox."}), 200

# Development/Simulation Endpoint for testing inbound OTPs locally
@app.route("/api/inbox/dev/receive", methods=["POST"])
def dev_receive_email():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Unauthorized session."}), 401

    data = request.get_json() or {}
    data["is_simulated"] = True

    success, msg, record = mail_receiver.process_incoming_email(data)
    if not success:
        return jsonify({"success": False, "error": msg}), 400

    return jsonify({
        "success": True,
        "message": "Demo inbound email ingested successfully.",
        "data": record
    }), 201

# Production Inbound Webhook Endpoint
@app.route("/api/inbound-email", methods=["POST"])
def inbound_email_webhook():
    # Verify Authorization header or secret token
    auth_header = request.headers.get("X-Webhook-Secret") or request.headers.get("Authorization", "")
    if auth_header.replace("Bearer ", "").strip() != MAIL_WEBHOOK_SECRET:
        return jsonify({"success": False, "error": "Unauthorized webhook signature."}), 401

    # Check payload size (Max 5MB)
    if request.content_length and request.content_length > 5 * 1024 * 1024:
        return jsonify({"success": False, "error": "Inbound payload exceeds 5MB limit."}), 413

    payload = request.get_json() or {}
    success, msg, record = mail_receiver.process_incoming_email(payload)

    if not success:
        return jsonify({"success": False, "error": msg}), 400

    return jsonify({"success": True, "message": "Inbound email processed."}), 200

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)