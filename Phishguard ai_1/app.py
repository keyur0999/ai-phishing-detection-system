"""
app.py
PhishGuard AI - Flask backend.

Implements the exact endpoints script.js already calls:
    GET  /api/health
    POST /api/scan/url    { "url": "..." }
    POST /api/scan/email  { "subject": "...", "body": "..." }
    POST /api/scan/qr     { "url": "..." }  (QR is decoded client-side to a URL)

Plus two extra read endpoints used by a dashboard/history view:
    GET  /api/history
    GET  /api/stats

Every scan is analyzed with a transparent, rule-based scorer and the
result is persisted to SQLite via database.py.
"""

import re
import os
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

import database

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "phishguard-cybersecurity-secret-key-2026")
CORS(app, supports_credentials=True)  # allow credentials for authentication

database.init_db()


@app.route("/")
@app.route("/landing")
def landing_page():
    return send_from_directory(FRONTEND_DIR, "landing.html")


@app.route("/dashboard")
@app.route("/scanner")
@app.route("/app")
def dashboard_page():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/login")
@app.route("/register")
def auth_page():
    return send_from_directory(FRONTEND_DIR, "login.html")


@app.route("/reports")
def reports_page():
    return send_from_directory(FRONTEND_DIR, "reports.html")



IP_URL_RE = re.compile(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".gq", ".tk", ".ml", ".work", ".click"}


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def score_url(url):
    reasons = []
    score = 0
    url_lower = url.strip().lower()

    try:
        parsed = urlparse(url_lower if "://" in url_lower else "http://" + url_lower)
        domain = parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        parsed = None
        domain = url_lower

    blocked = database.is_blocklisted(domain)
    if blocked:
        reasons.append(f"Domain matches known blocklist entry ({blocked['reason']})")
        score += 60

    if IP_URL_RE.match(url_lower):
        reasons.append("URL uses a raw IP address instead of a domain name")
        score += 25

    if "@" in url_lower:
        reasons.append("URL contains '@', which can hide the real destination")
        score += 20

    if url_lower.count("-") >= 3:
        reasons.append("Domain contains an unusually high number of hyphens")
        score += 10

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Uses a commonly abused top-level domain ({tld})")
            score += 15
            break

    for indicator, weight in database.get_indicators("url"):
        if indicator in url_lower:
            reasons.append(f"Matches known phishing pattern: '{indicator}'")
            score += weight

    if len(url_lower) > 90:
        reasons.append("Unusually long URL, often used to obscure the real domain")
        score += 10

    score = min(score, 100)
    verdict = "phishing" if score >= 60 else "suspicious" if score >= 30 else "safe"
    return verdict, score, reasons


def score_email(subject, body):
    reasons = []
    score = 0
    text = f"{subject or ''} {body or ''}".lower()

    for indicator, weight in database.get_indicators("email"):
        if indicator in text:
            reasons.append(f"Contains phishing phrase: '{indicator}'")
            score += weight

    urls_found = re.findall(r"https?://[^\s]+", text)
    if len(urls_found) >= 2:
        reasons.append(f"Contains multiple embedded links ({len(urls_found)})")
        score += 10

    for u in urls_found:
        _, url_score, url_reasons = score_url(u)
        if url_score >= 30:
            reasons.append(f"Embedded link looks suspicious: {u}")
            score += min(url_score // 2, 25)

    if "!" in subject and subject.count("!") >= 2:
        reasons.append("Subject line uses excessive urgency punctuation")
        score += 5

    score = min(score, 100)
    verdict = "phishing" if score >= 60 else "suspicious" if score >= 30 else "safe"
    return verdict, score, reasons


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"success": True, "status": "ok", "service": "PhishGuard AI backend"})


# ---------------------------------------------------------------------------
# Authentication Endpoints
# ---------------------------------------------------------------------------

def _get_client_meta():
    """Extract client IP and sanitized User-Agent for database audit logging."""
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    if not client_ip:
        client_ip = "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "Unknown")[:250]
    return client_ip, user_agent


@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()

    if not username:
        return jsonify({"success": False, "message": "Username is required."}), 400
    if len(username) < 3:
        return jsonify({"success": False, "message": "Username must be at least 3 characters."}), 400
    if not password:
        return jsonify({"success": False, "message": "Password is required."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400

    if database.get_user_by_username(username):
        return jsonify({"success": False, "message": "Username is already taken. Please choose another."}), 409

    if email and database.get_user_by_email(email):
        return jsonify({"success": False, "message": "Email is already registered. Please login instead."}), 409

    password_hash = generate_password_hash(password)
    try:
        user_id = database.create_user(username, email, password_hash)
        # Record initial login directly into SQLite user_logins
        client_ip, user_agent = _get_client_meta()
        login_id = database.record_login(user_id, username, client_ip, user_agent, status="success")

        session["user_id"] = user_id
        session["username"] = username

        user_info = database.get_user_by_id(user_id)
        return jsonify({
            "success": True,
            "message": "Account created and logged into SQLite database successfully.",
            "login_id": login_id,
            "user": user_info
        }), 201
    except Exception as e:
        return jsonify({"success": False, "message": f"Registration failed: {str(e)}"}), 500


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not identifier or not password:
        return jsonify({"success": False, "message": "Please enter both username/email and password."}), 400

    client_ip, user_agent = _get_client_meta()

    user = database.get_user_by_username(identifier)
    if not user:
        user = database.get_user_by_email(identifier)

    if not user or not check_password_hash(user["password_hash"], password):
        # Record failed login attempt in database audit table if username exists
        if user:
            database.record_login(user["id"], user["username"], client_ip, user_agent, status="failed")
        return jsonify({"success": False, "message": "Invalid username/email or password."}), 401

    # Record successful login event in SQLite database
    login_id = database.record_login(user["id"], user["username"], client_ip, user_agent, status="success")

    session["user_id"] = user["id"]
    session["username"] = user["username"]

    user_info = database.get_user_by_id(user["id"])

    return jsonify({
        "success": True,
        "message": "Login successful. Session persisted to database.",
        "login_id": login_id,
        "user": user_info
    })


@app.route("/api/auth/logout", methods=["POST", "GET"])
def auth_logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully."})


@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "authenticated": False, "user": None})
    user = database.get_user_by_id(user_id)
    if not user:
        session.clear()
        return jsonify({"success": False, "authenticated": False, "user": None})
    return jsonify({"success": True, "authenticated": True, "user": user})


@app.route("/api/auth/logins", methods=["GET"])
def list_user_logins():
    """Return database-persisted login audit logs."""
    user_id = session.get("user_id")
    limit = int(request.args.get("limit", 25))
    logins = database.get_user_logins(user_id=user_id, limit=limit)
    return jsonify({"success": True, "logins": logins})


@app.route("/api/database/info", methods=["GET"])
def get_db_info():
    """Return SQLite database health and summary statistics."""
    with database.get_connection() as conn:
        user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        login_count = conn.execute("SELECT COUNT(*) AS c FROM user_logins").fetchone()["c"]
        scan_count = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        last_login_row = conn.execute(
            "SELECT username, ip_address, login_time FROM user_logins WHERE status='success' ORDER BY login_time DESC LIMIT 1"
        ).fetchone()

    return jsonify({
        "success": True,
        "database": "SQLite (phishguard.db)",
        "users_count": user_count,
        "logins_recorded": login_count,
        "scans_count": scan_count,
        "last_login": dict(last_login_row) if last_login_row else None
    })


# ---------------------------------------------------------------------------
# Scans Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/scan/url", methods=["POST"])
def scan_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "message": "No URL provided."}), 400

    user_id = session.get("user_id") or data.get("user_id")
    verdict, score, reasons = score_url(url)
    scan_id = database.save_scan("url", url, verdict, score, reasons, user_id=user_id)

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "input": url,
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
    })


@app.route("/api/scan/email", methods=["POST"])
def scan_email():
    data = request.get_json(silent=True) or {}
    subject = (data.get("subject") or "").strip()
    body = (data.get("body") or "").strip()
    if not subject and not body:
        return jsonify({"success": False, "message": "No email content provided."}), 400

    user_id = session.get("user_id") or data.get("user_id")
    verdict, score, reasons = score_email(subject, body)
    scan_id = database.save_scan("email", f"{subject} | {body}", verdict, score, reasons, user_id=user_id)

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "subject": subject,
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
    })


@app.route("/api/scan/qr", methods=["POST"])
def scan_qr():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "message": "No QR content provided."}), 400

    user_id = session.get("user_id") or data.get("user_id")
    verdict, score, reasons = score_url(url)
    scan_id = database.save_scan("qr", url, verdict, score, reasons, user_id=user_id)

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "input": url,
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
    })


@app.route("/api/history", methods=["GET"])
def history():
    limit = int(request.args.get("limit", 50))
    scan_type = request.args.get("type")
    return jsonify({"success": True, "history": database.get_history(limit, scan_type)})


@app.route("/api/stats", methods=["GET"])
def stats():
    return jsonify({"success": True, "stats": database.get_stats()})


# ---------------------------------------------------------------------------
# Reports Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/reports", methods=["POST"])
@app.route("/api/report", methods=["POST"])
def submit_report():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    reason = (data.get("reason") or "").strip()

    if not reason:
        return jsonify({"success": False, "message": "Please provide a reason for reporting."}), 400

    user_id = session.get("user_id") or data.get("user_id")
    try:
        report_id = database.save_report(scan_id=scan_id, reason=reason, user_id=user_id)
        return jsonify({
            "success": True,
            "message": "Report submitted successfully. Thank you for helping keep the web safe!",
            "report_id": report_id,
        }), 201
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to save report: {str(e)}"}), 500


@app.route("/api/reports", methods=["GET"])
@app.route("/api/report", methods=["GET"])
def list_reports():
    limit = int(request.args.get("limit", 100))
    return jsonify({"success": True, "reports": database.get_reports(limit)})


@app.route("/api/reports/<int:report_id>/status", methods=["PATCH", "POST"])
@app.route("/api/report/<int:report_id>/status", methods=["PATCH", "POST"])
def update_report_status_route(report_id):
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip().lower()
    if status not in ("pending", "reviewed", "resolved", "dismissed"):
        return jsonify({"success": False, "message": "Invalid status value."}), 400

    updated = database.update_report_status(report_id, status)
    if not updated:
        return jsonify({"success": False, "message": "Report not found."}), 404

    return jsonify({"success": True, "message": f"Report #{report_id} status updated to {status}."})


if __name__ == "__main__":


    app.run(host="127.0.0.1", port=5000, debug=True)

