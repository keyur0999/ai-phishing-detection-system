"""
app.py
PhishGuard AI - Flask Backend Server.

Features:
  - Hybrid AI & Heuristic Phishing Detection Engine (offline local ML inference via scikit-learn).
  - Role-Based Access Control (Admin vs Normal User) with server-side authorization enforcement.
  - Safe SQLite persistence (phishguard.db) with non-destructive data migration.
  - Scans, user authentication, security auditing, and moderated threat reports.
"""

import re
import os
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_from_directory, session, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

import database
import ai_detector

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "phishguard-cybersecurity-secret-key-2026")
CORS(app, supports_credentials=True)

# Initialize and safely migrate SQLite tables
database.init_db()


# ---------------------------------------------------------------------------
# Authorization Helpers & Decorators
# ---------------------------------------------------------------------------

def login_required(f):
    """Ensure user is logged in. Returns 401 JSON for APIs, redirects for pages."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Authentication required. Please sign in."}), 401
            return redirect(f"/login?next={request.path}")
        user = database.get_user_by_id(user_id)
        if not user:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Session expired or user not found."}), 401
            return redirect(f"/login?next={request.path}")
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Ensure user is authenticated and possesses the 'admin' role.
    Hiding links is not sufficient; this enforces server-side security.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Authentication required. Admin privileges needed."}), 401
            return redirect(f"/login?next={request.path}&unauthorized=1")

        user = database.get_user_by_id(user_id)
        if not user or user.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({
                    "success": False,
                    "message": "Access denied. Administrator privileges are required to perform this action."
                }), 403
            return redirect("/dashboard?error=admin_access_required")

        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Page Navigation Routes
# ---------------------------------------------------------------------------

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


@app.route("/admin")
@app.route("/admin/dashboard")
@admin_required
def admin_page():
    return send_from_directory(FRONTEND_DIR, "admin.html")


# ---------------------------------------------------------------------------
# Heuristic Fallback Scorer (Rule-Based Fallback)
# ---------------------------------------------------------------------------

IP_URL_RE = re.compile(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".gq", ".tk", ".ml", ".work", ".click"}


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
        score += 65

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
        reasons.append("Unusually long URL, often used to obscure the real destination")
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

    if "!" in (subject or "") and subject.count("!") >= 2:
        reasons.append("Subject line uses excessive urgency punctuation")
        score += 5

    score = min(score, 100)
    verdict = "phishing" if score >= 60 else "suspicious" if score >= 30 else "safe"
    return verdict, score, reasons


# ---------------------------------------------------------------------------
# Health & AI Status Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True, 
        "status": "ok", 
        "service": "PhishGuard AI Backend",
        "ai_engine": ai_detector.get_engine_status()
    })


@app.route("/api/ai/status", methods=["GET"])
def ai_status():
    """Return local ML model operational status and metadata."""
    return jsonify({"success": True, "ai": ai_detector.get_engine_status()})


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

    # Strictly assign normal user role; user input cannot elevate privileges
    password_hash = generate_password_hash(password)
    try:
        user_id = database.create_user(username, email, password_hash, role="user")
        client_ip, user_agent = _get_client_meta()
        login_id = database.record_login(user_id, username, client_ip, user_agent, status="success")

        session["user_id"] = user_id
        session["username"] = username

        user_info = database.get_user_by_id(user_id)
        return jsonify({
            "success": True,
            "message": "Account created successfully with Normal User access.",
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
        if user:
            database.record_login(user["id"], user["username"], client_ip, user_agent, status="failed")
        return jsonify({"success": False, "message": "Invalid username/email or password."}), 401

    login_id = database.record_login(user["id"], user["username"], client_ip, user_agent, status="success")

    session["user_id"] = user["id"]
    session["username"] = user["username"]

    user_info = database.get_user_by_id(user["id"])

    return jsonify({
        "success": True,
        "message": "Login successful.",
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
@login_required
def list_user_logins():
    """Return login audit records for the authenticated user only."""
    user_id = session.get("user_id")
    limit = int(request.args.get("limit", 25))
    logins = database.get_user_logins(user_id=user_id, limit=limit)
    return jsonify({"success": True, "logins": logins})


@app.route("/api/database/info", methods=["GET"])
def get_db_info():
    """Return general database telemetry statistics."""
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
# Scans Endpoints (Hybrid ML Inference + Heuristic Fallback)
# ---------------------------------------------------------------------------

@app.route("/api/scan/url", methods=["POST"])
def scan_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "message": "No URL provided."}), 400

    user_id = session.get("user_id") or data.get("user_id")
    
    # Run hybrid AI analysis with rule-based fallback
    result = ai_detector.detect_url(url, heuristic_fn=score_url)
    
    # Persist to database
    scan_id = database.save_scan(
        "url", 
        url, 
        result["verdict"], 
        result["risk_score"], 
        result["reasons"], 
        user_id=user_id
    )

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "input": url,
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "reasons": result["reasons"],
        "engine_mode": result["engine_mode"],
        "ai_powered": result["ai_powered"],
        "model_loaded": result["model_loaded"],
        "model_name": result["model_name"],
        "model_probability": result["model_probability"],
        "model_verdict": result["model_verdict"],
        "model_score": result["model_score"],
        "model_explanation": result["model_explanation"],
        "heuristic_score": result["heuristic_score"],
        "heuristic_reasons": result["heuristic_reasons"],
    })


@app.route("/api/scan/email", methods=["POST"])
def scan_email():
    data = request.get_json(silent=True) or {}
    subject = (data.get("subject") or "").strip()
    body = (data.get("body") or "").strip()
    if not subject and not body:
        return jsonify({"success": False, "message": "No email content provided."}), 400

    user_id = session.get("user_id") or data.get("user_id")
    
    # Run hybrid AI analysis with rule-based fallback
    result = ai_detector.detect_email(subject, body, heuristic_fn=score_email)
    
    scan_id = database.save_scan(
        "email", 
        f"{subject} | {body}", 
        result["verdict"], 
        result["risk_score"], 
        result["reasons"], 
        user_id=user_id
    )

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "subject": subject,
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "reasons": result["reasons"],
        "engine_mode": result["engine_mode"],
        "ai_powered": result["ai_powered"],
        "model_loaded": result["model_loaded"],
        "model_name": result["model_name"],
        "model_probability": result["model_probability"],
        "model_verdict": result["model_verdict"],
        "model_score": result["model_score"],
        "model_explanation": result["model_explanation"],
        "heuristic_score": result["heuristic_score"],
        "heuristic_reasons": result["heuristic_reasons"],
    })


@app.route("/api/scan/qr", methods=["POST"])
def scan_qr():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "message": "No QR content provided."}), 400

    user_id = session.get("user_id") or data.get("user_id")
    
    # Run hybrid AI analysis with rule-based fallback
    result = ai_detector.detect_url(url, heuristic_fn=score_url)
    
    scan_id = database.save_scan(
        "qr", 
        url, 
        result["verdict"], 
        result["risk_score"], 
        result["reasons"], 
        user_id=user_id
    )

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "input": url,
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "reasons": result["reasons"],
        "engine_mode": result["engine_mode"],
        "ai_powered": result["ai_powered"],
        "model_loaded": result["model_loaded"],
        "model_name": result["model_name"],
        "model_probability": result["model_probability"],
        "model_verdict": result["model_verdict"],
        "model_score": result["model_score"],
        "model_explanation": result["model_explanation"],
        "heuristic_score": result["heuristic_score"],
        "heuristic_reasons": result["heuristic_reasons"],
    })


@app.route("/api/history", methods=["GET"])
def history():
    limit = int(request.args.get("limit", 50))
    scan_type = request.args.get("type")
    user_id = session.get("user_id")

    # If authenticated normal user, return only their personal history
    if user_id:
        current_user = database.get_user_by_id(user_id)
        if current_user and current_user.get("role") != "admin":
            return jsonify({"success": True, "history": database.get_history(limit, scan_type, user_id=user_id)})

    return jsonify({"success": True, "history": database.get_history(limit, scan_type)})


@app.route("/api/stats", methods=["GET"])
def stats():
    return jsonify({"success": True, "stats": database.get_stats()})


# ---------------------------------------------------------------------------
# Reports Endpoints (Per-User Isolation & Server-Side Admin Control)
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
    """
    List reports:
      - Authenticated Admins: view all reports across the system.
      - Authenticated Normal Users: view ONLY their own submitted reports.
      - Unauthenticated visitors: empty list.
    """
    limit = int(request.args.get("limit", 100))
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"success": True, "reports": []})

    current_user = database.get_user_by_id(user_id)
    if not current_user:
        return jsonify({"success": True, "reports": []})

    if current_user.get("role") == "admin":
        reports = database.get_reports(limit=limit)
    else:
        reports = database.get_reports(limit=limit, user_id=user_id)

    return jsonify({"success": True, "reports": reports})


@app.route("/api/reports/<int:report_id>/status", methods=["PATCH", "POST"])
@app.route("/api/report/<int:report_id>/status", methods=["PATCH", "POST"])
@admin_required
def update_report_status_route(report_id):
    """Admin-only: Change moderation status of a report."""
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip().lower()
    if status not in ("pending", "reviewed", "resolved", "dismissed"):
        return jsonify({"success": False, "message": "Invalid status value."}), 400

    updated = database.update_report_status(report_id, status)
    if not updated:
        return jsonify({"success": False, "message": "Report not found."}), 404

    return jsonify({"success": True, "message": f"Report #{report_id} status updated to {status}."})


# ---------------------------------------------------------------------------
# Admin Console API Endpoints (Strictly Server-Side Protected)
# ---------------------------------------------------------------------------

@app.route("/api/admin/overview", methods=["GET"])
@admin_required
def admin_overview():
    overview = database.get_admin_overview()
    overview["ai_engine"] = ai_detector.get_engine_status()
    return jsonify({"success": True, "overview": overview})


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    limit = int(request.args.get("limit", 100))
    users = database.get_all_users(limit=limit)
    return jsonify({"success": True, "users": users})


@app.route("/api/admin/logins", methods=["GET"])
@admin_required
def admin_list_logins():
    limit = int(request.args.get("limit", 150))
    logins = database.get_user_logins(user_id=None, limit=limit)
    return jsonify({"success": True, "logins": logins})


@app.route("/api/admin/blocklist", methods=["GET", "POST"])
@admin_required
def admin_blocklist_manage():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip().lower()
        reason = (data.get("reason") or "Manual admin blocklist entry").strip()
        if not domain:
            return jsonify({"success": False, "message": "Domain is required."}), 400
        database.add_to_blocklist(domain, reason)
        return jsonify({"success": True, "message": f"Domain '{domain}' added to blocklist."})

    items = database.get_blocklist_all()
    return jsonify({"success": True, "blocklist": items})


@app.route("/api/admin/blocklist/<int:entry_id>", methods=["DELETE", "POST"])
@admin_required
def admin_blocklist_delete(entry_id):
    deleted = database.delete_from_blocklist(entry_id)
    if not deleted:
        return jsonify({"success": False, "message": "Blocklist entry not found."}), 404
    return jsonify({"success": True, "message": "Blocklist entry removed."})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
