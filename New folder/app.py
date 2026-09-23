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
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from flask_cors import CORS

import database

app = Flask(__name__)
CORS(app)  # allow the static front-end (opened via file:// or a dev server) to call this API

database.init_db()

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


@app.route("/api/scan/url", methods=["POST"])
def scan_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "message": "No URL provided."}), 400

    verdict, score, reasons = score_url(url)
    scan_id = database.save_scan("url", url, verdict, score, reasons)

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

    verdict, score, reasons = score_email(subject, body)
    scan_id = database.save_scan("email", f"{subject} | {body}", verdict, score, reasons)

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

    verdict, score, reasons = score_url(url)
    scan_id = database.save_scan("qr", url, verdict, score, reasons)

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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
