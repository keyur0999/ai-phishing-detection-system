from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Allow your HTML/CSS/JS frontend to communicate with Flask
CORS(app)


# ============================================================
# BASIC URL ANALYZER
# ============================================================

def analyze_url(url):

    if not url:
        return {
            "result": "error",
            "risk_score": 0,
            "message": "URL is required"
        }

    try:
        parsed = urlparse(url)

        # Basic URL validation
        if not parsed.scheme or not parsed.netloc:
            return {
                "result": "invalid",
                "risk_score": 0,
                "message": "Invalid URL"
            }

        score = 0
        indicators = []

        url_lower = url.lower()

        # HTTP instead of HTTPS
        if parsed.scheme.lower() != "https":
            score += 15
            indicators.append("URL does not use HTTPS")

        # Suspicious keywords
        suspicious_words = [
            "login",
            "verify",
            "verification",
            "password",
            "account",
            "signin",
            "confirm",
            "secure",
            "update",
            "bank"
        ]

        for word in suspicious_words:
            if word in url_lower:
                score += 10
                indicators.append(
                    f"Suspicious keyword detected: {word}"
                )

        # Long URL
        if len(url) > 100:
            score += 15
            indicators.append("Unusually long URL")

        # @ symbol
        if "@" in url:
            score += 20
            indicators.append("URL contains @ symbol")

        # Too many subdomains
        hostname = parsed.hostname or ""

        if hostname.count(".") >= 3:
            score += 10
            indicators.append("Unusually complex domain structure")

        # IP address instead of domain
        if re.match(
            r"^(?:\d{1,3}\.){3}\d{1,3}$",
            hostname
        ):
            score += 20
            indicators.append(
                "URL uses an IP address instead of a domain"
            )

        score = min(score, 100)

        if score >= 60:
            result = "malicious"
        elif score >= 30:
            result = "suspicious"
        else:
            result = "safe"

        return {
            "result": result,
            "risk_score": score,
            "indicators": indicators
        }

    except Exception as error:

        return {
            "result": "error",
            "risk_score": 0,
            "message": str(error)
        }


# ============================================================
# EMAIL ANALYZER
# ============================================================

def analyze_email(subject, body):

    if not body:
        return {
            "result": "error",
            "risk_score": 0,
            "message": "Email content is required"
        }

    text = (
        (subject or "") +
        " " +
        body
    ).lower()

    score = 0
    indicators = []

    suspicious_words = [
        "urgent",
        "verify",
        "verification",
        "password",
        "account",
        "login",
        "click here",
        "security alert",
        "confirm",
        "suspended",
        "payment"
    ]

    for word in suspicious_words:

        if word in text:

            score += 8

            indicators.append(
                f"Suspicious phrase detected: {word}"
            )

    # Excessive exclamation marks
    if text.count("!") >= 3:

        score += 10

        indicators.append(
            "Excessive use of exclamation marks"
        )

    # URLs inside email
    urls = re.findall(
        r"https?://[^\s]+",
        body
    )

    if urls:

        indicators.append(
            f"{len(urls)} URL(s) found in email"
        )

        for url in urls[:3]:

            url_result = analyze_url(url)

            if url_result["risk_score"] > 0:

                score += min(
                    url_result["risk_score"] // 2,
                    20
                )

    score = min(score, 100)

    if score >= 60:
        result = "malicious"
    elif score >= 30:
        result = "suspicious"
    else:
        result = "safe"

    return {
        "result": result,
        "risk_score": score,
        "indicators": indicators
    }


# ============================================================
# HOME / SERVER STATUS
# ============================================================

@app.route("/")
def home():

    return jsonify({
        "application": "PhishGuard AI",
        "status": "running",
        "message": "PhishGuard AI backend is connected and running."
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/api/health")
def health():

    return jsonify({
        "success": True,
        "status": "healthy"
    })


# ============================================================
# URL SCAN API
# ============================================================

@app.route("/api/scan/url", methods=["POST"])
def scan_url():

    data = request.get_json(silent=True)

    if not data:

        return jsonify({
            "success": False,
            "message": "Request data is required"
        }), 400

    url = data.get("url", "").strip()

    result = analyze_url(url)

    if result["result"] == "error":

        return jsonify({
            "success": False,
            "message": result["message"]
        }), 400

    return jsonify({
        "success": True,
        "type": "url",
        "result": result["result"],
        "risk_score": result["risk_score"],
        "indicators": result.get("indicators", []),
        "timestamp": datetime.utcnow().isoformat()
    })


# ============================================================
# EMAIL SCAN API
# ============================================================

@app.route("/api/scan/email", methods=["POST"])
def scan_email():

    data = request.get_json(silent=True)

    if not data:

        return jsonify({
            "success": False,
            "message": "Request data is required"
        }), 400

    subject = data.get("subject", "")
    body = data.get("body", "")

    result = analyze_email(
        subject,
        body
    )

    if result["result"] == "error":

        return jsonify({
            "success": False,
            "message": result["message"]
        }), 400

    return jsonify({
        "success": True,
        "type": "email",
        "result": result["result"],
        "risk_score": result["risk_score"],
        "indicators": result.get("indicators", []),
        "timestamp": datetime.utcnow().isoformat()
    })


# ============================================================
# QR API
# ============================================================
# For now the frontend can send the URL extracted from a QR.
# Actual image decoding will be added later.

@app.route("/api/scan/qr", methods=["POST"])
def scan_qr():

    data = request.get_json(silent=True)

    if not data:

        return jsonify({
            "success": False,
            "message": "Request data is required"
        }), 400

    qr_url = data.get("url", "").strip()

    if not qr_url:

        return jsonify({
            "success": False,
            "message": "QR code URL is required"
        }), 400

    result = analyze_url(qr_url)

    return jsonify({
        "success": True,
        "type": "qr",
        "result": result["result"],
        "risk_score": result["risk_score"],
        "indicators": result.get("indicators", []),
        "extracted_url": qr_url,
        "timestamp": datetime.utcnow().isoformat()
    })


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    print("\n====================================")
    print("      PHISHGUARD AI BACKEND")
    print("====================================")
    print("Server: http://127.0.0.1:5000")
    print("Status: Running")
    print("====================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
