"""
ai_detector.py
PhishGuard AI - Hybrid Machine Learning & Heuristic Phishing Detection Engine.

Integrates local pretrained scikit-learn models for:
  - Email phishing detection (calibrated TF-IDF linear classifier)
  - URL phishing detection (calibrated lexical + character n-gram classifier)

Architecture:
  1. Local-first, privacy-preserving inference (zero external network requests for user content).
  2. Safe graceful fallback to rule-based heuristics if model weights are missing or inference fails.
  3. Transparent reporting: clearly delineates AI model probability vs heuristic indicators;
     NEVER claims a model result when inference did not run.
  4. Optional external provider hooks via environment variables (never hardcoded credentials).
"""

import os
import json
import logging
from urllib.parse import urlparse
import joblib

# Import custom transformer so joblib unpickling succeeds everywhere
from ml_features import URLLexicalFeatureExtractor, IP_PATTERN, SUSPICIOUS_TLDS, AUTH_KEYWORDS

logger = logging.getLogger("PhishGuard.AI")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
EMAIL_MODEL_PATH = os.path.join(MODELS_DIR, "email_phishing_detector.joblib")
URL_MODEL_PATH = os.path.join(MODELS_DIR, "url_phishing_detector.joblib")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")

# Global model state
_email_model = None
_url_model = None
_metadata = {}
_models_loaded = False
_load_error = None


def load_models():
    """
    Load ML models from disk with startup error handling.
    Does not crash application if models are missing or corrupted.
    """
    global _email_model, _url_model, _metadata, _models_loaded, _load_error

    try:
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                _metadata = json.load(f)

        if os.path.exists(EMAIL_MODEL_PATH):
            _email_model = joblib.load(EMAIL_MODEL_PATH)
            logger.info("Loaded Email Phishing ML model successfully.")
        else:
            logger.warning("Email model file not found at %s", EMAIL_MODEL_PATH)

        if os.path.exists(URL_MODEL_PATH):
            _url_model = joblib.load(URL_MODEL_PATH)
            logger.info("Loaded URL Phishing ML model successfully.")
        else:
            logger.warning("URL model file not found at %s", URL_MODEL_PATH)

        _models_loaded = (_email_model is not None) and (_url_model is not None)
        _load_error = None
        return _models_loaded
    except Exception as e:
        logger.error("Failed to load local ML models: %s", str(e), exc_info=True)
        _email_model = None
        _url_model = None
        _models_loaded = False
        _load_error = str(e)
        return False


# Attempt loading on initial import
load_models()


def get_engine_status():
    """Return health and status of the AI detection engine."""
    return {
        "engine": "PhishGuard Hybrid AI",
        "models_loaded": _models_loaded,
        "email_model_ready": _email_model is not None,
        "url_model_ready": _url_model is not None,
        "load_error": _load_error,
        "metadata": _metadata,
        "provider_configured": bool(os.environ.get("PHISHGUARD_AI_PROVIDER") and os.environ.get("PHISHGUARD_API_KEY")),
    }


# ---------------------------------------------------------------------------
# Explanation Generators
# ---------------------------------------------------------------------------

def _explain_email(subject, body, prob):
    """Generate a human-readable explanation based on text triggers and probability."""
    text = f"{subject or ''} {body or ''}".lower()
    triggers = []

    urgency_words = ["urgent", "immediately", "suspension", "suspended", "lockout", "24 hours", "unauthorized", "action required"]
    credential_words = ["password", "verify", "sign-in", "login", "seed phrase", "wallet", "ssn", "pin", "credentials"]
    financial_words = ["wire transfer", "invoice", "payroll", "bank", "payment", "refund", "overdue", "debit card", "crypto"]

    found_urgency = [w for w in urgency_words if w in text]
    found_cred = [w for w in credential_words if w in text]
    found_fin = [w for w in financial_words if w in text]

    if found_urgency:
        triggers.append(f"artificial urgency markers ('{', '.join(found_urgency[:2])}')")
    if found_cred:
        triggers.append(f"credential/account solicitation signals ('{', '.join(found_cred[:2])}')")
    if found_fin:
        triggers.append(f"financial or billing lures ('{', '.join(found_fin[:2])}')")

    confidence_pct = round(prob * 100, 1)

    if prob >= 0.60:
        base = f"Local ML Classifier identified high-probability phishing pattern ({confidence_pct}% threat confidence)."
        if triggers:
            return f"{base} Key detected indicators: {'; '.join(triggers)}."
        return f"{base} Linguistic structure matches known social engineering attack profiles."
    elif prob >= 0.40:
        base = f"Local ML Classifier flagged suspicious content ({confidence_pct}% threat confidence)."
        if triggers:
            return f"{base} Content exhibits cautionary signals: {'; '.join(triggers)}."
        return f"{base} Text contains atypical phrasing requiring recipient caution."
    else:
        safe_confidence = round((1 - prob) * 100, 1)
        return f"Local ML Classifier evaluated content as benign ({safe_confidence}% legitimate confidence). No adversarial linguistic patterns detected."


def _explain_url(url, prob):
    """Generate a human-readable explanation based on URL features and probability."""
    url_lower = url.lower()
    triggers = []

    if IP_PATTERN.match(url_lower):
        triggers.append("direct IP address host instead of valid domain")
    if "@" in url_lower:
        triggers.append("embedded '@' redirect obfuscation")
    if any(url_lower.endswith(tld) or f"{tld}/" in url_lower for tld in SUSPICIOUS_TLDS):
        triggers.append("abused or untrusted top-level domain")
    if any(kw in url_lower for kw in AUTH_KEYWORDS):
        triggers.append("deceptive authentication/security target keywords in URL path")
    if url_lower.count("-") >= 3:
        triggers.append("excessive hyphenation indicating domain spoofing")

    confidence_pct = round(prob * 100, 1)

    if prob >= 0.60:
        base = f"Local ML Classifier identified high-probability phishing destination ({confidence_pct}% threat confidence)."
        if triggers:
            return f"{base} Key lexical anomalies: {'; '.join(triggers)}."
        return f"{base} High character entropy and structural patterns align with deceptive attack links."
    elif prob >= 0.40:
        base = f"Local ML Classifier flagged destination as potentially suspicious ({confidence_pct}% threat confidence)."
        if triggers:
            return f"{base} Structural warnings: {'; '.join(triggers)}."
        return f"{base} Character distribution deviates from standard trusted web domains."
    else:
        safe_confidence = round((1 - prob) * 100, 1)
        return f"Local ML Classifier evaluated URL as legitimate ({safe_confidence}% safe confidence). Clean lexical structure and trusted domain formatting."


# ---------------------------------------------------------------------------
# Detection API
# ---------------------------------------------------------------------------

def detect_email(subject, body, heuristic_fn=None):
    """
    Analyzes an email using the local ML model and transparently combines with heuristics.
    Falls back to heuristics if the model is not loaded.
    """
    text = f"{subject or ''} {body or ''}".strip()
    
    # 1. Run rule-based heuristic check if provided
    heur_verdict = "safe"
    heur_score = 0
    heur_reasons = []
    if heuristic_fn:
        try:
            heur_verdict, heur_score, heur_reasons = heuristic_fn(subject, body)
        except Exception as e:
            logger.warning("Heuristic check failed: %s", e)

    # 2. Check if local ML model is loaded
    if _email_model is not None and text:
        try:
            proba = _email_model.predict_proba([text])[0]
            # proba[1] is phishing probability
            phish_prob = float(proba[1])
            ml_score = int(round(phish_prob * 100))
            ml_verdict = "phishing" if phish_prob >= 0.60 else "suspicious" if phish_prob >= 0.40 else "safe"
            ml_explanation = _explain_email(subject, body, phish_prob)

            # Combined transparent scoring:
            combined_score = max(ml_score, heur_score)
            combined_verdict = "phishing" if combined_score >= 60 else "suspicious" if combined_score >= 40 else "safe"

            combined_reasons = []
            combined_reasons.append(f"AI Model Assessment: {ml_verdict.upper()} ({round(phish_prob * 100, 1)}% probability)")
            if ml_explanation:
                combined_reasons.append(ml_explanation)
            for r in heur_reasons:
                if r not in combined_reasons:
                    combined_reasons.append(f"Heuristic Rule: {r}")

            return {
                "engine_mode": "hybrid_ai",
                "ai_powered": True,
                "model_loaded": True,
                "model_name": "PhishGuard-TFIDF-Email-Classifier-v1",
                "model_probability": round(phish_prob, 4),
                "model_score": ml_score,
                "model_verdict": ml_verdict,
                "model_explanation": ml_explanation,
                "heuristic_score": heur_score,
                "heuristic_reasons": heur_reasons,
                "verdict": combined_verdict,
                "risk_score": combined_score,
                "reasons": combined_reasons,
            }
        except Exception as e:
            logger.error("Email ML inference failed, falling back to heuristics: %s", e)

    # 3. Fallback: Report ONLY heuristic results, NEVER claim AI inference occurred
    fallback_reasons = [f"Heuristic Rule: {r}" for r in heur_reasons]
    fallback_reasons.insert(0, "Notice: Local ML model offline; scan processed via rule-based heuristic engine.")

    return {
        "engine_mode": "heuristic_fallback",
        "ai_powered": False,
        "model_loaded": False,
        "model_name": None,
        "model_probability": None,
        "model_score": None,
        "model_verdict": None,
        "model_explanation": "Local ML inference did not run. Threat evaluated via heuristic fallback rules.",
        "heuristic_score": heur_score,
        "heuristic_reasons": heur_reasons,
        "verdict": heur_verdict,
        "risk_score": heur_score,
        "reasons": fallback_reasons,
    }


def detect_url(url, heuristic_fn=None):
    """
    Analyzes a URL using the local ML model and transparently combines with heuristics.
    Falls back to heuristics if the model is not loaded.
    """
    url_clean = (url or "").strip()

    # 1. Run rule-based heuristic check
    heur_verdict = "safe"
    heur_score = 0
    heur_reasons = []
    if heuristic_fn:
        try:
            heur_verdict, heur_score, heur_reasons = heuristic_fn(url_clean)
        except Exception as e:
            logger.warning("Heuristic URL check failed: %s", e)

    # 2. Check if local ML model is loaded
    if _url_model is not None and url_clean:
        try:
            proba = _url_model.predict_proba([url_clean])[0]
            phish_prob = float(proba[1])
            ml_score = int(round(phish_prob * 100))
            ml_verdict = "phishing" if phish_prob >= 0.60 else "suspicious" if phish_prob >= 0.40 else "safe"
            ml_explanation = _explain_url(url_clean, phish_prob)

            # Combined transparent scoring:
            combined_score = max(ml_score, heur_score)
            combined_verdict = "phishing" if combined_score >= 60 else "suspicious" if combined_score >= 40 else "safe"

            combined_reasons = []
            combined_reasons.append(f"AI Model Assessment: {ml_verdict.upper()} ({round(phish_prob * 100, 1)}% probability)")
            if ml_explanation:
                combined_reasons.append(ml_explanation)
            for r in heur_reasons:
                if r not in combined_reasons:
                    combined_reasons.append(f"Heuristic Rule: {r}")

            return {
                "engine_mode": "hybrid_ai",
                "ai_powered": True,
                "model_loaded": True,
                "model_name": "PhishGuard-Lexical-URL-Classifier-v1",
                "model_probability": round(phish_prob, 4),
                "model_score": ml_score,
                "model_verdict": ml_verdict,
                "model_explanation": ml_explanation,
                "heuristic_score": heur_score,
                "heuristic_reasons": heur_reasons,
                "verdict": combined_verdict,
                "risk_score": combined_score,
                "reasons": combined_reasons,
            }
        except Exception as e:
            logger.error("URL ML inference failed, falling back to heuristics: %s", e)

    # 3. Fallback: Report ONLY heuristic results, NEVER claim AI inference occurred
    fallback_reasons = [f"Heuristic Rule: {r}" for r in heur_reasons]
    fallback_reasons.insert(0, "Notice: Local ML model offline; scan processed via rule-based heuristic engine.")

    return {
        "engine_mode": "heuristic_fallback",
        "ai_powered": False,
        "model_loaded": False,
        "model_name": None,
        "model_probability": None,
        "model_score": None,
        "model_verdict": None,
        "model_explanation": "Local ML inference did not run. Threat evaluated via heuristic fallback rules.",
        "heuristic_score": heur_score,
        "heuristic_reasons": heur_reasons,
        "verdict": heur_verdict,
        "risk_score": heur_score,
        "reasons": fallback_reasons,
    }
