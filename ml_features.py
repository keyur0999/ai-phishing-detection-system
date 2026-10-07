"""
ml_features.py
Feature extractors and transformers for PhishGuard AI models.
"""

import re
import math
from urllib.parse import urlparse
from sklearn.base import BaseEstimator, TransformerMixin

# Precompiled patterns for lexical URL analysis
IP_PATTERN = re.compile(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".work", ".zip", ".biz", ".country", ".kim", ".science"}
AUTH_KEYWORDS = [
    "verify", "login", "signin", "secure", "account", "update", "password", 
    "wallet", "banking", "confirm", "security", "token", "auth", "support", 
    "recover", "billing", "invoice", "claim", "free", "urgent"
]

# Recognized top global domains (for benign lexical baseline)
TOP_TRUSTED_DOMAINS = {
    "google.com", "google.co.in", "google.co.uk", "youtube.com", "microsoft.com", 
    "apple.com", "amazon.com", "github.com", "wikipedia.org", "cloudflare.com", 
    "netflix.com", "linkedin.com", "twitter.com", "x.com", "facebook.com", 
    "instagram.com", "stackoverflow.com", "python.org", "mozilla.org", "cnn.com", 
    "bbc.com", "reddit.com", "nytimes.com", "gitlab.com", "medium.com", 
    "scikit-learn.org", "flask.palletsprojects.com", "pypi.org", "arxiv.org"
}


def extract_registered_domain(url_or_host):
    """Extract the base registered domain (e.g. google.com from https://www.google.com or www.google.com)."""
    if not url_or_host:
        return ""
    clean = str(url_or_host).strip().lower()
    try:
        if "://" in clean:
            parsed = urlparse(clean)
            host = parsed.netloc or parsed.path.split("/")[0]
        else:
            host = clean.split("/")[0]
        host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return clean


def is_known_trusted_domain(url_str):
    """Check if the URL belongs to a verified trusted authority domain."""
    try:
        clean = url_str.strip().lower()
        if "://" not in clean:
            clean = "http://" + clean
        parsed = urlparse(clean)
        host = (parsed.netloc or parsed.path.split("/")[0]).split(":")[0]
        # Remove www.
        if host.startswith("www."):
            host = host[4:]
        reg = extract_registered_domain(host)
        return (host in TOP_TRUSTED_DOMAINS) or (reg in TOP_TRUSTED_DOMAINS)
    except Exception:
        return False


class URLLexicalFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts normalized, bounded [0.0, 1.0] lexical and structural features
    from URL strings for machine learning classification.
    """

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for url in X:
            url_str = str(url).strip().lower()
            length = len(url_str)
            
            try:
                parsed = urlparse(url_str if "://" in url_str else "http://" + url_str)
                host = parsed.netloc or parsed.path.split("/")[0]
            except Exception:
                host = url_str

            dot_count = host.count(".")
            dash_count = host.count("-")
            
            # Shannon Entropy calculation of character distribution
            prob = [url_str.count(c) / length for c in set(url_str)]
            entropy = -sum(p * math.log2(p) for p in prob) if length > 0 else 0.0

            # Normalized bounded indicators (all strictly between 0.0 and 1.0)
            len_penalty = 1.0 if length > 80 else (length / 80.0)
            subdomain_penalty = 1.0 if dot_count >= 3 else (0.5 if dot_count == 2 and not host.startswith("www.") else 0.0)
            hyphen_penalty = 1.0 if dash_count >= 2 else (0.5 if dash_count == 1 else 0.0)
            entropy_penalty = 1.0 if entropy > 4.4 else (0.5 if entropy > 4.0 else 0.0)
            digit_ratio = sum(c.isdigit() for c in url_str) / max(length, 1)

            has_ip = 1.0 if IP_PATTERN.match(url_str) else 0.0
            has_at = 1.0 if "@" in url_str else 0.0
            has_suspicious_tld = 1.0 if any(url_str.endswith(tld) or f"{tld}/" in url_str for tld in SUSPICIOUS_TLDS) else 0.0
            has_auth_keyword = 1.0 if any(kw in url_str for kw in AUTH_KEYWORDS) else 0.0
            is_trusted = 1.0 if is_known_trusted_domain(url_str) else 0.0

            features.append([
                len_penalty,
                subdomain_penalty,
                hyphen_penalty,
                entropy_penalty,
                digit_ratio,
                has_ip,
                has_at,
                has_suspicious_tld,
                has_auth_keyword,
                is_trusted,
            ])

        return features
