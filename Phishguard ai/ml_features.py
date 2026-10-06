"""
ml_features.py
Feature extractors and transformers for PhishGuard AI models.
"""

import re
import math
from sklearn.base import BaseEstimator, TransformerMixin

# Precompiled patterns for lexical URL analysis
IP_PATTERN = re.compile(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".work", ".zip", ".biz"}
AUTH_KEYWORDS = [
    "verify", "login", "signin", "secure", "account", "update", "password", 
    "wallet", "banking", "confirm", "security", "token", "auth", "support", 
    "recover", "billing", "invoice", "claim", "free", "urgent"
]


class URLLexicalFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts numerical structural, lexical, and information-theoretic (Shannon entropy)
    features from URL strings for machine learning classification.
    """

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for url in X:
            url_str = str(url).strip().lower()
            length = len(url_str)
            dot_count = url_str.count(".")
            dash_count = url_str.count("-")
            slash_count = url_str.count("/")
            digit_count = sum(c.isdigit() for c in url_str)
            digit_ratio = digit_count / max(length, 1)

            # Shannon Entropy calculation of character distribution
            prob = [url_str.count(c) / length for c in set(url_str)]
            entropy = -sum(p * math.log2(p) for p in prob) if length > 0 else 0.0

            has_ip = 1.0 if IP_PATTERN.match(url_str) else 0.0
            has_at = 1.0 if "@" in url_str else 0.0
            has_suspicious_tld = 1.0 if any(url_str.endswith(tld) or f"{tld}/" in url_str for tld in SUSPICIOUS_TLDS) else 0.0
            has_auth_keyword = 1.0 if any(kw in url_str for kw in AUTH_KEYWORDS) else 0.0

            features.append([
                length,
                dot_count,
                dash_count,
                slash_count,
                digit_ratio,
                entropy,
                has_ip,
                has_at,
                has_suspicious_tld,
                has_auth_keyword,
            ])

        return features
