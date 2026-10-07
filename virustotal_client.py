"""
virustotal_client.py
PhishGuard AI - VirusTotal Threat Intelligence Integration.

Connects to VirusTotal v3 API to identify and verify legitimate threats
across 70+ global antivirus and cybersecurity threat intelligence engines.
"""

import os
import re
import time
import base64
import logging
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv

# Ensure environment variables from .env are loaded
load_dotenv()

logger = logging.getLogger("PhishGuard.VirusTotal")

# Default fallback to user-provided key if not overridden in environment
DEFAULT_KEY = "8340f5b59df41d8861dfb077c451a48edc36d655a35ca24c3ccad226393770f8"
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip() or DEFAULT_KEY
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# In-memory cache to save API quota and provide fast repeated lookups
# Format: { key: (timestamp, result_dict) }
_CACHE = {}
CACHE_TTL = 900  # 15 minutes

URL_REGEX = re.compile(r"https?://[^\s<>\"'{}|\\^`]+", re.IGNORECASE)


def get_api_key():
    """Returns currently configured VirusTotal API key."""
    return os.environ.get("VIRUSTOTAL_API_KEY", "").strip() or VT_API_KEY


def is_configured():
    """Checks if a valid-length VirusTotal API key is present."""
    k = get_api_key()
    return bool(k and len(k) >= 32)


def get_status():
    """Returns operational status of the VirusTotal integration."""
    return {
        "service": "VirusTotal v3 Threat Intelligence",
        "configured": is_configured(),
        "key_masked": f"{get_api_key()[:6]}...{get_api_key()[-4:]}" if is_configured() else None,
        "cache_entries": len(_CACHE)
    }


def _cache_get(key):
    now = time.time()
    if key in _CACHE:
        ts, data = _CACHE[key]
        if now - ts < CACHE_TTL:
            return data
        else:
            del _CACHE[key]
    return None


def _cache_set(key, data):
    _CACHE[key] = (time.time(), data)


def _encode_url_id(url):
    """
    Computes VirusTotal v3 URL identifier:
    Base64 URL-safe encoding without '=' padding.
    """
    return base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("utf-8").rstrip("=")


def _extract_domain(url_or_str):
    """Safely extracts domain name from URL or raw domain string."""
    target = url_or_str.strip().lower()
    if "://" not in target:
        target = "http://" + target
    try:
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path.split("/")[0]
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain
    except Exception:
        return url_or_str.strip().lower()


def check_domain(domain, timeout=6):
    """
    Queries VirusTotal v3 Domain endpoint:
    GET /api/v3/domains/{domain}
    """
    api_key = get_api_key()
    if not api_key:
        return {"checked": False, "error": "VirusTotal API key not configured."}

    clean_domain = _extract_domain(domain)
    if not clean_domain:
        return {"checked": False, "error": "Invalid domain."}

    cached = _cache_get(f"domain:{clean_domain}")
    if cached:
        return cached

    headers = {"x-apikey": api_key, "User-Agent": "PhishGuard-AI/2.0"}
    try:
        resp = requests.get(
            f"{VT_BASE_URL}/domains/{clean_domain}",
            headers=headers,
            timeout=timeout
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            reputation = attrs.get("reputation", 0)

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            flagged_vendors = []
            for vendor_name, vendor_data in results.items():
                cat = vendor_data.get("category")
                res = vendor_data.get("result", "")
                if cat in ("malicious", "suspicious"):
                    flagged_vendors.append({
                        "engine": vendor_name,
                        "category": cat,
                        "result": res or cat
                    })

            # Import known trusted check to avoid outlier false positives on apex platforms
            from ml_features import is_known_trusted_domain

            # Threat classification with false positive defense for trusted authority domains
            is_trusted = is_known_trusted_domain(clean_domain) or reputation >= 100
            if is_trusted and malicious <= 3 and harmless >= 30:
                is_threat = False
                threat_level = "safe"
                summary = f"Verified clean authority domain across {harmless}/{total} engines (reputation score +{reputation})."
            else:
                is_threat = (malicious >= 2) or (malicious >= 1 and suspicious >= 1)
                threat_level = "phishing" if malicious >= 2 else ("suspicious" if (malicious >= 1 or suspicious >= 2) else "safe")
                vendors_sample = ", ".join([f"{v['engine']}: {v['result']}" for v in flagged_vendors[:3]])
                if is_threat or malicious > 0:
                    summary = f"Flagged by {malicious}/{total} security engines as threat ({vendors_sample})."
                elif harmless >= 20:
                    summary = f"Verified clean across {harmless}/{total} security engines (0 detections)."
                else:
                    summary = f"Scanned by {total} engines (0 detections)."

            res_dict = {
                "checked": True,
                "target": clean_domain,
                "target_type": "domain",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total,
                "reputation": reputation,
                "flagged_vendors": flagged_vendors,
                "flagged_count": len(flagged_vendors),
                "is_threat": is_threat,
                "threat_level": threat_level,
                "summary": summary,
                "permalink": f"https://www.virustotal.com/gui/domain/{clean_domain}"
            }
            _cache_set(f"domain:{clean_domain}", res_dict)
            return res_dict
        elif resp.status_code == 404:
            return {"checked": False, "target": clean_domain, "error": "Domain not found in VirusTotal database"}
        elif resp.status_code == 429:
            logger.warning("VirusTotal API quota reached (HTTP 429).")
            return {"checked": False, "error": "VirusTotal API rate limit reached."}
        else:
            return {"checked": False, "error": f"VirusTotal HTTP {resp.status_code}"}
    except Exception as ex:
        logger.warning("VirusTotal domain check failed: %s", str(ex))
        return {"checked": False, "error": str(ex)}


def check_url(url, timeout=6):
    """
    Queries VirusTotal v3 URL endpoint:
    GET /api/v3/urls/{url_id}
    Falls back to domain reputation if the specific URL path is not yet indexed.
    """
    api_key = get_api_key()
    if not api_key:
        return {"checked": False, "error": "VirusTotal API key not configured."}

    clean_url = (url or "").strip()
    if not clean_url:
        return {"checked": False, "error": "Empty URL."}

    cached = _cache_get(f"url:{clean_url}")
    if cached:
        return cached

    url_id = _encode_url_id(clean_url)
    headers = {"x-apikey": api_key, "User-Agent": "PhishGuard-AI/2.0"}

    try:
        resp = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=headers,
            timeout=timeout
        )

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            reputation = attrs.get("reputation", 0)

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            flagged_vendors = []
            for vendor_name, vendor_data in results.items():
                cat = vendor_data.get("category")
                res = vendor_data.get("result", "")
                if cat in ("malicious", "suspicious"):
                    flagged_vendors.append({
                        "engine": vendor_name,
                        "category": cat,
                        "result": res or cat
                    })

            # Import known trusted check to avoid outlier false positives on apex platforms
            from ml_features import is_known_trusted_domain
            domain = _extract_domain(clean_url)
            is_trusted = is_known_trusted_domain(domain) or reputation >= 100

            if is_trusted and malicious <= 3 and harmless >= 30:
                is_threat = False
                threat_level = "safe"
                summary = f"Verified clean authority destination across {harmless}/{total} engines (reputation score +{reputation})."
            else:
                is_threat = (malicious >= 2) or (malicious >= 1 and suspicious >= 1)
                threat_level = "phishing" if malicious >= 2 else ("suspicious" if (malicious >= 1 or suspicious >= 2) else "safe")
                vendors_sample = ", ".join([f"{v['engine']}: {v['result']}" for v in flagged_vendors[:3]])
                if is_threat or malicious > 0:
                    summary = f"Flagged by {malicious}/{total} security engines as threat ({vendors_sample})."
                elif harmless >= 20:
                    summary = f"Verified clean across {harmless}/{total} security engines (0 detections)."
                else:
                    summary = f"Scanned by {total} engines (0 detections)."

            res_dict = {
                "checked": True,
                "target": clean_url,
                "target_type": "url",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total,
                "reputation": reputation,
                "flagged_vendors": flagged_vendors,
                "flagged_count": len(flagged_vendors),
                "is_threat": is_threat,
                "threat_level": threat_level,
                "summary": summary,
                "permalink": f"https://www.virustotal.com/gui/url/{url_id}"
            }
            _cache_set(f"url:{clean_url}", res_dict)
            return res_dict

        elif resp.status_code == 404:
            # URL not in VirusTotal database yet -> fall back to checking the domain
            domain = _extract_domain(clean_url)
            domain_result = check_domain(domain, timeout=timeout)
            if domain_result.get("checked"):
                domain_result["target"] = clean_url
                _cache_set(f"url:{clean_url}", domain_result)
                return domain_result
            return {
                "checked": False,
                "target": clean_url,
                "error": "URL and domain not yet cataloged in VirusTotal database"
            }

        elif resp.status_code == 429:
            logger.warning("VirusTotal API quota reached (HTTP 429).")
            return {"checked": False, "error": "VirusTotal API rate limit reached."}
        else:
            return {"checked": False, "error": f"VirusTotal HTTP {resp.status_code}"}

    except Exception as ex:
        logger.warning("VirusTotal URL check failed: %s", str(ex))
        return {"checked": False, "error": str(ex)}


def check_email_content(subject, body):
    """
    Extracts embedded URLs from email and scans them through VirusTotal.
    Aggregates threat findings across all links.
    """
    text = f"{subject or ''} {body or ''}"
    urls = list(dict.fromkeys(URL_REGEX.findall(text)))

    if not urls:
        return {
            "checked": False,
            "has_urls": False,
            "message": "No embedded URLs found in email to query VirusTotal."
        }

    link_results = []
    max_malicious = 0
    worst_threat = False
    flagged_links = []

    # Check up to 3 embedded links to respect rate limits
    for link in urls[:3]:
        vt_res = check_url(link)
        link_results.append({"url": link, "result": vt_res})
        if vt_res.get("checked"):
            mal = vt_res.get("malicious", 0)
            if mal > max_malicious:
                max_malicious = mal
            if vt_res.get("is_threat"):
                worst_threat = True
                flagged_links.append({
                    "url": link,
                    "malicious": mal,
                    "summary": vt_res.get("summary")
                })

    threat_level = "phishing" if worst_threat or max_malicious >= 2 else ("suspicious" if max_malicious >= 1 else "safe")

    return {
        "checked": True,
        "has_urls": True,
        "scanned_links_count": len(link_results),
        "total_urls_found": len(urls),
        "worst_malicious_count": max_malicious,
        "is_threat": worst_threat,
        "threat_level": threat_level,
        "flagged_links": flagged_links,
        "link_results": link_results,
        "summary": (
            f"Flagged {len(flagged_links)} embedded link(s) as malicious via VirusTotal."
            if flagged_links else
            f"Verified {len(link_results)} embedded link(s) clean via VirusTotal."
        )
    }
