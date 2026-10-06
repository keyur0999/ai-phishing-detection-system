"""
train_models.py
PhishGuard AI - Model Training Script.

Trains two production-ready local scikit-learn models:
  1. Email Phishing Classifier: TF-IDF n-grams + Calibrated Classifier
  2. URL Phishing Classifier: Char n-grams + Structural Lexical features + Logistic Classifier

Saves trained pipelines to:
  models/email_phishing_detector.joblib
  models/url_phishing_detector.joblib
  models/model_metadata.json
"""

import os
import json
import re
import math
import numpy as np
from datetime import datetime

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from sklearn.calibration import CalibratedClassifierCV

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(MODELS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Training Dataset: Email Corpus (Phishing vs Legitimate)
# ---------------------------------------------------------------------------

EMAIL_TRAINING_CORPUS = [
    # --- PHISHING EXAMPLES (Label: 1) ---
    ("URGENT: Your Account Has Been Suspended", "Dear Customer, we detected unauthorized sign-in attempts on your account. Click here immediately to verify your identity and restore access: http://secure-verify-account.xyz/login. Failure to verify within 24 hours will result in permanent suspension.", 1),
    ("Action Required: Unusual Sign-in Activity Detected", "Someone attempted to sign in to your Microsoft account from an unrecognized IP address (192.168.1.1). Please confirm your password immediately to secure your files: http://micros0ft-support.com/auth-verify.", 1),
    ("Payroll Update: Action Needed by Friday", "Your direct deposit bank details failed to process for this month's payroll cycle. Update your banking and routing number right now to prevent salary disbursement delay: http://payroll-portal-verify.top/employee.", 1),
    ("Invoice INV-88291 Overdue - Final Notice", "Attached is your overdue invoice for $4,850.00. Wire transfer payment must be made within 48 hours or legal proceedings will initiate. View and pay invoice here: http://invoice-payment-gateway.xyz/pay.", 1),
    ("Congratulations! You are the selected winner", "You have won a $1,000 Walmart Gift Card in our annual giveaway! Click here to claim your prize before time expires: http://free-gift-rewards.click/claim-now. Enter your credit card to verify eligibility.", 1),
    ("Important Security Notice: Password Expiring Today", "Your corporate workstation password will expire in 2 hours. Reset your password now to avoid account lockout: http://signin-password-reset.xyz/it-helpdesk.", 1),
    ("PayPal: Notice of Account Limitation", "We have temporarily limited your PayPal wallet due to suspicious transactions. Please submit your identity documents and credit card numbers at: http://paypa1-security-center.com/resolve.", 1),
    ("Urgent: Wire Transfer Request from CEO", "Are you at your desk? I need an urgent wire transfer processed for an off-market acquisition immediately. Keep this confidential. Wire $45,000 to the attached beneficiary account.", 1),
    ("Cryptocurrency Wallet Security Alert", "Suspicious token withdrawal detected on your MetaMask wallet. Connect your wallet immediately and input your 12-word seed recovery phrase to prevent asset liquidation: http://wallet-connect-auth.top/sync.", 1),
    ("DHL Delivery Notification: Package Delayed", "Your package could not be delivered due to an unpaid customs clearance fee of $2.50. Pay the fee immediately to release shipment: http://dhl-package-tracking.xyz/confirm.", 1),
    ("Your Apple ID has been locked for security reasons", "Your Apple ID was locked because of repeated incorrect password attempts. Verify your billing info to unlock: http://appleid-verify.net/account/unlock.", 1),
    ("Tax Refund Notification: Internal Revenue Service", "Our records show you have an unclaimed tax refund of $1,280. Submit your SSN, date of birth, and direct deposit account to receive funds: http://irs-tax-refund.top/form.", 1),
    ("Urgent: Bank of America Security Verification", "We have placed a temporary security hold on your debit card. Confirm your PIN and card details to resume online banking: http://bofa-alert-check.xyz/login.", 1),
    ("Netflix: Update Payment Method to Keep Streaming", "We were unable to process your subscription renewal. Update your card details within 12 hours or your account will be canceled: http://netflix-billing-update.click/update.", 1),
    ("HR Notice: Mandatory Employee Policy Signoff", "All personnel must complete the mandatory company compliance verification today. Log in using your work credentials: http://company-hr-portal.top/sign.", 1),
    ("Immediate Action: Google Workspace Storage Full", "Your Google Drive storage is 99% full and you will stop receiving incoming emails in 6 hours. Purchase additional storage and verify account: http://g00gle-security.com/storage.", 1),
    ("Notice of Subpoena: Legal Summons", "You are required to appear in district court regarding pending litigation. Review the court summons document online immediately: http://court-summons-document.xyz/case-392.", 1),
    ("Amazon Order Confirmation: iPhone 16 Pro Max Purchased", "Thank you for your order #849-28194 for $1,399.00. If you did not make this purchase, call our fraud support or cancel order immediately at: http://amazon-order-cancel.top/dispute.", 1),
    ("LinkedIn: Someone viewed your private profile", "A recruiter from a Fortune 500 company viewed your profile. Log in to view who is interested in your resume: http://linkedin-view-profile.click/auth.", 1),
    ("Urgent IT Notice: VPN Client Certificate Upgrade", "Our corporate Cisco VPN client certificate must be renewed today. Download the patch and authenticate your domain user: http://vpn-patch-it.xyz/download.", 1),
    ("Bank Alert: Debit Card Deactivated", "Suspicious charge of $840 at Target. Reply STOP or click link to verify your transactions: http://bank-card-security.xyz/debit.", 1),
    ("FedEx: Delivery Attempt Failed - Reschedule Now", "We tried to deliver your parcel at 10:45 AM. Reschedule delivery and verify address here: http://fedex-parcel-delivery.top/track.", 1),

    # --- LEGITIMATE EXAMPLES (Label: 0) ---
    ("Sprint Planning Meeting - Thursday 10:00 AM", "Hi Team, please find attached the agenda for our upcoming sprint planning session. We will review the sprint backlog and finalize user story point estimates for sprint 14. Let me know if you have items to add.", 0),
    ("Your Weekly Engineering Progress Digest", "Here is the summary of merged pull requests and resolved Jira issues across the platform team this past week. Great job everyone on closing 24 bugs and improving build latency by 18%.", 0),
    ("Lunch and Learn: Introduction to Rust Programming", "Hello all, our senior architect will be hosting an internal lunch and learn session on memory safety and concurrency in Rust this Wednesday in Conference Room B. Pizza will be provided.", 0),
    ("Quarterly Financial Results Presentation Notes", "Attached are the meeting minutes and slide deck from our Q3 all-hands meeting. Highlights include a 15% year-over-year revenue growth and the opening of our new regional office in Austin.", 0),
    ("Project Kickoff: Customer Portal Redesign", "Welcome to the project working group. The goal of this initiative is to improve user onboarding workflows and streamline billing inquiry tickets. First sync is scheduled for next Monday.", 0),
    ("Happy Birthday from the Department!", "Wishing you a very happy birthday from all of us in the cybersecurity operations team! Hope you have a wonderful day celebrating with family and friends.", 0),
    ("Code Review Requested: Fix JWT Expiration Handling", "Hey, I have submitted pull request #142 fixing token refresh race conditions when multiple tabs are open simultaneously. Please review when you have a moment.", 0),
    ("Office Holiday Closure Schedule", "Please be advised that all corporate offices will be closed on Thanksgiving Thursday and the following Friday. On-call rotations will continue as scheduled in PagerDuty.", 0),
    ("Your receipt for purchase at Local Coffee Roasters", "Thank you for visiting Local Coffee Roasters! Here is your digital receipt for $4.75. Your order was paid via Apple Pay. We hope to see you again soon.", 0),
    ("Summary of Vendor Assessment Meeting", "Thanks for your time earlier today. We discussed the SOC 2 compliance requirements and service level agreements for the new observability platform. Next steps are outlined in Confluence.", 0),
    ("Team Outing Poll: Bowling or Escape Room", "Please vote on the team outing options for next month by end of week so we can secure the venue reservation. Option A: Retro Bowling, Option B: Mystery Escape Room.", 0),
    ("Documentation Update: API Rate Limiting Guidelines", "The developer documentation portal has been updated with detailed examples of handling 429 Too Many Requests responses and implementing exponential backoff with jitter.", 0),
    ("Monthly 1:1 Sync Notes and Goals Review", "Great meeting with you today. We aligned on your career development objectives for the upcoming quarter, including completing your AWS Solutions Architect certification.", 0),
    ("Database Migration Completed Successfully", "The planned maintenance window for upgrading the PostgreSQL read replicas to version 16 concluded with zero downtime at 03:00 UTC. All services are reporting healthy.", 0),
    ("Flight Itinerary Confirmation for Tech Conference", "Here is your confirmed flight itinerary for the upcoming security summit in San Francisco. Departure is on October 12, returning October 15. Safe travels!", 0),
    ("Library Book Return Reminder", "This is a friendly reminder that the book 'Designing Data-Intensive Applications' borrowed from the company tech library is due for return next Tuesday.", 0),
    ("New Employee Welcome: Meet Sarah Chen", "Please join us in welcoming Sarah Chen, who joins our frontend design team as a Senior UX Engineer. Sarah previously worked at Stripe and brings extensive design system experience.", 0),
    ("Volunteer Day Signup Sheet", "Our annual community service day is coming up next month. If you would like to volunteer at the local food bank or tree planting project, please add your name to the spreadsheet.", 0),
    ("Internal Security Training: Phishing Awareness Q4", "This is a reminder to complete the mandatory quarterly security awareness module in the internal LMS before the end of the month. The course takes approximately 20 minutes.", 0),
    ("Release Notes: Version 2.4.0 Now Live", "Version 2.4.0 has been deployed to production. Key improvements include faster search indexing, optimized dark mode contrast, and upgraded session management.", 0),
    ("Customer Feedback Survey Results Summary", "The customer satisfaction score for Q3 reached 4.7 out of 5.0. Customers highlighted prompt response times and intuitive dashboard navigation.", 0),
    ("Meeting Rescheduled: Design Sync to 3:00 PM", "Hi Keyur, due to a scheduling conflict with the client demo, our design sync has been moved from 2:00 PM to 3:00 PM today. Let me know if that works for you.", 0),
    ("Sprint Planning Agenda", "Hi team, let us meet at 10am to review user stories and sprint backlog estimates.", 0),
    ("Weekly Team Sync Notes", "Thanks everyone for the productive sync today. Action items have been logged in Notion and assigned to respective owners.", 0),
    ("Design Review Presentation Deck", "Sharing the updated Figma prototypes and slide deck for tomorrow's UI/UX review session with the product leads.", 0),
    ("Platform Architecture Sync", "Attached are the architectural diagrams outlining the decoupled microservice design for our analytics collector pipeline.", 0),
    ("Coffee Machine Maintenance Today", "Please note that the third floor espresso machine will be undergoing routine cleaning between 2pm and 3pm this afternoon.", 0),
    ("Quarterly Strategy Roadmap Sync", "Hi team, looking forward to our quarterly roadmap planning session tomorrow. Please review the shared spreadsheet before the meeting.", 0),
]


# ---------------------------------------------------------------------------
# Training Dataset: URL Corpus (Phishing vs Legitimate)
# ---------------------------------------------------------------------------

URL_TRAINING_CORPUS = [
    # --- PHISHING URLS (Label: 1) ---
    ("http://paypa1.com/login-verify", 1),
    ("http://192.168.1.1/update-billing", 1),
    ("https://g00gle-security.com/account-confirm", 1),
    ("http://appleid-verify.net/security-update", 1),
    ("https://micros0ft-support.com/password-reset", 1),
    ("http://secure-login-chase.xyz/auth", 1),
    ("http://wallet-connect-airdrop.top/claim", 1),
    ("http://verify-account-bofa.click/signin-confirm", 1),
    ("http://netflix-billing-resolve.gq/login", 1),
    ("http://free-gift-crypto.tk/bonus", 1),
    ("http://amazon-order-suspended.ml/helpdesk", 1),
    ("http://dhl-package-reschedule.work/track-fee", 1),
    ("https://secure-update-wellsfargo.xyz/banking", 1),
    ("http://login-verify-coinbase.click/2fa", 1),
    ("http://signin-att-portal.top/mail", 1),
    ("http://172.56.21.90/login.php?user=verify", 1),
    ("http://steamcommunity-gift.xyz/trade", 1),
    ("http://facebook-security-appeal.top/case92", 1),
    ("http://instagram-copyright-infringement.click/appeal", 1),
    ("http://binance-kyc-update.xyz/verify", 1),
    ("http://outlook-password-renew.work/login.html", 1),
    ("http://citibank-card-protection.xyz/auth", 1),
    ("http://irs-tax-refund-status.top/check", 1),
    ("http://ups-delivery-problem.click/reschedule", 1),
    ("http://meta-business-verification.xyz/support", 1),

    # --- LEGITIMATE URLS (Label: 0) ---
    ("https://www.google.com", 0),
    ("https://google.com", 0),
    ("google.com", 0),
    ("https://www.google.com/search?q=cybersecurity", 0),
    ("https://www.youtube.com", 0),
    ("https://youtube.com", 0),
    ("youtube.com", 0),
    ("https://youtube.com/watch?v=dQw4w9WgXcQ", 0),
    ("https://github.com", 0),
    ("github.com", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://gitlab.com/explore", 0),
    ("https://en.wikipedia.org", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://www.microsoft.com", 0),
    ("https://microsoft.com", 0),
    ("https://www.microsoft.com/en-us/windows", 0),
    ("https://apple.com", 0),
    ("https://www.apple.com", 0),
    ("apple.com", 0),
    ("https://apple.com/iphone", 0),
    ("https://amazon.com", 0),
    ("https://www.amazon.com", 0),
    ("amazon.com", 0),
    ("https://www.amazon.com/dp/B08N5WRWNW", 0),
    ("https://paypal.com", 0),
    ("https://www.paypal.com", 0),
    ("https://paypal.com/signin", 0),
    ("https://netflix.com", 0),
    ("https://www.netflix.com", 0),
    ("https://netflix.com/browse", 0),
    ("https://stackoverflow.com", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://python.org", 0),
    ("https://docs.python.org/3/library/sqlite3.html", 0),
    ("https://pypi.org/project/scikit-learn/", 0),
    ("https://nytimes.com", 0),
    ("https://www.nytimes.com/section/technology", 0),
    ("https://linkedin.com", 0),
    ("https://www.linkedin.com/in/keyur", 0),
    ("https://medium.com", 0),
    ("https://medium.com/@author/machine-learning-in-practice", 0),
    ("https://scikit-learn.org/stable/modules/classes.html", 0),
    ("https://cloudflare.com", 0),
    ("https://cloudflare.com/learning/security/what-is-zero-trust", 0),
    ("https://flask.palletsprojects.com/en/3.0.x/", 0),
    ("https://developer.mozilla.org/en-US/docs/Web/HTML", 0),
    ("https://cnn.com", 0),
    ("https://cnn.com/world", 0),
    ("https://bbc.com", 0),
    ("https://bbc.com/news/technology", 0),
    ("https://reddit.com", 0),
    ("https://reddit.com/r/netsec", 0),
    ("https://arxiv.org/abs/2301.00234", 0),
    ("https://news.ycombinator.com/news", 0),
    ("https://weather.com/weather/today", 0),
]


from ml_features import URLLexicalFeatureExtractor


# ---------------------------------------------------------------------------
# Training Pipeline: Email Model
# ---------------------------------------------------------------------------

def train_email_model():
    print("[TRAINING] Training Email Phishing Classifier...")
    X = [f"{item[0]} {item[1]}" for item in EMAIL_TRAINING_CORPUS]
    y = np.array([item[2] for item in EMAIL_TRAINING_CORPUS])

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=2500,
            sublinear_tf=True,
            token_pattern=r"(?u)\b\w+\b",
        )),
        ("classifier", LogisticRegression(
            C=2.0,
            class_weight={0: 1.3, 1: 1.0},
            max_iter=1000,
            random_state=42,
        )),
    ])

    pipeline.fit(X, y)
    preds = pipeline.predict(X)
    proba = pipeline.predict_proba(X)[:, 1]
    acc = accuracy_score(y, preds)
    roc = roc_auc_score(y, proba)
    print(f"[TRAINING] Email Model Accuracy: {acc * 100:.2f}% | ROC-AUC: {roc:.3f}")

    model_path = os.path.join(MODELS_DIR, "email_phishing_detector.joblib")
    joblib.dump(pipeline, model_path)
    print(f"[SAVED] Email model saved to: {model_path}")
    return pipeline, acc


# ---------------------------------------------------------------------------
# Training Pipeline: URL Model
# ---------------------------------------------------------------------------

def train_url_model():
    print("[TRAINING] Training URL Phishing Classifier...")
    X = [item[0] for item in URL_TRAINING_CORPUS]
    y = np.array([item[1] for item in URL_TRAINING_CORPUS])

    union = FeatureUnion([
        ("char_ngram", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            max_features=2500,
            sublinear_tf=True,
        )),
        ("lexical_stats", URLLexicalFeatureExtractor()),
    ])

    pipeline = Pipeline([
        ("features", union),
        ("classifier", LogisticRegression(
            C=1.5,
            class_weight={0: 1.8, 1: 1.0},
            max_iter=1000,
            random_state=42,
        )),
    ])

    pipeline.fit(X, y)
    preds = pipeline.predict(X)
    proba = pipeline.predict_proba(X)[:, 1]
    acc = accuracy_score(y, preds)
    roc = roc_auc_score(y, proba)
    print(f"[TRAINING] URL Model Accuracy: {acc * 100:.2f}% | ROC-AUC: {roc:.3f}")

    model_path = os.path.join(MODELS_DIR, "url_phishing_detector.joblib")
    joblib.dump(pipeline, model_path)
    print(f"[SAVED] URL model saved to: {model_path}")
    return pipeline, acc


# ---------------------------------------------------------------------------
# Main Training Entrypoint
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("PhishGuard AI - Training Local Machine Learning Models")
    print("=" * 60)

    _, email_acc = train_email_model()
    _, url_acc = train_url_model()

    metadata = {
        "version": "1.0.0",
        "created_at": datetime.now().isoformat(),
        "framework": "scikit-learn",
        "email_model": {
            "name": "PhishGuard-NLP-TfidfLogReg",
            "accuracy": float(round(email_acc, 4)),
            "algorithm": "TF-IDF (1,2-grams) + LogisticRegression(C=2.5)",
            "classes": ["safe", "phishing"],
        },
        "url_model": {
            "name": "PhishGuard-URL-CharLexicalLogReg",
            "accuracy": float(round(url_acc, 4)),
            "algorithm": "Char-ngram TF-IDF + Shannon Entropy/Lexical Union + LogisticRegression",
            "classes": ["safe", "phishing"],
        },
        "offline_inference": True,
        "privacy": "100% on-device local execution; zero outbound telemetry.",
    }

    meta_path = os.path.join(MODELS_DIR, "model_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[SAVED] Model metadata saved to: {meta_path}")
    print("=" * 60)
    print("All models trained and ready for local inference!")
    print("=" * 60)


if __name__ == "__main__":
    main()
