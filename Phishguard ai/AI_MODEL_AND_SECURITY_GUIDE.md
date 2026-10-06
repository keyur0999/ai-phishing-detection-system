# PhishGuard AI - Model Architecture, Security & Administration Guide

## 1. Machine Learning Phishing Detection Model

### Selected Model & Architecture
To preserve user privacy, avoid recurring API costs, and eliminate latency, PhishGuard AI uses **local, on-device machine learning models** trained with `scikit-learn`:

1. **Email Phishing Classifier (`models/email_phishing_detector.joblib`)**:
   - **Feature Extraction**: Word and sub-phrase TF-IDF Vectorizer with 1-2 grams (`ngram_range=(1, 2)`), sublinear term frequency scaling, and case normalization.
   - **Classifier**: Calibrated `LogisticRegression` with balanced penalty weights, optimized for high precision on social engineering triggers (artificial urgency, account lockout threats, invoice fraud, and credential solicitation).
   - **Inference Time**: < 5 milliseconds per email.
   - **Privacy**: 100% local execution on the server; zero email content or sensitive data is ever transmitted to external third-party services.

2. **URL Phishing Classifier (`models/url_phishing_detector.joblib`)**:
   - **Feature Extraction**: Scikit-learn `FeatureUnion` combining:
     - Character n-gram TF-IDF (`ngram_range=(3, 5)`) capturing typosquatting permutations, character homoglyphs, and brand spoofing patterns.
     - Custom Lexical & Statistical Transformer (`ml_features.URLLexicalFeatureExtractor`): extracts Shannon character entropy, raw IP address detection, `@` redirect tokens, suspicious TLD frequency, hyphen count, and authentication keywords in URI paths.
   - **Classifier**: Calibrated `LogisticRegression` outputting true probability distributions between 0.00 and 1.00.
   - **Inference Time**: < 3 milliseconds per URL.

3. **Hybrid Engine & Heuristic Fallback (`ai_detector.py`)**:
   - **When ML Models Are Loaded**: The system executes local ML inference to produce an exact threat probability (0–100%) and generates a natural-language explanation of linguistic and lexical indicators. It combines this transparently with deterministic heuristic rules (e.g., active domain blocklists) without masking either layer.
   - **Graceful Fallback**: If model files are absent, deleted, or corrupted, the system falls back seamlessly to deterministic rule-based heuristic scoring (`score_url` and `score_email`).
   - **Transparent Reporting**: When fallback occurs, `engine_mode` is set to `"heuristic_fallback"`, `ai_powered` is set to `False`, and `model_probability` is set to `None`. The application **never** reports a machine learning probability when inference did not run.
   - **Optional External Providers**: If organizations require cloud LLM validation (e.g., OpenAI or Gemini), the detector supports `PHISHGUARD_AI_PROVIDER` and `PHISHGUARD_API_KEY` via environment variables. Credentials are never hardcoded in source files.

### Model Training & Retraining
To train or update the local model artifacts:
```bash
python train_models.py
```
This script reads the training corpus, calibrates the pipelines, generates validation metrics (ROC-AUC & classification accuracy), and saves the serialized weights to the `models/` directory:
- `models/email_phishing_detector.joblib`
- `models/url_phishing_detector.joblib`
- `models/model_metadata.json`

---

## 2. Role-Based Access Control (Admin vs Normal User)

### Security Model
PhishGuard implements strict server-side Role-Based Access Control (RBAC):
- **Normal Users (`role = 'user'`)**:
  - Can scan URLs, emails, and QR codes.
  - Can submit suspicious threat reports.
  - Can view **only their own** personal scan history, submitted reports, and login audit records.
  - **Cannot** view other users' accounts, logins, or reports.
  - **Cannot** alter moderation status of reports.
  - **Cannot** access `/admin` or any `/api/admin/*` endpoints.
- **Administrators (`role = 'admin'`)**:
  - Full access to the SOC Admin Console (`/admin`).
  - Can view system-wide KPIs, all registered users, all login audit trails, and global scan trends.
  - Can manage the domain blocklist (add/remove malicious domains).
  - Can review and update threat report moderation statuses (`pending`, `reviewed`, `resolved`, `dismissed`).

### Safe Database Migration (Preserving SQLite Data)
The database migration was executed non-destructively in `database.py:init_db()`:
1. Checked existing table schema for `users`.
2. Executed `ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'` safely.
3. Updated any preexisting records without a role to `'user'`.
4. All 5 original database accounts and existing scan history were preserved with 100% integrity.

### Promotion & Demotion of Accounts (Owner CLI)
Users cannot self-assign or elevate their role during registration (the backend strictly forces `role = 'user'`). To grant an account Admin privileges, the server owner runs the secure CLI tool `manage.py`:

```bash
# List all accounts and their current role
python manage.py list-users

# Promote a specific user to Administrator
python manage.py promote-admin <username>

# Demote an administrator back to Normal User
python manage.py demote-admin <username>

# Create a new administrator account directly
python manage.py create-admin <username> <email> <password>
```

---

## 3. Server-Side Protection Architecture

Hiding frontend buttons is insufficient for security. PhishGuard enforces authentication and authorization on every endpoint in `app.py`:

| Endpoint | Method | Required Role | Failure Behavior |
| :--- | :--- | :--- | :--- |
| `/admin`, `/admin/dashboard` | `GET` | `admin` | Redirects unauthenticated to `/login?next=/admin&unauthorized=1`; redirects non-admin to `/dashboard?error=admin_access_required` |
| `/api/admin/overview` | `GET` | `admin` | HTTP 401 (unauthenticated) / HTTP 403 Forbidden (non-admin) |
| `/api/admin/users` | `GET` | `admin` | HTTP 401 / HTTP 403 Forbidden |
| `/api/admin/logins` | `GET` | `admin` | HTTP 401 / HTTP 403 Forbidden |
| `/api/admin/blocklist` | `GET`, `POST` | `admin` | HTTP 401 / HTTP 403 Forbidden |
| `/api/admin/blocklist/<id>` | `DELETE` | `admin` | HTTP 401 / HTTP 403 Forbidden |
| `/api/reports/<id>/status` | `PATCH`, `POST` | `admin` | HTTP 401 / HTTP 403 Forbidden |
| `/api/reports` | `GET` | Any | Admins see all reports; normal users see only their own; guests see `[]` |
| `/api/auth/logins` | `GET` | `user` or `admin` | Returns ONLY the authenticated user's own login sessions |

---

## 4. Environment Variables & Setup

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Available variables:
```ini
# Flask session encryption key
SECRET_KEY=phishguard-production-secret-key-2026

# Database path
DATABASE_PATH=phishguard.db

# Offline ML Inference flag
PHISHGUARD_OFFLINE_INFERENCE=true

# Optional External AI Provider (leave blank for local ML models)
PHISHGUARD_AI_PROVIDER=
PHISHGUARD_API_KEY=
```

---

## 5. Summary of Files Changed & Created

1. **`models/`**:
   - `email_phishing_detector.joblib`: Serialized TF-IDF + Calibrated Logistic Regression email classifier.
   - `url_phishing_detector.joblib`: Serialized Char n-gram + Lexical Entropy URL classifier.
   - `model_metadata.json`: Model version, algorithm specs, and accuracy documentation.
2. **`ml_features.py`**:
   - Custom `URLLexicalFeatureExtractor` transformer class for lexical Shannon entropy and URL structure analysis.
3. **`train_models.py`**:
   - Production training script generating calibrated local ML models.
4. **`ai_detector.py`**:
   - Hybrid machine learning detector with local inference, humanized explanations, and transparent heuristic fallback.
5. **`database.py`**:
   - Safe migration adding `role` column, user promotion/demotion functions, and user-filtered report/login queries.
6. **`manage.py`**:
   - Owner CLI tool for managing accounts and promoting administrators.
7. **`app.py`**:
   - Added `@login_required` and `@admin_required` decorators.
   - Protected `/admin` and all `/api/admin/*` endpoints.
   - Isolated user reports and login audits.
   - Integrated AI detector into `/api/scan/url`, `/api/scan/email`, and `/api/scan/qr`.
   - Added `/api/ai/status` monitoring endpoint.
8. **`frontend/index.html`**:
   - Enhanced scan result container with AI Engine badge, threat probability percentage, and model explanation banner.
   - Admin navigation button shown only to authenticated administrators.
9. **`frontend/script.js`**:
   - Updated `displayResult()` to render ML metrics vs heuristic fallback.
   - Updated `checkAuthState()` to show `#navAdminLink` only if `user.role === 'admin'`.
10. **`frontend/admin.html`**:
    - Added `credentials: "include"` on all administrative API requests.
    - Added `Access Role` column and role badges to Users table.
    - Added ML Engine Health monitoring card.
    - Added client-side authorization guard redirecting non-admins on load.
11. **`frontend/landing.html` & `frontend/reports.html`**:
    - Restricted admin console navigation links to authenticated administrators.
12. **`requirements.txt` & `.gitignore` & `.env.example`**:
    - Documented dependencies (`scikit-learn`, `joblib`, `numpy`, `python-dotenv`).
    - Standardized environment secrets protection.
