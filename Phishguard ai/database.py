"""
database.py
PhishGuard AI - SQLite database layer.

Handles: connection management, schema creation, seeding default
threat indicators / blocklist, and all read/write operations used
by app.py.
"""

import sqlite3
import json
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard.db")
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


@contextmanager
def get_connection():
    """Yield a SQLite connection with foreign keys enabled and row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables (if they don't exist yet) and seed default data."""
    with get_connection() as conn:
        with open(SCHEMA_PATH, "r") as f:
            conn.executescript(f.read())
        # Safe schema migration for existing databases
        for col_name, col_type in [
            ("last_login_at", "TIMESTAMP"),
            ("login_count", "INTEGER DEFAULT 0"),
            ("role", "TEXT DEFAULT 'user'"),
        ]:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass
        # Ensure all existing accounts have default 'user' role
        conn.execute("UPDATE users SET role = 'user' WHERE role IS NULL OR role = ''")
    _seed_defaults()


def _seed_defaults():
    """Populate starter threat indicators and a small blocklist, only if empty."""
    with get_connection() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM threat_indicators").fetchone()["c"]
        if count == 0:
            url_indicators = [
                ("bit.ly", "url", 15), ("tinyurl.com", "url", 15), ("t.co", "url", 10),
                ("goo.gl", "url", 10), ("is.gd", "url", 15),
                ("login-verify", "url", 20), ("secure-update", "url", 20),
                ("account-confirm", "url", 20), ("password-reset", "url", 15),
                ("verify-account", "url", 20), ("signin-", "url", 15),
                ("wallet-connect", "url", 20), ("free-gift", "url", 15),
            ]
            email_indicators = [
                ("urgent action required", "email", 20), ("verify your account", "email", 20),
                ("suspended", "email", 15), ("click here immediately", "email", 20),
                ("confirm your password", "email", 25), ("limited time", "email", 10),
                ("winner", "email", 15), ("wire transfer", "email", 20),
                ("gift card", "email", 15), ("unusual activity", "email", 15),
                ("update your billing", "email", 20), ("act now", "email", 15),
            ]
            conn.executemany(
                "INSERT OR IGNORE INTO threat_indicators (indicator, category, weight) VALUES (?, ?, ?)",
                url_indicators + email_indicators,
            )

        bl_count = conn.execute("SELECT COUNT(*) AS c FROM blocklist").fetchone()["c"]
        if bl_count == 0:
            seed_blocklist = [
                ("paypa1.com", "Typosquat of paypal.com"),
                ("g00gle-security.com", "Typosquat / brand impersonation"),
                ("appleid-verify.net", "Brand impersonation"),
                ("micros0ft-support.com", "Typosquat of microsoft.com"),
            ]
            conn.executemany(
                "INSERT OR IGNORE INTO blocklist (domain, reason) VALUES (?, ?)",
                seed_blocklist,
            )


# ---------------------------------------------------------------------------
# Threat intelligence lookups
# ---------------------------------------------------------------------------

def get_indicators(category):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT indicator, weight FROM threat_indicators WHERE category = ?",
            (category,),
        ).fetchall()
        return [(r["indicator"], r["weight"]) for r in rows]


def is_blocklisted(domain):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT domain, reason FROM blocklist WHERE ? LIKE '%' || domain || '%'",
            (domain,),
        ).fetchone()
        return dict(row) if row else None


def add_to_blocklist(domain, reason):
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO blocklist (domain, reason) VALUES (?, ?)",
            (domain, reason),
        )


# ---------------------------------------------------------------------------
# Users & Authentication
# ---------------------------------------------------------------------------

def create_user(username, email, password_hash, role="user"):
    # Always enforce normal user role on registration unless explicitly internal
    safe_role = "admin" if role == "admin" else "user"
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username.strip(), email.strip().lower() if email else None, password_hash, safe_role),
        )
        return cur.lastrowid


def get_user_by_username(username):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE LOWER(username) = LOWER(?)",
            (username.strip(),),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_email(email):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE LOWER(email) = LOWER(?)",
            (email.strip(),),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, email, role, created_at, last_login_at, login_count FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def promote_user(username, role="admin"):
    """Secure owner-controlled promotion of an existing account to Admin or User."""
    if role not in ("admin", "user"):
        raise ValueError("Role must be 'admin' or 'user'")
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE users SET role = ? WHERE LOWER(username) = LOWER(?)",
            (role, username.strip()),
        )
        return cur.rowcount > 0


def demote_user(username):
    """Demote an account back to normal User."""
    return promote_user(username, role="user")


# ---------------------------------------------------------------------------
# Logins Audit & History
# ---------------------------------------------------------------------------

def record_login(user_id, username, ip_address=None, user_agent=None, status="success"):
    """Persist a login event to SQLite database and update user login stats."""
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO user_logins (user_id, username, ip_address, user_agent, status)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, username, ip_address, user_agent, status),
        )
        login_id = cur.lastrowid
        if status == "success":
            conn.execute(
                """UPDATE users
                   SET last_login_at = CURRENT_TIMESTAMP,
                       login_count = COALESCE(login_count, 0) + 1
                   WHERE id = ?""",
                (user_id,),
            )
        return login_id


def get_user_logins(user_id=None, limit=20):
    """Retrieve recent login entries from SQLite."""
    with get_connection() as conn:
        if user_id:
            rows = conn.execute(
                """SELECT id, user_id, username, ip_address, user_agent, login_time, status
                   FROM user_logins
                   WHERE user_id = ?
                   ORDER BY login_time DESC LIMIT ?""",
                (user_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, user_id, username, ip_address, user_agent, login_time, status
                   FROM user_logins
                   ORDER BY login_time DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


def save_scan(scan_type, input_data, verdict, risk_score, reasons, user_id=None):
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO scans (user_id, scan_type, input_data, verdict, risk_score, reasons)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, scan_type, input_data, verdict, risk_score, json.dumps(reasons)),
        )
        return cur.lastrowid


def get_history(limit=50, scan_type=None, user_id=None):
    with get_connection() as conn:
        if user_id is not None:
            if scan_type:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE scan_type = ? AND user_id = ? ORDER BY created_at DESC LIMIT ?",
                    (scan_type, user_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                    (user_id, limit),
                ).fetchall()
        else:
            if scan_type:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE scan_type = ? ORDER BY created_at DESC LIMIT ?",
                    (scan_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
            results.append(d)
        return results


def get_stats():
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        by_verdict = conn.execute(
            "SELECT verdict, COUNT(*) AS c FROM scans GROUP BY verdict"
        ).fetchall()
        by_type = conn.execute(
            "SELECT scan_type, COUNT(*) AS c FROM scans GROUP BY scan_type"
        ).fetchall()
        return {
            "total_scans": total,
            "by_verdict": {r["verdict"]: r["c"] for r in by_verdict},
            "by_type": {r["scan_type"]: r["c"] for r in by_type},
        }


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def save_report(scan_id, reason, user_id=None, status="pending"):
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO reports (scan_id, user_id, reason, status)
               VALUES (?, ?, ?, ?)""",
            (scan_id, user_id, reason.strip(), status),
        )
        return cur.lastrowid


def get_reports(limit=100, user_id=None):
    with get_connection() as conn:
        if user_id is not None:
            rows = conn.execute(
                """SELECT r.id, r.scan_id, r.user_id, r.reason, r.status, r.created_at,
                          s.scan_type, s.input_data, s.verdict, s.risk_score,
                          u.username
                   FROM reports r
                   LEFT JOIN scans s ON r.scan_id = s.id
                   LEFT JOIN users u ON r.user_id = u.id
                   WHERE r.user_id = ?
                   ORDER BY r.created_at DESC LIMIT ?""",
                (user_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT r.id, r.scan_id, r.user_id, r.reason, r.status, r.created_at,
                          s.scan_type, s.input_data, s.verdict, s.risk_score,
                          u.username
                   FROM reports r
                   LEFT JOIN scans s ON r.scan_id = s.id
                   LEFT JOIN users u ON r.user_id = u.id
                   ORDER BY r.created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


def update_report_status(report_id, status):
    if status not in ("pending", "reviewed", "resolved", "dismissed"):
        return False
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE reports SET status = ? WHERE id = ?",
            (status, report_id),
        )
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Admin Console Queries
# ---------------------------------------------------------------------------

def get_all_users(limit=100):
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT id, username, email, role, created_at, last_login_at, login_count
               FROM users
               ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_blocklist_all():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, domain, reason, added_at FROM blocklist ORDER BY added_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_from_blocklist(entry_id):
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM blocklist WHERE id = ?", (entry_id,))
        return cur.rowcount > 0


def get_admin_overview():
    with get_connection() as conn:
        users_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        logins_count = conn.execute("SELECT COUNT(*) AS c FROM user_logins").fetchone()["c"]
        scans_count = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        reports_count = conn.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]
        pending_reports = conn.execute(
            "SELECT COUNT(*) AS c FROM reports WHERE status = 'pending'"
        ).fetchone()["c"]
        phish_scans = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE verdict = 'phishing'"
        ).fetchone()["c"]
        blocklist_count = conn.execute("SELECT COUNT(*) AS c FROM blocklist").fetchone()["c"]
        return {
            "users_count": users_count,
            "logins_count": logins_count,
            "scans_count": scans_count,
            "reports_count": reports_count,
            "pending_reports": pending_reports,
            "phish_scans": phish_scans,
            "blocklist_count": blocklist_count,
        }


