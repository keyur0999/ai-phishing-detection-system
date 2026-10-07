-- ==========================================
-- PhishGuard AI - Database Schema (SQLite)
-- ==========================================

PRAGMA foreign_keys = ON;

-- Registered users with Role-Based Access Control (RBAC)
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE,
    password_hash TEXT,
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    last_login_at TIMESTAMP,
    login_count   INTEGER DEFAULT 0,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Every scan submitted through the site (email / url / qr)
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER,
    scan_type    TEXT NOT NULL CHECK (scan_type IN ('url', 'email', 'qr')),
    input_data   TEXT NOT NULL,          -- URL, or "subject | body" for email
    verdict      TEXT NOT NULL CHECK (verdict IN ('safe', 'suspicious', 'phishing')),
    risk_score   INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    reasons      TEXT,                   -- JSON array of triggered indicators
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Known-bad domains / URLs, editable blocklist
CREATE TABLE IF NOT EXISTS blocklist (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    domain    TEXT UNIQUE NOT NULL,
    reason    TEXT,
    added_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Reusable phishing keyword / pattern dictionary (used to score emails & urls)
CREATE TABLE IF NOT EXISTS threat_indicators (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT UNIQUE NOT NULL,
    category  TEXT NOT NULL CHECK (category IN ('url', 'email')),
    weight    INTEGER NOT NULL DEFAULT 10,
    added_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);

-- User-submitted threat reports
CREATE TABLE IF NOT EXISTS reports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER,
    user_id    INTEGER,
    reason     TEXT NOT NULL,
    status     TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'reviewed', 'resolved', 'dismissed')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_scan ON reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);

-- User login audit logs (stores each login session in database)
CREATE TABLE IF NOT EXISTS user_logins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    username    TEXT NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    login_time  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status      TEXT DEFAULT 'success' CHECK (status IN ('success', 'failed')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_logins_user ON user_logins(user_id);
CREATE INDEX IF NOT EXISTS idx_user_logins_time ON user_logins(login_time);

