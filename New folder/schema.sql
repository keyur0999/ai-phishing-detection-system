-- ==========================================
-- PhishGuard AI - Database Schema (SQLite)
-- ==========================================

PRAGMA foreign_keys = ON;

-- Registered users (optional, for future login/history-per-user)
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE,
    password_hash TEXT,
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
