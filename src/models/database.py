#!/usr/bin/env python3
"""
KWTCyberWatch - Database Models
SQLite-backed storage for alerts, domains, and scan history.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional


class Database:
    """SQLite database manager for KWTCyberWatch."""

    def __init__(self, db_path: str = "data/kwtcyberwatch.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    risk_score REAL DEFAULT 0,
                    risk_level TEXT DEFAULT 'clean',
                    is_phishing INTEGER DEFAULT 0,
                    categories TEXT DEFAULT '[]',
                    source TEXT DEFAULT '',
                    matched_keywords TEXT DEFAULT '[]',
                    UNIQUE(domain)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    brand_name TEXT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    assignee TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    result TEXT NOT NULL,
                    scanned_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS certstream_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    all_domains TEXT,
                    issuer TEXT,
                    fingerprint TEXT,
                    risk_score REAL DEFAULT 0,
                    matched_keywords TEXT,
                    timestamp TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_domains_risk ON domains(risk_score DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            """)

    def add_domain(self, domain: str, risk_score: float, risk_level: str,
                   is_phishing: bool, categories: List[str], source: str = "",
                   keywords: List[str] = None):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO domains (domain, first_seen, last_seen, risk_score,
                                     risk_level, is_phishing, categories, source, matched_keywords)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    last_seen=?, risk_score=?, risk_level=?, is_phishing=?
            """, (domain, now, now, risk_score, risk_level, int(is_phishing),
                  json.dumps(categories), source, json.dumps(keywords or []),
                  now, risk_score, risk_level, int(is_phishing)))

    def get_recent_domains(self, limit: int = 50) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM domains ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
            phishing = conn.execute(
                "SELECT COUNT(*) FROM domains WHERE is_phishing=1"
            ).fetchone()[0]
            critical = conn.execute(
                "SELECT COUNT(*) FROM domains WHERE risk_level='critical'"
            ).fetchone()[0]
            return {
                "total_domains": total,
                "phishing_detected": phishing,
                "critical_threats": critical,
            }
