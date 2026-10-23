"""
╔══════════════════════════════════════════════════════════════════╗
║  SentinelSOC — Mini Security Operations Center                  ║
║  Detect. Investigate. Defend.                                   ║
║                                                                  ║
║  Single-file Flask application                                   ║
║  Python 3.10+  |  SQLite  |  Chart.js                           ║
║                                                                  ║
║  Run:   python sentinelsoc.py                                    ║
║  Open:  http://127.0.0.1:5000                                    ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────
#  Standard library imports
# ─────────────────────────────────────────────
import csv
import hashlib
import io
import json
import logging
import os
import random
import re
import secrets
import sqlite3
import textwrap
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps

def _utcnow():
    """Return current UTC time as naive datetime (Python 3.14 compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

# ─────────────────────────────────────────────
#  Third-party imports
# ─────────────────────────────────────────────
from flask import (
    Flask, abort, g, get_flashed_messages, jsonify, redirect,
    render_template_string, request, send_file, session, url_for, flash
)

# ══════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════

DATABASE = "sentinelsoc.db"
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
MAX_UPLOAD_BYTES = 5 * 1024 * 1024   # 5 MB
DEBUG = os.environ.get("FLASK_ENV", "development") == "development"

# ── Demo user accounts (username → {password, role, display_name}) ──
# In production replace with a proper user table and bcrypt hashing.
DEMO_USERS = {
    "admin": {
        "password": "Admin@1234",
        "role": "admin",
        "display": "Administrator",
        "initials": "AD",
    },
    "analyst": {
        "password": "Analyst@1234",
        "role": "analyst",
        "display": "SOC Analyst",
        "initials": "SA",
    },
    "viewer": {
        "password": "Viewer@1234",
        "role": "viewer",
        "display": "Read-Only Viewer",
        "initials": "RV",
    },
}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    DEBUG=DEBUG,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("sentinelsoc")

# ══════════════════════════════════════════════════════════════════
#  DATABASE LAYER
# ══════════════════════════════════════════════════════════════════

def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

@contextmanager
def raw_db():
    """Context manager for use outside request context (scripts, tests)."""
    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables and seed default detection rules."""
    with raw_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS ingestion_batches (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            filename     TEXT NOT NULL,
            ingested_at  TEXT NOT NULL DEFAULT (datetime('now')),
            record_count INTEGER NOT NULL DEFAULT 0,
            accepted     INTEGER NOT NULL DEFAULT 0,
            rejected     INTEGER NOT NULL DEFAULT 0,
            source_format TEXT
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            source_ip   TEXT,
            username    TEXT,
            event_type  TEXT NOT NULL,
            auth_result TEXT,
            description TEXT,
            raw_data    TEXT,
            batch_id    INTEGER REFERENCES ingestion_batches(id) ON DELETE SET NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_ev_ts   ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_ev_ip   ON security_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_ev_user ON security_events(username);
        CREATE INDEX IF NOT EXISTS idx_ev_type ON security_events(event_type);

        CREATE TABLE IF NOT EXISTS detection_rules (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_key       TEXT NOT NULL UNIQUE,
            name           TEXT NOT NULL,
            description    TEXT,
            severity       TEXT NOT NULL DEFAULT 'medium',
            enabled        INTEGER NOT NULL DEFAULT 1,
            threshold      INTEGER,
            window_minutes INTEGER,
            recommendation TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_key     TEXT NOT NULL,
            rule_name    TEXT NOT NULL,
            severity     TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'new',
            source_ip    TEXT,
            username     TEXT,
            description  TEXT,
            evidence     TEXT,
            recommendation TEXT,
            event_ids    TEXT,
            dedup_key    TEXT UNIQUE,
            triggered_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_al_status   ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_al_severity ON alerts(severity);

        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            description TEXT,
            severity    TEXT NOT NULL DEFAULT 'medium',
            status      TEXT NOT NULL DEFAULT 'open',
            assigned_to TEXT,
            resolution  TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS incident_alerts (
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            alert_id    INTEGER NOT NULL REFERENCES alerts(id)    ON DELETE CASCADE,
            linked_at   TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (incident_id, alert_id)
        );

        CREATE TABLE IF NOT EXISTS incident_notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            author      TEXT NOT NULL DEFAULT 'analyst',
            note        TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """)

        # Default detection rules
        rules = [
            ("brute_force",        "Repeated Failed Logins",
             "Detects 5+ failed login attempts from the same source IP within 5 minutes. "
             "May indicate a brute-force attack against a user account.",
             "high", 1, 5, 5,
             "Investigate the source IP. Review affected accounts. "
             "Consider restricting access from this IP if confirmed malicious."),

            ("password_spray",     "Multiple-Account Login Failures",
             "Detects failed logins from one source IP targeting 3+ distinct usernames within 10 minutes. "
             "May indicate password spraying or account enumeration — investigation required.",
             "high", 1, 3, 10,
             "Review all targeted accounts. Verify whether any account was subsequently compromised. "
             "Investigate the source IP."),

            ("success_after_fail", "Successful Login After Repeated Failures",
             "Detects a successful login following 3+ failed attempts for the same username and source IP "
             "within 10 minutes. Suspicious — requires investigation but does not confirm an attack.",
             "high", 1, 3, 10,
             "Contact the account owner to verify the login was legitimate. "
             "Review activity after the successful login. Preserve logs."),

            ("lockout_spike",      "Account Lockout Spike",
             "Detects 5+ account lockout events within 10 minutes. "
             "May indicate automated credential attacks triggering lockout policies.",
             "medium", 1, 5, 10,
             "Review locked accounts and unlock if appropriate. "
             "Identify and investigate the source of failed attempts."),

            ("multi_ip_attack",    "Suspicious Authentication Pattern",
             "Detects 3+ distinct source IPs failing to authenticate the same account within 15 minutes. "
             "May indicate a distributed attack. Not all unfamiliar IPs are malicious — investigate.",
             "medium", 1, 3, 15,
             "Verify whether the account owner is travelling or using multiple devices. "
             "Review source IP locations. Preserve relevant log entries."),
        ]
        for (rk, name, desc, sev, ena, thr, win, rec) in rules:
            db.execute("""
                INSERT OR IGNORE INTO detection_rules
                    (rule_key,name,description,severity,enabled,threshold,window_minutes,recommendation)
                VALUES (?,?,?,?,?,?,?,?)
            """, (rk, name, desc, sev, ena, thr, win, rec))

# ══════════════════════════════════════════════════════════════════
#  LOG PARSER & NORMALIZER
# ══════════════════════════════════════════════════════════════════

REQUIRED_CSV_COLS = {"timestamp", "event_type"}

_TS_FMTS = [
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
    "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
]
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_AUTH_MAP = {
    "success": "success", "succeeded": "success", "ok": "success", "true": "success",
    "fail": "failure", "failed": "failure", "failure": "failure",
    "false": "failure", "denied": "failure",
    "locked": "lockout", "lockout": "lockout",
    "account locked": "lockout", "account_locked": "lockout",
}


def _parse_ts(raw):
    if not raw:
        return None
    for fmt in _TS_FMTS:
        try:
            return datetime.strptime(str(raw).strip(), fmt).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass
    return None


def _norm_ip(raw):
    if not raw:
        return None
    s = str(raw).strip()
    return s if _IP_RE.match(s) else None


def _norm_auth(raw):
    if not raw:
        return None
    return _AUTH_MAP.get(str(raw).strip().lower(), str(raw).strip().lower())


def normalize_record(raw):
    """Convert a raw dict to a SecurityEvent dict. Returns _error key if invalid."""
    ts = _parse_ts(raw.get("timestamp") or raw.get("time") or raw.get("ts") or "")
    etype = (raw.get("event_type") or raw.get("eventtype") or raw.get("type") or "").strip().lower()
    error = None
    if not ts:
        error = f"Bad timestamp: {raw.get('timestamp', '')!r}"
    elif not etype:
        error = "Missing event_type"
    return {
        "timestamp":   ts,
        "source_ip":   _norm_ip(raw.get("source_ip") or raw.get("src_ip") or raw.get("ip")),
        "username":    str(raw.get("username") or raw.get("user") or raw.get("account") or "")[:128] or None,
        "event_type":  etype,
        "auth_result": _norm_auth(raw.get("auth_result") or raw.get("result") or raw.get("status")),
        "description": str(raw.get("description") or raw.get("message") or raw.get("msg") or "")[:512] or None,
        "raw_data":    json.dumps({k: v for k, v in raw.items()
                                   if k not in {"timestamp","source_ip","username","event_type",
                                                "auth_result","description"}}, default=str)[:512],
        "_error":      error,
    }


def parse_file_content(filename, content):
    """Detect format (CSV or JSONL) and return {records, errors, format}."""
    stripped = content.lstrip()
    if stripped.startswith("{"):
        records, errors = [], []
        for i, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append({k.lower(): v for k, v in obj.items()})
                else:
                    errors.append(f"Line {i}: expected object")
            except json.JSONDecodeError as e:
                errors.append(f"Line {i}: {e.msg}")
        return {"records": records, "errors": errors, "format": "jsonl"}
    else:
        records, errors = [], []
        try:
            reader = csv.DictReader(io.StringIO(content))
            if not reader.fieldnames:
                return {"records": [], "errors": ["Empty file or no header"], "format": "csv"}
            headers = {h.strip().lower() for h in reader.fieldnames if h}
            missing = REQUIRED_CSV_COLS - headers
            if missing:
                return {"records": [], "errors": [f"Missing columns: {', '.join(sorted(missing))}"], "format": "csv"}
            for i, row in enumerate(reader, 2):
                try:
                    records.append({k.strip().lower(): (v.strip() if v else "") for k, v in row.items() if k})
                except Exception as e:
                    errors.append(f"Row {i}: {e}")
        except Exception as e:
            errors.append(f"CSV error: {e}")
        return {"records": records, "errors": errors, "format": "csv"}

# ══════════════════════════════════════════════════════════════════
#  DETECTION ENGINE
# ══════════════════════════════════════════════════════════════════

def _get_rule(db, rule_key):
    row = db.execute("SELECT * FROM detection_rules WHERE rule_key=? AND enabled=1", (rule_key,)).fetchone()
    return dict(row) if row else None


def _make_dedup_key(rule_key, context_str, window_start):
    h = hashlib.sha256(f"{rule_key}:{context_str}:{window_start}".encode()).hexdigest()[:16]
    return f"{rule_key}:{h}"


def _alert_exists(db, dedup_key):
    return db.execute("SELECT id FROM alerts WHERE dedup_key=?", (dedup_key,)).fetchone() is not None


def _create_alert(db, rule_key, rule_name, severity, source_ip, username,
                  description, evidence, recommendation, event_ids, dedup_key):
    now = _utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    db.execute("""
        INSERT OR IGNORE INTO alerts
            (rule_key,rule_name,severity,status,source_ip,username,
             description,evidence,recommendation,event_ids,dedup_key,triggered_at,updated_at)
        VALUES (?,?,?,  'new',  ?,?,?,?,?,?,?,?,?)
    """, (rule_key, rule_name, severity, source_ip, username,
          description, json.dumps(evidence), recommendation,
          json.dumps(event_ids), dedup_key, now, now))
    return db.execute("SELECT last_insert_rowid()").fetchone()[0]


def run_detection(db, batch_id=None):
    """
    Run all enabled detection rules over security events.
    If batch_id is given, only process events from that batch;
    otherwise scan ALL events in the database.
    """
    alerts_created = 0

    if batch_id:
        events = db.execute(
            "SELECT * FROM security_events WHERE batch_id=? ORDER BY timestamp",
            (batch_id,)
        ).fetchall()
    else:
        events = db.execute(
            "SELECT * FROM security_events ORDER BY timestamp"
        ).fetchall()

    events = [dict(e) for e in events]
    if not events:
        return 0

    # ── Rule 1: Brute Force ───────────────────────────────────────
    rule = _get_rule(db, "brute_force")
    if rule:
        threshold = rule["threshold"] or 5
        window    = rule["window_minutes"] or 5
        rule_name = rule["name"]
        severity  = rule["severity"]
        rec       = rule["recommendation"]

        by_ip = defaultdict(list)
        for e in events:
            if e.get("auth_result") == "failure" and e.get("source_ip"):
                by_ip[e["source_ip"]].append(e)

        for ip, evs in by_ip.items():
            evs.sort(key=lambda x: x["timestamp"])
            i = 0
            while i < len(evs):
                window_end = _add_minutes(evs[i]["timestamp"], window)
                bucket = [e for e in evs[i:] if e["timestamp"] <= window_end]
                if len(bucket) >= threshold:
                    wstart = evs[i]["timestamp"]
                    dedup = _make_dedup_key("brute_force", ip, wstart)
                    if not _alert_exists(db, dedup):
                        evidence = {
                            "source_ip": ip,
                            "failed_count": len(bucket),
                            "window_minutes": window,
                            "first_event": bucket[0]["timestamp"],
                            "last_event": bucket[-1]["timestamp"],
                            "usernames": list({e.get("username") for e in bucket if e.get("username")}),
                        }
                        desc = (f"[DEMO] {len(bucket)} failed login attempts from {ip} "
                                f"between {bucket[0]['timestamp']} and {bucket[-1]['timestamp']}. "
                                f"Threshold: {threshold} failures in {window} minutes.")
                        eids = [e["id"] for e in bucket]
                        _create_alert(db, "brute_force", rule_name, severity,
                                      ip, None, desc, evidence, rec, eids, dedup)
                        alerts_created += 1
                    i += len(bucket)
                else:
                    i += 1

    # ── Rule 2: Password Spray ────────────────────────────────────
    rule = _get_rule(db, "password_spray")
    if rule:
        threshold = rule["threshold"] or 3
        window    = rule["window_minutes"] or 10
        rule_name = rule["name"]
        severity  = rule["severity"]
        rec       = rule["recommendation"]

        by_ip = defaultdict(list)
        for e in events:
            if e.get("auth_result") == "failure" and e.get("source_ip") and e.get("username"):
                by_ip[e["source_ip"]].append(e)

        for ip, evs in by_ip.items():
            evs.sort(key=lambda x: x["timestamp"])
            i = 0
            while i < len(evs):
                window_end = _add_minutes(evs[i]["timestamp"], window)
                bucket = [e for e in evs[i:] if e["timestamp"] <= window_end]
                users = {e["username"] for e in bucket}
                if len(users) >= threshold:
                    wstart = evs[i]["timestamp"]
                    dedup = _make_dedup_key("password_spray", ip, wstart)
                    if not _alert_exists(db, dedup):
                        evidence = {
                            "source_ip": ip,
                            "distinct_accounts": len(users),
                            "accounts": list(users),
                            "window_minutes": window,
                            "first_event": bucket[0]["timestamp"],
                            "last_event": bucket[-1]["timestamp"],
                        }
                        desc = (f"[DEMO] Source IP {ip} attempted logins against "
                                f"{len(users)} different accounts "
                                f"({', '.join(sorted(users)[:5])}) "
                                f"between {bucket[0]['timestamp']} and {bucket[-1]['timestamp']}. "
                                f"May indicate password spraying or enumeration.")
                        eids = [e["id"] for e in bucket]
                        _create_alert(db, "password_spray", rule_name, severity,
                                      ip, None, desc, evidence, rec, eids, dedup)
                        alerts_created += 1
                i += len(bucket) if len(users) >= threshold else 1

    # ── Rule 3: Success After Failures ───────────────────────────
    rule = _get_rule(db, "success_after_fail")
    if rule:
        threshold = rule["threshold"] or 3
        window    = rule["window_minutes"] or 10
        rule_name = rule["name"]
        severity  = rule["severity"]
        rec       = rule["recommendation"]

        # group by (username, source_ip)
        by_user_ip = defaultdict(list)
        for e in events:
            if e.get("username") and e.get("source_ip") and e.get("auth_result") in ("failure", "success"):
                by_user_ip[(e["username"], e["source_ip"])].append(e)

        for (user, ip), evs in by_user_ip.items():
            evs.sort(key=lambda x: x["timestamp"])
            for j, ev in enumerate(evs):
                if ev.get("auth_result") != "success":
                    continue
                window_start = _sub_minutes(ev["timestamp"], window)
                prior_fails = [e for e in evs[:j]
                               if e.get("auth_result") == "failure"
                               and e["timestamp"] >= window_start]
                if len(prior_fails) >= threshold:
                    wstart = prior_fails[0]["timestamp"]
                    dedup = _make_dedup_key("success_after_fail", f"{user}:{ip}", wstart)
                    if not _alert_exists(db, dedup):
                        evidence = {
                            "username": user,
                            "source_ip": ip,
                            "failed_count": len(prior_fails),
                            "success_time": ev["timestamp"],
                            "first_failure": prior_fails[0]["timestamp"],
                            "window_minutes": window,
                        }
                        desc = (f"[DEMO] User '{user}' had {len(prior_fails)} failed logins from {ip} "
                                f"followed by a successful login at {ev['timestamp']}. "
                                f"This is suspicious and requires investigation.")
                        eids = [e["id"] for e in prior_fails] + [ev["id"]]
                        _create_alert(db, "success_after_fail", rule_name, severity,
                                      ip, user, desc, evidence, rec, eids, dedup)
                        alerts_created += 1

    # ── Rule 4: Lockout Spike ─────────────────────────────────────
    rule = _get_rule(db, "lockout_spike")
    if rule:
        threshold = rule["threshold"] or 5
        window    = rule["window_minutes"] or 10
        rule_name = rule["name"]
        severity  = rule["severity"]
        rec       = rule["recommendation"]

        lockouts = sorted(
            [e for e in events if e.get("auth_result") == "lockout"],
            key=lambda x: x["timestamp"]
        )
        i = 0
        while i < len(lockouts):
            window_end = _add_minutes(lockouts[i]["timestamp"], window)
            bucket = [e for e in lockouts[i:] if e["timestamp"] <= window_end]
            if len(bucket) >= threshold:
                wstart = lockouts[i]["timestamp"]
                dedup = _make_dedup_key("lockout_spike", "global", wstart)
                if not _alert_exists(db, dedup):
                    accounts = list({e.get("username") for e in bucket if e.get("username")})
                    evidence = {
                        "lockout_count": len(bucket),
                        "window_minutes": window,
                        "accounts_locked": accounts,
                        "first_event": bucket[0]["timestamp"],
                        "last_event": bucket[-1]["timestamp"],
                    }
                    desc = (f"[DEMO] {len(bucket)} account lockout events detected "
                            f"between {bucket[0]['timestamp']} and {bucket[-1]['timestamp']}. "
                            f"Accounts affected: {', '.join(accounts[:5]) if accounts else 'unknown'}.")
                    eids = [e["id"] for e in bucket]
                    _create_alert(db, "lockout_spike", rule_name, severity,
                                  None, None, desc, evidence, rec, eids, dedup)
                    alerts_created += 1
                i += len(bucket)
            else:
                i += 1

    # ── Rule 5: Multi-IP Attack ───────────────────────────────────
    rule = _get_rule(db, "multi_ip_attack")
    if rule:
        threshold = rule["threshold"] or 3
        window    = rule["window_minutes"] or 15
        rule_name = rule["name"]
        severity  = rule["severity"]
        rec       = rule["recommendation"]

        by_user = defaultdict(list)
        for e in events:
            if e.get("auth_result") == "failure" and e.get("username") and e.get("source_ip"):
                by_user[e["username"]].append(e)

        for user, evs in by_user.items():
            evs.sort(key=lambda x: x["timestamp"])
            i = 0
            while i < len(evs):
                window_end = _add_minutes(evs[i]["timestamp"], window)
                bucket = [e for e in evs[i:] if e["timestamp"] <= window_end]
                ips = {e["source_ip"] for e in bucket}
                if len(ips) >= threshold:
                    wstart = evs[i]["timestamp"]
                    dedup = _make_dedup_key("multi_ip_attack", user, wstart)
                    if not _alert_exists(db, dedup):
                        evidence = {
                            "username": user,
                            "distinct_ips": len(ips),
                            "source_ips": list(ips),
                            "window_minutes": window,
                            "first_event": bucket[0]["timestamp"],
                            "last_event": bucket[-1]["timestamp"],
                        }
                        desc = (f"[DEMO] Account '{user}' targeted by {len(ips)} distinct source IPs "
                                f"between {bucket[0]['timestamp']} and {bucket[-1]['timestamp']}. "
                                f"May indicate distributed attack — investigation required.")
                        eids = [e["id"] for e in bucket]
                        _create_alert(db, "multi_ip_attack", rule_name, severity,
                                      None, user, desc, evidence, rec, eids, dedup)
                        alerts_created += 1
                i += len(bucket) if len(ips) >= threshold else 1

    db.commit()
    return alerts_created


def _add_minutes(ts_str, minutes):
    try:
        dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
        return (dt + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return ts_str


def _sub_minutes(ts_str, minutes):
    try:
        dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
        return (dt - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return ts_str

# ══════════════════════════════════════════════════════════════════
#  SYNTHETIC DEMO DATA GENERATOR
# ══════════════════════════════════════════════════════════════════

def seed_demo_data():
    """Insert synthetic security events to populate the demo dashboard."""
    with raw_db() as db:
        count = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        if count > 0:
            log.info("Demo data already present — skipping seed.")
            return

        now = _utcnow()
        events = []

        # Fictional usernames and documentation IP ranges (RFC 5737)
        users = ["alice.smith", "bob.jones", "charlie.dev", "diana.ops",
                 "eve.admin", "frank.user", "grace.test"]
        good_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.5"]
        attacker_ip = "198.51.100.42"    # TEST-NET-3 (RFC 5737) — documentation range
        dist_ips    = ["203.0.113.10", "203.0.113.11", "203.0.113.12",
                       "203.0.113.13"]  # TEST-NET-3

        def ev(ts, ip, user, etype, auth, desc):
            events.append({
                "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S"),
                "source_ip": ip, "username": user,
                "event_type": etype, "auth_result": auth, "description": desc,
            })

        # ── Normal logins over the past 7 days ──
        for day in range(7):
            base = now - timedelta(days=day)
            for user in users[:4]:
                ip = random.choice(good_ips)
                ev(base.replace(hour=8,  minute=random.randint(0, 59)), ip, user,
                   "authentication", "success", f"Normal login — {user}")
                ev(base.replace(hour=17, minute=random.randint(0, 59)), ip, user,
                   "authentication", "success", f"Normal logout — {user}")
            # occasional single failures
            if day % 2 == 0:
                ev(base.replace(hour=9, minute=15), good_ips[0], "alice.smith",
                   "authentication", "failure", "Wrong password")

        # ── SCENARIO 1: Brute-force (Rule 1) — 6 failures from attacker_ip ──
        t = now - timedelta(hours=2)
        for i in range(6):
            ev(t + timedelta(minutes=i), attacker_ip, "alice.smith",
               "authentication", "failure",
               f"[DEMO] Brute-force attempt {i+1} from {attacker_ip}")

        # ── SCENARIO 2: Password spray (Rule 2) — 1 IP, 4 accounts ──
        t = now - timedelta(hours=3)
        for i, user in enumerate(users[:4]):
            ev(t + timedelta(minutes=i), attacker_ip, user,
               "authentication", "failure",
               f"[DEMO] Password spray attempt against {user}")

        # ── SCENARIO 3: Success after failures (Rule 3) ──
        t = now - timedelta(hours=4)
        for i in range(4):
            ev(t + timedelta(minutes=i), attacker_ip, "bob.jones",
               "authentication", "failure",
               f"[DEMO] Failed attempt {i+1} before success")
        ev(t + timedelta(minutes=5), attacker_ip, "bob.jones",
           "authentication", "success",
           "[DEMO] Successful login after repeated failures")

        # ── SCENARIO 4: Lockout spike (Rule 4) — 6 lockouts ──
        t = now - timedelta(hours=5)
        for i, user in enumerate(users):
            ev(t + timedelta(minutes=i), attacker_ip, user,
               "authentication", "lockout",
               f"[DEMO] Account {user} locked after repeated failures")

        # ── SCENARIO 5: Multi-IP (Rule 5) — 4 IPs target charlie.dev ──
        t = now - timedelta(hours=6)
        for i, ip in enumerate(dist_ips):
            for j in range(2):
                ev(t + timedelta(minutes=i*3+j), ip, "charlie.dev",
                   "authentication", "failure",
                   f"[DEMO] Distributed attempt from {ip}")

        # ── Additional mixed events ──
        for i in range(20):
            offset = random.randint(1, 48)
            user = random.choice(users)
            ip   = random.choice(good_ips)
            ev(now - timedelta(hours=offset, minutes=random.randint(0,59)),
               ip, user, "authentication",
               random.choice(["success","success","success","failure"]),
               "Normal activity")

        # Batch insert
        db.execute("""INSERT INTO ingestion_batches
            (filename,ingested_at,record_count,accepted,rejected,source_format)
            VALUES ('demo_seed',datetime('now'),?,?,0,'seed')""",
            (len(events), len(events)))
        batch_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        db.executemany("""
            INSERT INTO security_events
                (timestamp,source_ip,username,event_type,auth_result,description,batch_id)
            VALUES (:timestamp,:source_ip,:username,:event_type,:auth_result,:description,:batch_id)
        """, [{**e, "batch_id": batch_id} for e in events])

        db.commit()

    # Run detection on seeded data
    with raw_db() as db:
        created = run_detection(db)
        log.info(f"Demo seed: {len(events)} events inserted, {created} alerts created.")

# ══════════════════════════════════════════════════════════════════
#  CSV EXPORT HELPER (injection-safe)
# ══════════════════════════════════════════════════════════════════

def _safe_csv_cell(value):
    """Prevent CSV formula injection by prefixing suspicious cells."""
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "|", "%"):
        return "'" + s
    return s

# ══════════════════════════════════════════════════════════════════
#  JINJA2 GLOBALS
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
#  AUTH HELPERS
# ══════════════════════════════════════════════════════════════════

def current_user():
    """Return the logged-in user dict or None."""
    username = session.get("username")
    if not username:
        return None
    return DEMO_USERS.get(username)


def login_required(f):
    """Decorator: redirect to /login if not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


# ── Apply login_required to ALL routes by checking in before_request ──
@app.before_request
def require_login():
    public_endpoints = {"login", "logout", "static"}
    if request.endpoint in public_endpoints:
        return
    if request.endpoint and not current_user():
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login", next=request.full_path))


@app.context_processor
def inject_globals():
    db = get_db()
    new_alerts = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE status='new'"
    ).fetchone()[0]
    open_incidents = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')"
    ).fetchone()[0]
    user = current_user() or {}
    return dict(
        new_alert_count=new_alerts,
        open_incident_count=open_incidents,
        now=_utcnow(),
        current_user=user,
        current_username=session.get("username", ""),
    )

# ══════════════════════════════════════════════════════════════════
#  BASE TEMPLATE
# ══════════════════════════════════════════════════════════════════

BASE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelSOC – {{ page_title }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>
<style>
/* ── DARK MODE (default) ── */
:root,[data-theme="dark"]{
  --bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--accent2:#388bfd;
  --crit:#f85149;--high:#ff7b72;--med:#e3b341;--low:#3fb950;
  --green:#3fb950;--red:#f85149;--orange:#ff7b72;--yellow:#e3b341;
  --cyan:#79c0ff;--sidebar-w:240px;
  --shadow:0 2px 8px rgba(0,0,0,.4);
  --card-hover:rgba(255,255,255,.02);
}
/* ── LIGHT MODE ── */
[data-theme="light"]{
  --bg:#f0f2f5;--surface:#ffffff;--surface2:#f7f8fa;--border:#d0d7de;
  --text:#1f2328;--muted:#57606a;--accent:#0969da;--accent2:#0550ae;
  --crit:#cf222e;--high:#d1242f;--med:#9a6700;--low:#1a7f37;
  --green:#1a7f37;--red:#cf222e;--orange:#bc4c00;--yellow:#9a6700;
  --cyan:#0550ae;--sidebar-w:240px;
  --shadow:0 2px 8px rgba(0,0,0,.08);
  --card-hover:rgba(0,0,0,.02);
}
[data-theme="light"] .nav-item.active{
  background:rgba(9,105,218,.08);
}
[data-theme="light"] .evidence-box{
  background:#f6f8fa;color:#0550ae;
}
[data-theme="light"] .badge-critical{background:rgba(207,34,46,.1);color:#cf222e;}
[data-theme="light"] .badge-high{background:rgba(209,36,47,.1);color:#d1242f;}
[data-theme="light"] .badge-medium{background:rgba(154,103,0,.1);color:#9a6700;}
[data-theme="light"] .badge-low{background:rgba(26,127,55,.1);color:#1a7f37;}
[data-theme="light"] .badge-info{background:rgba(9,105,218,.1);color:#0969da;}
[data-theme="light"] .st-new{background:rgba(9,105,218,.1);color:#0550ae;}
[data-theme="light"] .st-investigating{background:rgba(154,103,0,.1);color:#9a6700;}
[data-theme="light"] .st-resolved{background:rgba(26,127,55,.1);color:#1a7f37;}
[data-theme="light"] .st-acknowledged{background:rgba(130,80,223,.1);color:#6639ba;}
[data-theme="light"] .st-false_positive{background:rgba(87,96,106,.1);color:#57606a;}
[data-theme="light"] .st-open{background:rgba(207,34,46,.1);color:#cf222e;}
[data-theme="light"] .st-contained{background:rgba(188,76,0,.1);color:#bc4c00;}
[data-theme="light"] .st-closed{background:rgba(87,96,106,.1);color:#57606a;}
[data-theme="light"] .flash-success{background:rgba(26,127,55,.08);border-color:rgba(26,127,55,.3);color:#1a7f37;}
[data-theme="light"] .flash-error{background:rgba(207,34,46,.08);border-color:rgba(207,34,46,.3);color:#cf222e;}
[data-theme="light"] .flash-info{background:rgba(9,105,218,.08);border-color:rgba(9,105,218,.3);color:#0969da;}
[data-theme="light"] .flash-warning{background:rgba(154,103,0,.08);border-color:rgba(154,103,0,.3);color:#9a6700;}
[data-theme="light"] .upload-area{border-color:#d0d7de;}
[data-theme="light"] .upload-area:hover,[data-theme="light"] .upload-area.drag-over{
  border-color:#0969da;background:rgba(9,105,218,.04);
}
[data-theme="light"] #sidebar{box-shadow:2px 0 8px rgba(0,0,0,.06);}
[data-theme="light"] #topbar{box-shadow:0 1px 4px rgba(0,0,0,.06);}
/* Theme toggle button */
.theme-toggle{
  width:34px;height:34px;border-radius:8px;border:1px solid var(--border);
  background:var(--surface2);color:var(--muted);cursor:pointer;
  display:flex;align-items:center;justify-content:center;transition:all .15s;
  flex-shrink:0;
}
.theme-toggle:hover{background:var(--border);color:var(--text);}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);
     display:flex;min-height:100vh;font-size:14px;line-height:1.6;}

/* ── Sidebar ── */
#sidebar{
  width:var(--sidebar-w);min-height:100vh;background:var(--surface);
  border-right:1px solid var(--border);display:flex;flex-direction:column;
  position:fixed;top:0;left:0;bottom:0;z-index:100;overflow-y:auto;
}
.sidebar-logo{
  padding:20px 16px 16px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px;
}
.sidebar-logo .logo-icon{
  width:36px;height:36px;background:linear-gradient(135deg,#1f6feb,#388bfd);
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  color:#fff;font-size:18px;flex-shrink:0;
}
.sidebar-logo .brand{font-weight:700;font-size:15px;color:var(--text);line-height:1.2;}
.sidebar-logo .tagline{font-size:10px;color:var(--muted);}
.nav-section{padding:12px 0 4px;}
.nav-label{font-size:10px;font-weight:600;color:var(--muted);
           text-transform:uppercase;letter-spacing:.08em;padding:0 16px 4px;}
.nav-item{
  display:flex;align-items:center;gap:10px;padding:8px 16px;
  color:var(--muted);text-decoration:none;font-size:13px;font-weight:500;
  border-radius:0;transition:all .15s;position:relative;
}
.nav-item:hover{color:var(--text);background:var(--surface2);}
.nav-item.active{color:var(--accent);background:rgba(88,166,255,.08);
  border-left:2px solid var(--accent);}
.nav-item .badge{
  margin-left:auto;background:var(--red);color:#fff;border-radius:10px;
  padding:1px 7px;font-size:10px;font-weight:700;
}
.nav-item .badge-warn{background:var(--orange);}

/* ── Top bar ── */
#topbar{
  position:fixed;top:0;left:var(--sidebar-w);right:0;height:56px;
  background:var(--surface);border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
  padding:0 24px;z-index:99;gap:16px;
}
.topbar-title{font-size:16px;font-weight:600;color:var(--text);}
.topbar-right{display:flex;align-items:center;gap:12px;}
.demo-badge{
  background:rgba(227,179,65,.15);color:var(--yellow);border:1px solid rgba(227,179,65,.3);
  border-radius:12px;padding:3px 10px;font-size:11px;font-weight:600;letter-spacing:.05em;
}
.topbar-user{
  width:32px;height:32px;border-radius:50%;background:var(--accent2);
  display:flex;align-items:center;justify-content:center;font-size:12px;
  font-weight:700;color:#fff;cursor:default;
}

/* ── Main content ── */
#main{margin-left:var(--sidebar-w);padding-top:56px;flex:1;min-height:100vh;}
.page{padding:24px;}
.page-header{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:24px;flex-wrap:wrap;gap:12px;
}
.page-header h1{font-size:20px;font-weight:700;color:var(--text);}

/* ── Cards ── */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:16px;margin-bottom:24px;}
.card{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:18px;transition:border-color .2s;
}
.card:hover{border-color:var(--accent);}
.card-label{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;}
.card-value{font-size:28px;font-weight:700;color:var(--text);margin:6px 0 4px;}
.card-sub{font-size:12px;color:var(--muted);}
.card-icon{float:right;opacity:.4;}

/* ── Charts ── */
.charts-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px;margin-bottom:24px;}
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;}
.chart-card h3{font-size:13px;font-weight:600;color:var(--muted);
               text-transform:uppercase;letter-spacing:.06em;margin-bottom:16px;}
.chart-wrapper{position:relative;height:220px;}

/* ── Tables ── */
.table-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;
            overflow:hidden;margin-bottom:16px;}
.table-card-header{
  display:flex;align-items:center;justify-content:space-between;
  padding:14px 16px;border-bottom:1px solid var(--border);
}
.table-card-header h3{font-size:13px;font-weight:600;color:var(--muted);
                      text-transform:uppercase;letter-spacing:.06em;}
table{width:100%;border-collapse:collapse;}
th{padding:10px 14px;text-align:left;font-size:11px;font-weight:600;
   color:var(--muted);text-transform:uppercase;letter-spacing:.06em;
   background:var(--surface2);border-bottom:1px solid var(--border);}
td{padding:10px 14px;border-bottom:1px solid var(--border);font-size:13px;
   vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(255,255,255,.02);}
.table-link{color:var(--accent);text-decoration:none;font-weight:500;}
.table-link:hover{text-decoration:underline;}

/* ── Severity badges ── */
.badge-sev{
  display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;
  text-transform:uppercase;letter-spacing:.06em;
}
.badge-critical{background:rgba(248,81,73,.15);color:var(--crit);border:1px solid rgba(248,81,73,.3);}
.badge-high{background:rgba(255,123,114,.15);color:var(--high);border:1px solid rgba(255,123,114,.3);}
.badge-medium{background:rgba(227,179,65,.15);color:var(--med);border:1px solid rgba(227,179,65,.3);}
.badge-low{background:rgba(63,185,80,.15);color:var(--low);border:1px solid rgba(63,185,80,.3);}
.badge-info{background:rgba(88,166,255,.1);color:var(--accent);border:1px solid rgba(88,166,255,.2);}

/* ── Status badges ── */
.badge-status{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;}
.st-new{background:rgba(88,166,255,.15);color:var(--cyan);}
.st-acknowledged{background:rgba(163,113,247,.15);color:#a371f7;}
.st-investigating{background:rgba(227,179,65,.15);color:var(--yellow);}
.st-resolved{background:rgba(63,185,80,.15);color:var(--green);}
.st-false_positive{background:rgba(139,148,158,.15);color:var(--muted);}
.st-open{background:rgba(248,81,73,.15);color:var(--red);}
.st-contained{background:rgba(255,123,114,.15);color:var(--orange);}
.st-closed{background:rgba(139,148,158,.15);color:var(--muted);}

/* ── Buttons ── */
.btn{
  display:inline-flex;align-items:center;gap:6px;padding:7px 14px;
  border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;
  border:1px solid var(--border);background:var(--surface2);color:var(--text);
  text-decoration:none;transition:all .15s;
}
.btn:hover{background:var(--border);}
.btn-primary{background:var(--accent2);border-color:var(--accent2);color:#fff;}
.btn-primary:hover{background:var(--accent);border-color:var(--accent);}
.btn-danger{background:rgba(248,81,73,.15);border-color:var(--red);color:var(--red);}
.btn-danger:hover{background:rgba(248,81,73,.3);}
.btn-sm{padding:4px 10px;font-size:12px;}

/* ── Forms ── */
.form-group{margin-bottom:16px;}
label{display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:6px;}
input[type=text],input[type=number],input[type=email],
textarea,select{
  width:100%;padding:8px 12px;background:var(--surface2);
  border:1px solid var(--border);border-radius:6px;color:var(--text);
  font-size:13px;font-family:inherit;transition:border-color .15s;
}
input:focus,textarea:focus,select:focus{
  outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(88,166,255,.1);
}
textarea{resize:vertical;min-height:80px;}

/* ── Filters ── */
.filters{
  display:flex;align-items:center;flex-wrap:wrap;gap:10px;
  background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:14px;margin-bottom:16px;
}
.filters select,.filters input[type=text]{
  width:auto;min-width:130px;
}

/* ── Detail panels ── */
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;}
.detail-card{background:var(--surface);border:1px solid var(--border);
             border-radius:10px;padding:18px;}
.detail-card h3{font-size:12px;font-weight:600;color:var(--muted);
                text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px;}
.detail-row{display:flex;justify-content:space-between;align-items:baseline;
            padding:5px 0;border-bottom:1px solid var(--border);gap:12px;}
.detail-row:last-child{border-bottom:none;}
.detail-key{font-size:12px;color:var(--muted);flex-shrink:0;}
.detail-val{font-size:13px;color:var(--text);text-align:right;
            word-break:break-all;font-family:'JetBrains Mono',monospace;}

/* ── Code / evidence ── */
.evidence-box{
  background:var(--surface2);border:1px solid var(--border);border-radius:8px;
  padding:14px;font-family:'JetBrains Mono',monospace;font-size:12px;
  white-space:pre-wrap;word-break:break-all;color:var(--cyan);
  max-height:260px;overflow-y:auto;
}

/* ── Upload area ── */
.upload-area{
  border:2px dashed var(--border);border-radius:10px;padding:40px;
  text-align:center;cursor:pointer;transition:all .2s;
}
.upload-area:hover,.upload-area.drag-over{
  border-color:var(--accent);background:rgba(88,166,255,.04);
}
.upload-area .upload-icon{font-size:40px;opacity:.4;margin-bottom:12px;}
.upload-area p{color:var(--muted);font-size:13px;}
.upload-area strong{color:var(--text);}

/* ── Alerts / flash ── */
.flash{border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:13px;}
.flash-success{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.3);color:var(--green);}
.flash-error{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);color:var(--red);}
.flash-info{background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.3);color:var(--accent);}
.flash-warning{background:rgba(227,179,65,.1);border:1px solid rgba(227,179,65,.3);color:var(--yellow);}

/* ── Empty state ── */
.empty-state{text-align:center;padding:60px 20px;color:var(--muted);}
.empty-state .empty-icon{font-size:40px;margin-bottom:12px;opacity:.3;}
.empty-state h3{font-size:15px;font-weight:600;color:var(--text);margin-bottom:6px;}

/* ── Pagination ── */
.pagination{display:flex;align-items:center;gap:6px;margin-top:16px;justify-content:center;}
.page-btn{
  padding:5px 10px;border:1px solid var(--border);background:var(--surface);
  border-radius:5px;color:var(--muted);text-decoration:none;font-size:12px;
}
.page-btn:hover,.page-btn.active{background:var(--accent2);border-color:var(--accent2);color:#fff;}
.page-btn.disabled{pointer-events:none;opacity:.4;}

/* ── Responsive ── */
@media(max-width:768px){
  #sidebar{transform:translateX(-100%);transition:transform .25s;}
  #sidebar.open{transform:translateX(0);}
  #main{margin-left:0;}
  #topbar{left:0;}
  .detail-grid{grid-template-columns:1fr;}
  .charts-grid{grid-template-columns:1fr;}
}
.hamburger{display:none;cursor:pointer;}
@media(max-width:768px){.hamburger{display:flex;}}
</style>
</head>
<body>

<!-- SIDEBAR -->
<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon"><i data-lucide="shield-check" style="width:18px;height:18px;"></i></div>
    <div>
      <div class="brand">SentinelSOC</div>
      <div class="tagline">Detect · Investigate · Defend</div>
    </div>
  </div>

  <div class="nav-section">
    <div class="nav-label">Monitor</div>
    <a href="{{ url_for('dashboard') }}" class="nav-item {% if active=='dashboard' %}active{% endif %}">
      <i data-lucide="layout-dashboard" style="width:15px;height:15px;"></i> Overview
    </a>
    <a href="{{ url_for('events') }}" class="nav-item {% if active=='events' %}active{% endif %}">
      <i data-lucide="activity" style="width:15px;height:15px;"></i> Security Events
    </a>
    <a href="{{ url_for('alerts') }}" class="nav-item {% if active=='alerts' %}active{% endif %}">
      <i data-lucide="bell" style="width:15px;height:15px;"></i> Alerts
      {% if new_alert_count > 0 %}<span class="badge">{{ new_alert_count }}</span>{% endif %}
    </a>
    <a href="{{ url_for('incidents') }}" class="nav-item {% if active=='incidents' %}active{% endif %}">
      <i data-lucide="folder-open" style="width:15px;height:15px;"></i> Incidents
      {% if open_incident_count > 0 %}<span class="badge badge-warn">{{ open_incident_count }}</span>{% endif %}
    </a>
  </div>

  <div class="nav-section">
    <div class="nav-label">Manage</div>
    <a href="{{ url_for('ingestion') }}" class="nav-item {% if active=='ingestion' %}active{% endif %}">
      <i data-lucide="upload" style="width:15px;height:15px;"></i> Log Ingestion
    </a>
    <a href="{{ url_for('rules') }}" class="nav-item {% if active=='rules' %}active{% endif %}">
      <i data-lucide="cpu" style="width:15px;height:15px;"></i> Detection Rules
    </a>
    <a href="{{ url_for('reports') }}" class="nav-item {% if active=='reports' %}active{% endif %}">
      <i data-lucide="file-bar-chart" style="width:15px;height:15px;"></i> Reports
    </a>
  </div>

  <div class="nav-section">
    <div class="nav-label">Help</div>
    <a href="{{ url_for('how_to_use') }}" class="nav-item {% if active=='how_to_use' %}active{% endif %}">
      <i data-lucide="book-open" style="width:15px;height:15px;"></i> How to Use
    </a>
    <a href="{{ url_for('customer_care') }}" class="nav-item {% if active=='customer_care' %}active{% endif %}">
      <i data-lucide="headphones" style="width:15px;height:15px;"></i> Customer Care
    </a>
  </div>

  <div class="nav-section">
    <div class="nav-label">System</div>
    <a href="{{ url_for('settings') }}" class="nav-item {% if active=='settings' %}active{% endif %}">
      <i data-lucide="settings" style="width:15px;height:15px;"></i> Settings
    </a>
    <a href="{{ url_for('about') }}" class="nav-item {% if active=='about' %}active{% endif %}">
      <i data-lucide="globe" style="width:15px;height:15px;"></i> About Website
    </a>
  </div>

  <!-- Logged-in user + logout at bottom of sidebar -->
  <div style="margin-top:auto;padding:12px 16px;border-top:1px solid var(--border);">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
      <div style="width:30px;height:30px;border-radius:50%;background:var(--accent2);
                  display:flex;align-items:center;justify-content:center;font-size:11px;
                  font-weight:700;color:#fff;flex-shrink:0;">
        {{ current_user.get('initials','?') }}
      </div>
      <div style="overflow:hidden;">
        <div style="font-size:13px;font-weight:600;color:var(--text);
                    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
          {{ current_user.get('display', current_username) }}
        </div>
        <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;">
          {{ current_user.get('role','') }}
        </div>
      </div>
    </div>
    <a href="{{ url_for('logout') }}" class="nav-item" style="color:var(--red);padding:6px 0;">
      <i data-lucide="log-out" style="width:14px;height:14px;"></i> Log Out
    </a>
  </div>
</nav>

<!-- TOP BAR -->
<header id="topbar">
  <div style="display:flex;align-items:center;gap:12px;">
    <span class="hamburger" onclick="toggleSidebar()">
      <i data-lucide="menu" style="width:20px;height:20px;color:var(--muted);"></i>
    </span>
    <span class="topbar-title">{{ page_title }}</span>
  </div>
  <div class="topbar-right">
    <span class="demo-badge">⚠ DEMO DATA</span>
    <!-- Theme toggle -->
    <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" title="Toggle light/dark mode" aria-label="Toggle theme">
      <i data-lucide="sun" id="themeIconLight" style="width:16px;height:16px;display:none;"></i>
      <i data-lucide="moon" id="themeIconDark" style="width:16px;height:16px;"></i>
    </button>
    <div style="display:flex;align-items:center;gap:8px;">
      <div class="topbar-user" title="{{ current_user.get('display','') }}">
        {{ current_user.get('initials','?') }}
      </div>
      <span style="font-size:12px;color:var(--muted);display:none;" class="show-lg">
        {{ current_user.get('display','') }}
      </span>
    </div>
  </div>
</header>

<!-- MAIN -->
<div id="main">
  <div class="page">
    {% for cat, msg in get_flashed_messages(with_categories=true) %}
    <div class="flash flash-{{ cat }}">{{ msg }}</div>
    {% endfor %}
    {% block content %}{% endblock %}
  </div>
</div>

<script>
// ── Theme toggle ──────────────────────────────────────────────
(function(){
  var saved = localStorage.getItem('soc-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
})();

function toggleTheme(){
  var current = document.documentElement.getAttribute('data-theme') || 'dark';
  var next    = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('soc-theme', next);
  _updateThemeIcons(next);
}

function _updateThemeIcons(theme){
  var light = document.getElementById('themeIconLight');
  var dark  = document.getElementById('themeIconDark');
  if (!light || !dark) return;
  if (theme === 'light'){
    light.style.display = 'block';
    dark.style.display  = 'none';
  } else {
    light.style.display = 'none';
    dark.style.display  = 'block';
  }
}

// ── Sidebar ───────────────────────────────────────────────────
function toggleSidebar(){
  document.getElementById('sidebar').classList.toggle('open');
}

// ── Init ──────────────────────────────────────────────────────
lucide.createIcons();
_updateThemeIcons(document.documentElement.getAttribute('data-theme') || 'dark');
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════
#  ROUTE: DASHBOARD
# ══════════════════════════════════════════════════════════════════

DASHBOARD_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header">
  <h1><i data-lucide="layout-dashboard" style="width:18px;height:18px;vertical-align:-3px;margin-right:6px;"></i>Security Overview</h1>
  <form method="get" style="display:flex;gap:8px;align-items:center;">
    <label style="margin:0;font-size:12px;color:var(--muted);">Period:</label>
    <select name="days" onchange="this.form.submit()" style="width:auto;padding:6px 10px;">
      <option value="1" {% if days==1 %}selected{% endif %}>Last 24h</option>
      <option value="7" {% if days==7 %}selected{% endif %}>Last 7 days</option>
      <option value="30" {% if days==30 %}selected{% endif %}>Last 30 days</option>
    </select>
  </form>
</div>

<div class="cards">
  <div class="card">
    <div class="card-label">Total Events</div>
    <div class="card-value" style="color:var(--cyan);">{{ stats.total_events }}</div>
    <div class="card-sub">In selected period</div>
  </div>
  <div class="card">
    <div class="card-label">Failed Logins</div>
    <div class="card-value" style="color:var(--orange);">{{ stats.failed_logins }}</div>
    <div class="card-sub">Authentication failures</div>
  </div>
  <div class="card">
    <div class="card-label">Active Alerts</div>
    <div class="card-value" style="color:var(--red);">{{ stats.active_alerts }}</div>
    <div class="card-sub"><a href="{{ url_for('alerts') }}" style="color:var(--accent);">View all</a></div>
  </div>
  <div class="card">
    <div class="card-label">Open Incidents</div>
    <div class="card-value" style="color:var(--yellow);">{{ stats.open_incidents }}</div>
    <div class="card-sub"><a href="{{ url_for('incidents') }}" style="color:var(--accent);">Manage</a></div>
  </div>
  <div class="card">
    <div class="card-label">High / Critical</div>
    <div class="card-value" style="color:var(--red);">{{ stats.high_critical }}</div>
    <div class="card-sub">Alerts needing attention</div>
  </div>
  <div class="card">
    <div class="card-label">Account Lockouts</div>
    <div class="card-value" style="color:var(--med);">{{ stats.lockouts }}</div>
    <div class="card-sub">Lockout events</div>
  </div>
</div>

<div class="charts-grid">
  <div class="chart-card" style="grid-column:span 2;">
    <h3>Events Over Time (Last {{ days }} day{{ 's' if days>1 else '' }})</h3>
    <div class="chart-wrapper"><canvas id="eventsChart"></canvas></div>
  </div>
  <div class="chart-card">
    <h3>Alert Severity Distribution</h3>
    <div class="chart-wrapper"><canvas id="severityChart"></canvas></div>
  </div>
  <div class="chart-card">
    <h3>Event Category Breakdown</h3>
    <div class="chart-wrapper"><canvas id="categoryChart"></canvas></div>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">

<div class="table-card">
  <div class="table-card-header">
    <h3>Recent Security Events</h3>
    <a href="{{ url_for('events') }}" class="btn btn-sm">View All</a>
  </div>
  {% if recent_events %}
  <table>
    <thead><tr><th>Time</th><th>Source IP</th><th>User</th><th>Result</th></tr></thead>
    <tbody>
    {% for e in recent_events %}
    <tr>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);">{{ e['timestamp'][:16] }}</td>
      <td>{{ e['source_ip'] or '—' }}</td>
      <td>{{ e['username'] or '—' }}</td>
      <td>
        {% if e['auth_result']=='success' %}<span class="badge-sev badge-low">success</span>
        {% elif e['auth_result']=='failure' %}<span class="badge-sev badge-high">failure</span>
        {% elif e['auth_result']=='lockout' %}<span class="badge-sev badge-medium">lockout</span>
        {% else %}<span style="color:var(--muted);">{{ e['auth_result'] or '—' }}</span>{% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty-state"><p>No events yet. <a href="{{ url_for('ingestion') }}" class="table-link">Upload logs</a>.</p></div>
  {% endif %}
</div>

<div class="table-card">
  <div class="table-card-header">
    <h3>Recent Alerts</h3>
    <a href="{{ url_for('alerts') }}" class="btn btn-sm">View All</a>
  </div>
  {% if recent_alerts %}
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Time</th><th>Status</th></tr></thead>
    <tbody>
    {% for a in recent_alerts %}
    <tr>
      <td>
        <span class="badge-sev badge-{{ a['severity'] }}">{{ a['severity'] }}</span>
      </td>
      <td><a href="{{ url_for('alert_detail', alert_id=a['id']) }}" class="table-link">{{ a['rule_name'][:30] }}</a></td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);">{{ a['triggered_at'][:16] }}</td>
      <td><span class="badge-status st-{{ a['status'] }}">{{ a['status'].replace('_',' ') }}</span></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty-state"><p>No alerts generated yet.</p></div>
  {% endif %}
</div>

</div>

<script>
const chartDefaults = {
  plugins:{ legend:{labels:{color:'#8b949e',font:{size:11}}} },
  scales:{ x:{ticks:{color:'#8b949e',font:{size:10}}, grid:{color:'rgba(48,54,61,.8)'}},
           y:{ticks:{color:'#8b949e',font:{size:10}}, grid:{color:'rgba(48,54,61,.8)'}, beginAtZero:true} }
};

// Events over time
const evData = {{ events_over_time|tojson }};
new Chart(document.getElementById('eventsChart'), {
  type:'line',
  data:{
    labels: evData.map(d=>d.date),
    datasets:[
      {label:'Total Events', data:evData.map(d=>d.total), borderColor:'#58a6ff',
       backgroundColor:'rgba(88,166,255,.08)', tension:.3, fill:true, pointRadius:3},
      {label:'Failures', data:evData.map(d=>d.failures), borderColor:'#f85149',
       backgroundColor:'rgba(248,81,73,.06)', tension:.3, fill:true, pointRadius:3},
    ]
  },
  options:{...chartDefaults, responsive:true, maintainAspectRatio:false}
});

// Severity donut
const sevData = {{ severity_data|tojson }};
new Chart(document.getElementById('severityChart'), {
  type:'doughnut',
  data:{
    labels: sevData.map(d=>d.severity.charAt(0).toUpperCase()+d.severity.slice(1)),
    datasets:[{
      data: sevData.map(d=>d.count),
      backgroundColor:['#f85149','#ff7b72','#e3b341','#3fb950','#58a6ff'],
      borderColor:'#161b22', borderWidth:2,
    }]
  },
  options:{responsive:true, maintainAspectRatio:false,
           plugins:{legend:{position:'right',labels:{color:'#8b949e',font:{size:11}}}}}
});

// Category bar
const catData = {{ category_data|tojson }};
new Chart(document.getElementById('categoryChart'), {
  type:'bar',
  data:{
    labels: catData.map(d=>d.event_type),
    datasets:[{label:'Events', data:catData.map(d=>d.count),
               backgroundColor:'rgba(88,166,255,.6)', borderColor:'#58a6ff',borderWidth:1}]
  },
  options:{...chartDefaults, responsive:true, maintainAspectRatio:false,
           plugins:{legend:{display:false}}}
});
</script>
{% endblock %}""")


@app.route("/")
def dashboard():
    days = int(request.args.get("days", 7))
    days = max(1, min(days, 90))
    cutoff = (_utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    db = get_db()

    stats = {
        "total_events":  db.execute("SELECT COUNT(*) FROM security_events WHERE timestamp>=?", (cutoff,)).fetchone()[0],
        "failed_logins": db.execute("SELECT COUNT(*) FROM security_events WHERE auth_result='failure' AND timestamp>=?", (cutoff,)).fetchone()[0],
        "active_alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE status NOT IN ('resolved','false_positive')").fetchone()[0],
        "open_incidents":db.execute("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')").fetchone()[0],
        "high_critical": db.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('high','critical') AND status NOT IN ('resolved','false_positive')").fetchone()[0],
        "lockouts":      db.execute("SELECT COUNT(*) FROM security_events WHERE auth_result='lockout' AND timestamp>=?", (cutoff,)).fetchone()[0],
    }

    # events over time (grouped by day)
    rows = db.execute("""
        SELECT substr(timestamp,1,10) as date,
               COUNT(*) as total,
               SUM(CASE WHEN auth_result='failure' THEN 1 ELSE 0 END) as failures
        FROM security_events WHERE timestamp>=? GROUP BY date ORDER BY date
    """, (cutoff,)).fetchall()
    events_over_time = [dict(r) for r in rows]

    sev_rows = db.execute("""
        SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC
    """).fetchall()
    severity_data = [dict(r) for r in sev_rows]

    cat_rows = db.execute("""
        SELECT event_type, COUNT(*) as count FROM security_events
        WHERE timestamp>=? GROUP BY event_type ORDER BY count DESC LIMIT 8
    """, (cutoff,)).fetchall()
    category_data = [dict(r) for r in cat_rows]

    recent_events = [dict(r) for r in db.execute(
        "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10"
    ).fetchall()]
    recent_alerts = [dict(r) for r in db.execute(
        "SELECT * FROM alerts ORDER BY triggered_at DESC LIMIT 10"
    ).fetchall()]

    return render_template_string(DASHBOARD_TMPL,
        page_title="Overview", active="dashboard",
        stats=stats, days=days,
        events_over_time=events_over_time,
        severity_data=severity_data,
        category_data=category_data,
        recent_events=recent_events,
        recent_alerts=recent_alerts,
    )

# ══════════════════════════════════════════════════════════════════
#  ROUTE: SECURITY EVENTS
# ══════════════════════════════════════════════════════════════════

EVENTS_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header">
  <h1>Security Events</h1>
  <div style="display:flex;gap:8px;">
    <a href="{{ url_for('export_events') }}?{{ request.query_string.decode() }}" class="btn btn-sm">
      <i data-lucide="download" style="width:13px;height:13px;"></i> Export CSV
    </a>
  </div>
</div>
<form method="get" class="filters">
  <input type="text" name="q" placeholder="Search username, IP, description…" value="{{ q }}" style="min-width:200px;">
  <select name="auth_result"><option value="">All Results</option>
    <option value="success" {% if auth_result=='success' %}selected{% endif %}>Success</option>
    <option value="failure" {% if auth_result=='failure' %}selected{% endif %}>Failure</option>
    <option value="lockout" {% if auth_result=='lockout' %}selected{% endif %}>Lockout</option>
  </select>
  <select name="days"><option value="">All Time</option>
    <option value="1" {% if days=='1' %}selected{% endif %}>Last 24h</option>
    <option value="7" {% if days=='7' %}selected{% endif %}>Last 7 days</option>
    <option value="30" {% if days=='30' %}selected{% endif %}>Last 30 days</option>
  </select>
  <button type="submit" class="btn btn-primary btn-sm">Filter</button>
  <a href="{{ url_for('events') }}" class="btn btn-sm">Reset</a>
  <span style="color:var(--muted);font-size:12px;margin-left:auto;">{{ total }} events</span>
</form>
<div class="table-card">
  {% if rows %}
  <table>
    <thead><tr><th>#</th><th>Timestamp</th><th>Source IP</th><th>Username</th><th>Event Type</th><th>Result</th><th>Description</th></tr></thead>
    <tbody>
    {% for e in rows %}
    <tr>
      <td style="color:var(--muted);font-size:11px;">{{ e['id'] }}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;white-space:nowrap;">{{ e['timestamp'] }}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px;">{{ e['source_ip'] or '—' }}</td>
      <td>{{ e['username'] or '—' }}</td>
      <td><span class="badge-sev badge-info">{{ e['event_type'] }}</span></td>
      <td>
        {% if e['auth_result']=='success' %}<span class="badge-sev badge-low">success</span>
        {% elif e['auth_result']=='failure' %}<span class="badge-sev badge-high">failure</span>
        {% elif e['auth_result']=='lockout' %}<span class="badge-sev badge-medium">lockout</span>
        {% elif e['auth_result'] %}<span class="badge-sev badge-info">{{ e['auth_result'] }}</span>
        {% else %}—{% endif %}
      </td>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);" title="{{ e['description'] or '' }}">{{ e['description'] or '—' }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  <div class="pagination" style="padding:12px;">
    {% if page > 1 %}<a href="?{{ q_str }}&page={{ page-1 }}" class="page-btn">‹ Prev</a>{% endif %}
    <span style="font-size:12px;color:var(--muted);">Page {{ page }} / {{ total_pages }}</span>
    {% if page < total_pages %}<a href="?{{ q_str }}&page={{ page+1 }}" class="page-btn">Next ›</a>{% endif %}
  </div>
  {% else %}
  <div class="empty-state">
    <div class="empty-icon">📋</div>
    <h3>No events found</h3>
    <p>Try adjusting your filters or <a href="{{ url_for('ingestion') }}" class="table-link">upload log files</a>.</p>
  </div>
  {% endif %}
</div>
{% endblock %}""")


@app.route("/events")
def events():
    q = request.args.get("q", "").strip()
    auth_result = request.args.get("auth_result", "")
    days = request.args.get("days", "")
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50

    db = get_db()
    conditions, params = [], []
    if q:
        conditions.append("(username LIKE ? OR source_ip LIKE ? OR description LIKE ?)")
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if auth_result:
        conditions.append("auth_result=?")
        params.append(auth_result)
    if days:
        cutoff = (_utcnow() - timedelta(days=int(days))).strftime("%Y-%m-%dT%H:%M:%S")
        conditions.append("timestamp>=?")
        params.append(cutoff)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    total = db.execute(f"SELECT COUNT(*) FROM security_events {where}", params).fetchone()[0]
    total_pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page
    rows = db.execute(
        f"SELECT * FROM security_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()
    rows = [dict(r) for r in rows]

    q_str = "&".join(f"{k}={v}" for k, v in [("q", q), ("auth_result", auth_result), ("days", days)] if v)
    return render_template_string(EVENTS_TMPL,
        page_title="Security Events", active="events",
        rows=rows, total=total, page=page, total_pages=total_pages,
        q=q, auth_result=auth_result, days=days, q_str=q_str,
    )


@app.route("/events/export")
def export_events():
    q = request.args.get("q", "").strip()
    auth_result = request.args.get("auth_result", "")
    days = request.args.get("days", "")
    db = get_db()
    conditions, params = [], []
    if q:
        conditions.append("(username LIKE ? OR source_ip LIKE ? OR description LIKE ?)")
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if auth_result:
        conditions.append("auth_result=?")
        params.append(auth_result)
    if days:
        cutoff = (_utcnow() - timedelta(days=int(days))).strftime("%Y-%m-%dT%H:%M:%S")
        conditions.append("timestamp>=?")
        params.append(cutoff)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows = db.execute(f"SELECT * FROM security_events {where} ORDER BY timestamp DESC LIMIT 5000", params).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "source_ip", "username", "event_type", "auth_result", "description"])
    for r in rows:
        writer.writerow([_safe_csv_cell(r[k]) for k in ("id","timestamp","source_ip","username","event_type","auth_result","description")])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"sentinel_events_{_utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    )

# ══════════════════════════════════════════════════════════════════
#  ROUTE: ALERTS
# ══════════════════════════════════════════════════════════════════

ALERTS_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header">
  <h1>Alerts</h1>
  <a href="{{ url_for('export_alerts') }}" class="btn btn-sm">
    <i data-lucide="download" style="width:13px;height:13px;"></i> Export CSV
  </a>
</div>
<form method="get" class="filters">
  <input type="text" name="q" placeholder="Search rule, IP, username…" value="{{ q }}" style="min-width:200px;">
  <select name="severity"><option value="">All Severities</option>
    {% for s in ['critical','high','medium','low'] %}
    <option value="{{ s }}" {% if severity==s %}selected{% endif %}>{{ s.capitalize() }}</option>
    {% endfor %}
  </select>
  <select name="status"><option value="">All Statuses</option>
    {% for s in ['new','acknowledged','investigating','resolved','false_positive'] %}
    <option value="{{ s }}" {% if status==s %}selected{% endif %}>{{ s.replace('_',' ').title() }}</option>
    {% endfor %}
  </select>
  <button type="submit" class="btn btn-primary btn-sm">Filter</button>
  <a href="{{ url_for('alerts') }}" class="btn btn-sm">Reset</a>
  <span style="color:var(--muted);font-size:12px;margin-left:auto;">{{ total }} alerts</span>
</form>
<div class="table-card">
  {% if rows %}
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>Source IP</th><th>Username</th><th>Triggered</th><th>Status</th><th>Action</th></tr></thead>
    <tbody>
    {% for a in rows %}
    <tr>
      <td style="color:var(--muted);font-size:11px;">{{ a['id'] }}</td>
      <td><span class="badge-sev badge-{{ a['severity'] }}">{{ a['severity'] }}</span></td>
      <td><a href="{{ url_for('alert_detail', alert_id=a['id']) }}" class="table-link">{{ a['rule_name'] }}</a></td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px;">{{ a['source_ip'] or '—' }}</td>
      <td>{{ a['username'] or '—' }}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;white-space:nowrap;">{{ a['triggered_at'][:16] }}</td>
      <td><span class="badge-status st-{{ a['status'] }}">{{ a['status'].replace('_',' ') }}</span></td>
      <td><a href="{{ url_for('alert_detail', alert_id=a['id']) }}" class="btn btn-sm">View</a></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  <div class="pagination" style="padding:12px;">
    {% if page > 1 %}<a href="?{{ q_str }}&page={{ page-1 }}" class="page-btn">‹ Prev</a>{% endif %}
    <span style="font-size:12px;color:var(--muted);">Page {{ page }} / {{ total_pages }}</span>
    {% if page < total_pages %}<a href="?{{ q_str }}&page={{ page+1 }}" class="page-btn">Next ›</a>{% endif %}
  </div>
  {% else %}
  <div class="empty-state">
    <div class="empty-icon">🔔</div>
    <h3>No alerts found</h3>
    <p>Upload log files and the detection engine will generate alerts automatically.</p>
  </div>
  {% endif %}
</div>
{% endblock %}""")

ALERT_DETAIL_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header">
  <h1>Alert #{{ a['id'] }} — {{ a['rule_name'] }}</h1>
  <a href="{{ url_for('alerts') }}" class="btn btn-sm">← Back to Alerts</a>
</div>

<div class="detail-grid">
  <div class="detail-card">
    <h3>Alert Details</h3>
    <div class="detail-row"><span class="detail-key">Alert ID</span><span class="detail-val">#{{ a['id'] }}</span></div>
    <div class="detail-row"><span class="detail-key">Rule</span><span class="detail-val">{{ a['rule_name'] }}</span></div>
    <div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val"><span class="badge-sev badge-{{ a['severity'] }}">{{ a['severity'] }}</span></span></div>
    <div class="detail-row"><span class="detail-key">Status</span><span class="detail-val"><span class="badge-status st-{{ a['status'] }}">{{ a['status'].replace('_',' ') }}</span></span></div>
    <div class="detail-row"><span class="detail-key">Triggered</span><span class="detail-val">{{ a['triggered_at'] }}</span></div>
    <div class="detail-row"><span class="detail-key">Source IP</span><span class="detail-val">{{ a['source_ip'] or '—' }}</span></div>
    <div class="detail-row"><span class="detail-key">Username</span><span class="detail-val">{{ a['username'] or '—' }}</span></div>
  </div>
  <div class="detail-card">
    <h3>Update Status</h3>
    <form method="post" action="{{ url_for('alert_update', alert_id=a['id']) }}">
      <div class="form-group">
        <label>New Status</label>
        <select name="status">
          {% for s in ['new','acknowledged','investigating','resolved','false_positive'] %}
          <option value="{{ s }}" {% if a['status']==s %}selected{% endif %}>{{ s.replace('_',' ').title() }}</option>
          {% endfor %}
        </select>
      </div>
      <button type="submit" class="btn btn-primary">Update Status</button>
    </form>
    <hr style="border-color:var(--border);margin:16px 0;">
    <form method="post" action="{{ url_for('create_incident_from_alert', alert_id=a['id']) }}">
      <button type="submit" class="btn" style="width:100%;">
        <i data-lucide="folder-plus" style="width:13px;height:13px;"></i> Create Incident from Alert
      </button>
    </form>
  </div>
</div>

<div class="detail-card" style="margin-bottom:16px;">
  <h3>Detection Explanation</h3>
  <p style="color:var(--text);line-height:1.7;margin-bottom:12px;">{{ a['description'] }}</p>
</div>

{% if a['recommendation'] %}
<div class="detail-card" style="margin-bottom:16px;border-left:3px solid var(--accent);">
  <h3>Investigation Recommendation</h3>
  <p style="color:var(--text);line-height:1.7;">{{ a['recommendation'] }}</p>
  <p style="color:var(--muted);font-size:12px;margin-top:8px;">
    ⚠ This is a recommendation only. Do not automatically block IPs or execute remediation without proper investigation.
  </p>
</div>
{% endif %}

{% if evidence %}
<div class="detail-card" style="margin-bottom:16px;">
  <h3>Evidence</h3>
  <div class="evidence-box">{{ evidence }}</div>
</div>
{% endif %}

{% if linked_incidents %}
<div class="table-card">
  <div class="table-card-header"><h3>Linked Incidents</h3></div>
  <table>
    <thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th></tr></thead>
    <tbody>
    {% for inc in linked_incidents %}
    <tr>
      <td>{{ inc['id'] }}</td>
      <td><a href="{{ url_for('incident_detail', incident_id=inc['id']) }}" class="table-link">{{ inc['title'] }}</a></td>
      <td><span class="badge-sev badge-{{ inc['severity'] }}">{{ inc['severity'] }}</span></td>
      <td><span class="badge-status st-{{ inc['status'] }}">{{ inc['status'] }}</span></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}
{% endblock %}""")


@app.route("/alerts")
def alerts():
    q        = request.args.get("q", "").strip()
    severity = request.args.get("severity", "")
    status   = request.args.get("status", "")
    page     = max(1, int(request.args.get("page", 1)))
    per_page = 25
    db = get_db()
    conditions, params = [], []
    if q:
        conditions.append("(rule_name LIKE ? OR source_ip LIKE ? OR username LIKE ?)")
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if severity:
        conditions.append("severity=?")
        params.append(severity)
    if status:
        conditions.append("status=?")
        params.append(status)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    total = db.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
    total_pages = max(1, (total + per_page - 1) // per_page)
    rows = db.execute(
        f"SELECT * FROM alerts {where} ORDER BY triggered_at DESC LIMIT ? OFFSET ?",
        params + [per_page, (page-1)*per_page]
    ).fetchall()
    rows = [dict(r) for r in rows]
    q_str = "&".join(f"{k}={v}" for k, v in [("q",q),("severity",severity),("status",status)] if v)
    return render_template_string(ALERTS_TMPL,
        page_title="Alerts", active="alerts",
        rows=rows, total=total, page=page, total_pages=total_pages,
        q=q, severity=severity, status=status, q_str=q_str,
    )


@app.route("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    db = get_db()
    a = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not a:
        abort(404)
    a = dict(a)
    try:
        ev = json.loads(a.get("evidence") or "{}")
        evidence = json.dumps(ev, indent=2)
    except Exception:
        evidence = a.get("evidence", "")

    linked = db.execute("""
        SELECT i.* FROM incidents i
        JOIN incident_alerts ia ON ia.incident_id=i.id
        WHERE ia.alert_id=?
    """, (alert_id,)).fetchall()
    return render_template_string(ALERT_DETAIL_TMPL,
        page_title=f"Alert #{alert_id}", active="alerts",
        a=a, evidence=evidence,
        linked_incidents=[dict(r) for r in linked],
    )


@app.route("/alerts/<int:alert_id>/update", methods=["POST"])
def alert_update(alert_id):
    allowed = {"new","acknowledged","investigating","resolved","false_positive"}
    status = request.form.get("status","").strip()
    if status not in allowed:
        flash("Invalid status value.", "error")
        return redirect(url_for("alert_detail", alert_id=alert_id))
    db = get_db()
    if not db.execute("SELECT id FROM alerts WHERE id=?", (alert_id,)).fetchone():
        abort(404)
    db.execute("UPDATE alerts SET status=?, updated_at=datetime('now') WHERE id=?", (status, alert_id))
    db.commit()
    flash(f"Alert #{alert_id} status updated to '{status}'.", "success")
    return redirect(url_for("alert_detail", alert_id=alert_id))


@app.route("/alerts/<int:alert_id>/create-incident", methods=["POST"])
def create_incident_from_alert(alert_id):
    db = get_db()
    alert = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert:
        abort(404)
    alert = dict(alert)
    title = f"Incident — {alert['rule_name']} (Alert #{alert_id})"
    db.execute("""INSERT INTO incidents (title,description,severity,status)
                  VALUES (?,?,?,'open')""",
               (title, alert["description"], alert["severity"]))
    inc_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute("INSERT OR IGNORE INTO incident_alerts (incident_id,alert_id) VALUES (?,?)", (inc_id, alert_id))
    db.commit()
    flash(f"Incident #{inc_id} created and linked to Alert #{alert_id}.", "success")
    return redirect(url_for("incident_detail", incident_id=inc_id))


@app.route("/alerts/export")
def export_alerts():
    db = get_db()
    rows = db.execute("SELECT * FROM alerts ORDER BY triggered_at DESC LIMIT 5000").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id","rule_key","rule_name","severity","status","source_ip","username","triggered_at","description"])
    for r in rows:
        writer.writerow([_safe_csv_cell(r[k]) for k in ("id","rule_key","rule_name","severity","status","source_ip","username","triggered_at","description")])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv",
                     as_attachment=True,
                     download_name=f"sentinel_alerts_{_utcnow().strftime('%Y%m%d_%H%M%S')}.csv")

# ══════════════════════════════════════════════════════════════════
#  ROUTE: INCIDENTS
# ══════════════════════════════════════════════════════════════════

INCIDENTS_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header">
  <h1>Incidents</h1>
  <a href="{{ url_for('incident_new') }}" class="btn btn-primary">
    <i data-lucide="plus" style="width:13px;height:13px;"></i> New Incident
  </a>
</div>
<form method="get" class="filters">
  <input type="text" name="q" placeholder="Search title…" value="{{ q }}" style="min-width:200px;">
  <select name="status"><option value="">All Statuses</option>
    {% for s in ['open','investigating','contained','resolved','closed'] %}
    <option value="{{ s }}" {% if status==s %}selected{% endif %}>{{ s.capitalize() }}</option>
    {% endfor %}
  </select>
  <button type="submit" class="btn btn-primary btn-sm">Filter</button>
  <a href="{{ url_for('incidents') }}" class="btn btn-sm">Reset</a>
  <span style="color:var(--muted);font-size:12px;margin-left:auto;">{{ total }} incidents</span>
</form>
<div class="table-card">
  {% if rows %}
  <table>
    <thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th><th>Created</th><th>Action</th></tr></thead>
    <tbody>
    {% for inc in rows %}
    <tr>
      <td style="color:var(--muted);">{{ inc['id'] }}</td>
      <td><a href="{{ url_for('incident_detail', incident_id=inc['id']) }}" class="table-link">{{ inc['title'] }}</a></td>
      <td><span class="badge-sev badge-{{ inc['severity'] }}">{{ inc['severity'] }}</span></td>
      <td><span class="badge-status st-{{ inc['status'] }}">{{ inc['status'] }}</span></td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);">{{ inc['created_at'][:16] }}</td>
      <td><a href="{{ url_for('incident_detail', incident_id=inc['id']) }}" class="btn btn-sm">View</a></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty-state">
    <div class="empty-icon">📁</div>
    <h3>No incidents yet</h3>
    <p>Create an incident manually or generate one from an alert.</p>
  </div>
  {% endif %}
</div>
{% endblock %}""")

INCIDENT_NEW_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header">
  <h1>New Incident</h1>
  <a href="{{ url_for('incidents') }}" class="btn btn-sm">← Back</a>
</div>
<div class="detail-card" style="max-width:600px;">
  <form method="post" action="{{ url_for('incident_new') }}">
    <div class="form-group">
      <label>Title *</label>
      <input type="text" name="title" required maxlength="200" placeholder="Brief incident title">
    </div>
    <div class="form-group">
      <label>Description</label>
      <textarea name="description" rows="3" placeholder="What happened?"></textarea>
    </div>
    <div class="form-group">
      <label>Severity</label>
      <select name="severity">
        {% for s in ['critical','high','medium','low'] %}
        <option value="{{ s }}" {% if s=='medium' %}selected{% endif %}>{{ s.capitalize() }}</option>
        {% endfor %}
      </select>
    </div>
    <div class="form-group">
      <label>Assigned To</label>
      <input type="text" name="assigned_to" maxlength="100" placeholder="Analyst name (optional)">
    </div>
    <button type="submit" class="btn btn-primary">Create Incident</button>
  </form>
</div>
{% endblock %}""")

INCIDENT_DETAIL_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header">
  <h1>Incident #{{ inc['id'] }} — {{ inc['title'] }}</h1>
  <a href="{{ url_for('incidents') }}" class="btn btn-sm">← Back</a>
</div>
<div class="detail-grid">
  <div class="detail-card">
    <h3>Incident Details</h3>
    <div class="detail-row"><span class="detail-key">ID</span><span class="detail-val">#{{ inc['id'] }}</span></div>
    <div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val"><span class="badge-sev badge-{{ inc['severity'] }}">{{ inc['severity'] }}</span></span></div>
    <div class="detail-row"><span class="detail-key">Status</span><span class="detail-val"><span class="badge-status st-{{ inc['status'] }}">{{ inc['status'] }}</span></span></div>
    <div class="detail-row"><span class="detail-key">Assigned To</span><span class="detail-val">{{ inc['assigned_to'] or '—' }}</span></div>
    <div class="detail-row"><span class="detail-key">Created</span><span class="detail-val">{{ inc['created_at'] }}</span></div>
    <div class="detail-row"><span class="detail-key">Updated</span><span class="detail-val">{{ inc['updated_at'] }}</span></div>
  </div>
  <div class="detail-card">
    <h3>Update Incident</h3>
    <form method="post" action="{{ url_for('incident_update', incident_id=inc['id']) }}">
      <div class="form-group">
        <label>Status</label>
        <select name="status">
          {% for s in ['open','investigating','contained','resolved','closed'] %}
          <option value="{{ s }}" {% if inc['status']==s %}selected{% endif %}>{{ s.capitalize() }}</option>
          {% endfor %}
        </select>
      </div>
      <div class="form-group">
        <label>Severity</label>
        <select name="severity">
          {% for s in ['critical','high','medium','low'] %}
          <option value="{{ s }}" {% if inc['severity']==s %}selected{% endif %}>{{ s.capitalize() }}</option>
          {% endfor %}
        </select>
      </div>
      <div class="form-group">
        <label>Assigned To</label>
        <input type="text" name="assigned_to" value="{{ inc['assigned_to'] or '' }}" maxlength="100">
      </div>
      <div class="form-group">
        <label>Resolution Summary</label>
        <textarea name="resolution" rows="2">{{ inc['resolution'] or '' }}</textarea>
      </div>
      <button type="submit" class="btn btn-primary">Update</button>
    </form>
  </div>
</div>

{% if inc['description'] %}
<div class="detail-card" style="margin-bottom:16px;">
  <h3>Description</h3>
  <p style="color:var(--text);line-height:1.7;">{{ inc['description'] }}</p>
</div>
{% endif %}

<!-- Linked Alerts -->
<div class="table-card" style="margin-bottom:16px;">
  <div class="table-card-header">
    <h3>Linked Alerts</h3>
    <form method="post" action="{{ url_for('incident_link_alert', incident_id=inc['id']) }}" style="display:flex;gap:8px;">
      <input type="number" name="alert_id" placeholder="Alert ID" style="width:110px;padding:4px 8px;font-size:12px;">
      <button type="submit" class="btn btn-sm btn-primary">Link Alert</button>
    </form>
  </div>
  {% if linked_alerts %}
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>Status</th><th>Action</th></tr></thead>
    <tbody>
    {% for a in linked_alerts %}
    <tr>
      <td>{{ a['id'] }}</td>
      <td><span class="badge-sev badge-{{ a['severity'] }}">{{ a['severity'] }}</span></td>
      <td><a href="{{ url_for('alert_detail', alert_id=a['id']) }}" class="table-link">{{ a['rule_name'] }}</a></td>
      <td><span class="badge-status st-{{ a['status'] }}">{{ a['status'].replace('_',' ') }}</span></td>
      <td>
        <form method="post" action="{{ url_for('incident_unlink_alert', incident_id=inc['id'], alert_id=a['id']) }}" style="display:inline;">
          <button type="submit" class="btn btn-sm btn-danger">Unlink</button>
        </form>
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div style="padding:20px;color:var(--muted);text-align:center;font-size:13px;">No alerts linked yet.</div>
  {% endif %}
</div>

<!-- Notes -->
<div class="table-card">
  <div class="table-card-header"><h3>Investigation Notes</h3></div>
  {% if notes %}
  <div style="padding:4px 0;">
    {% for note in notes %}
    <div style="padding:12px 16px;border-bottom:1px solid var(--border);">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
        <span style="font-size:12px;font-weight:600;color:var(--accent);">{{ note['author'] }}</span>
        <span style="font-size:11px;color:var(--muted);font-family:'JetBrains Mono',monospace;">{{ note['created_at'][:16] }}</span>
      </div>
      <p style="font-size:13px;color:var(--text);line-height:1.6;white-space:pre-wrap;">{{ note['note'] }}</p>
    </div>
    {% endfor %}
  </div>
  {% endif %}
  <div style="padding:16px;border-top:1px solid var(--border);">
    <form method="post" action="{{ url_for('incident_add_note', incident_id=inc['id']) }}">
      <div class="form-group">
        <label>Add Note</label>
        <textarea name="note" rows="3" placeholder="Enter investigation notes…" required></textarea>
      </div>
      <div style="display:flex;gap:8px;align-items:center;">
        <input type="text" name="author" value="analyst" maxlength="60" style="width:150px;" placeholder="Author">
        <button type="submit" class="btn btn-primary">Add Note</button>
      </div>
    </form>
  </div>
</div>
{% endblock %}""")


@app.route("/incidents")
def incidents():
    q      = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    db     = get_db()
    conditions, params = [], []
    if q:
        conditions.append("title LIKE ?")
        params.append(f"%{q}%")
    if status:
        conditions.append("status=?")
        params.append(status)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    total = db.execute(f"SELECT COUNT(*) FROM incidents {where}", params).fetchone()[0]
    rows  = db.execute(f"SELECT * FROM incidents {where} ORDER BY created_at DESC", params).fetchall()
    return render_template_string(INCIDENTS_TMPL,
        page_title="Incidents", active="incidents",
        rows=[dict(r) for r in rows], total=total, q=q, status=status,
    )


@app.route("/incidents/new", methods=["GET", "POST"])
def incident_new():
    if request.method == "POST":
        title       = request.form.get("title", "").strip()[:200]
        description = request.form.get("description", "").strip()[:2000]
        severity    = request.form.get("severity", "medium")
        assigned    = request.form.get("assigned_to", "").strip()[:100]
        if not title:
            flash("Title is required.", "error")
            return render_template_string(INCIDENT_NEW_TMPL, page_title="New Incident", active="incidents")
        if severity not in {"critical","high","medium","low"}:
            severity = "medium"
        db = get_db()
        db.execute("INSERT INTO incidents (title,description,severity,status,assigned_to) VALUES (?,?,?,'open',?)",
                   (title, description, severity, assigned or None))
        inc_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.commit()
        flash(f"Incident #{inc_id} created.", "success")
        return redirect(url_for("incident_detail", incident_id=inc_id))
    return render_template_string(INCIDENT_NEW_TMPL, page_title="New Incident", active="incidents")


@app.route("/incidents/<int:incident_id>")
def incident_detail(incident_id):
    db  = get_db()
    inc = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not inc:
        abort(404)
    notes = db.execute("SELECT * FROM incident_notes WHERE incident_id=? ORDER BY created_at", (incident_id,)).fetchall()
    linked = db.execute("""
        SELECT a.* FROM alerts a
        JOIN incident_alerts ia ON ia.alert_id=a.id
        WHERE ia.incident_id=?
    """, (incident_id,)).fetchall()
    return render_template_string(INCIDENT_DETAIL_TMPL,
        page_title=f"Incident #{incident_id}", active="incidents",
        inc=dict(inc),
        notes=[dict(n) for n in notes],
        linked_alerts=[dict(a) for a in linked],
    )


@app.route("/incidents/<int:incident_id>/update", methods=["POST"])
def incident_update(incident_id):
    db = get_db()
    if not db.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone():
        abort(404)
    status     = request.form.get("status","open")
    severity   = request.form.get("severity","medium")
    assigned   = request.form.get("assigned_to","").strip()[:100]
    resolution = request.form.get("resolution","").strip()[:2000]
    if status   not in {"open","investigating","contained","resolved","closed"}: status="open"
    if severity not in {"critical","high","medium","low"}: severity="medium"
    db.execute("""UPDATE incidents SET status=?,severity=?,assigned_to=?,resolution=?,
                  updated_at=datetime('now') WHERE id=?""",
               (status, severity, assigned or None, resolution or None, incident_id))
    db.commit()
    flash("Incident updated.", "success")
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/add-note", methods=["POST"])
def incident_add_note(incident_id):
    db = get_db()
    if not db.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone():
        abort(404)
    note   = request.form.get("note","").strip()[:5000]
    author = request.form.get("author","analyst").strip()[:60] or "analyst"
    if not note:
        flash("Note cannot be empty.", "error")
        return redirect(url_for("incident_detail", incident_id=incident_id))
    db.execute("INSERT INTO incident_notes (incident_id,author,note) VALUES (?,?,?)",
               (incident_id, author, note))
    db.commit()
    flash("Note added.", "success")
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/link-alert", methods=["POST"])
def incident_link_alert(incident_id):
    db = get_db()
    if not db.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone():
        abort(404)
    try:
        alert_id = int(request.form.get("alert_id",""))
    except (ValueError, TypeError):
        flash("Invalid alert ID.", "error")
        return redirect(url_for("incident_detail", incident_id=incident_id))
    if not db.execute("SELECT id FROM alerts WHERE id=?", (alert_id,)).fetchone():
        flash(f"Alert #{alert_id} not found.", "error")
        return redirect(url_for("incident_detail", incident_id=incident_id))
    db.execute("INSERT OR IGNORE INTO incident_alerts (incident_id,alert_id) VALUES (?,?)", (incident_id, alert_id))
    db.commit()
    flash(f"Alert #{alert_id} linked.", "success")
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/unlink-alert/<int:alert_id>", methods=["POST"])
def incident_unlink_alert(incident_id, alert_id):
    db = get_db()
    db.execute("DELETE FROM incident_alerts WHERE incident_id=? AND alert_id=?", (incident_id, alert_id))
    db.commit()
    flash(f"Alert #{alert_id} unlinked.", "success")
    return redirect(url_for("incident_detail", incident_id=incident_id))

# ══════════════════════════════════════════════════════════════════
#  ROUTE: LOG INGESTION
# ══════════════════════════════════════════════════════════════════

INGESTION_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header"><h1>Log Ingestion</h1></div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;">
<div class="detail-card">
  <h3>Upload Log File</h3>
  <p style="color:var(--muted);font-size:13px;margin-bottom:16px;">
    Supported formats: <strong>CSV</strong> and <strong>JSON Lines (.jsonl)</strong>. Max 5 MB.
  </p>

  <div class="upload-area" id="dropZone" onclick="document.getElementById('fileInput').click()">
    <div class="upload-icon">📂</div>
    <strong>Click to browse or drag &amp; drop</strong>
    <p>CSV or JSON Lines file</p>
    <p id="selectedFile" style="color:var(--accent);margin-top:8px;"></p>
  </div>

  <form method="post" enctype="multipart/form-data" id="uploadForm" style="margin-top:16px;">
    <input type="file" id="fileInput" name="file" accept=".csv,.jsonl,.json,.txt" style="display:none">
    <button type="submit" class="btn btn-primary" style="width:100%;" id="uploadBtn" disabled>
      <i data-lucide="upload" style="width:13px;height:13px;"></i> Process &amp; Ingest
    </button>
  </form>
</div>

<div class="detail-card">
  <h3>CSV Format Reference</h3>
  <p style="color:var(--muted);font-size:12px;margin-bottom:10px;">Required columns (case-insensitive):</p>
  <div class="evidence-box">timestamp,event_type,source_ip,username,auth_result,description

# Example rows:
2024-01-15T08:30:00,authentication,192.168.1.10,alice.smith,success,Normal login
2024-01-15T08:31:00,authentication,198.51.100.1,alice.smith,failure,Bad password
2024-01-15T08:32:00,authentication,198.51.100.1,alice.smith,lockout,Account locked</div>
  <p style="color:var(--muted);font-size:12px;margin-top:12px;">JSON Lines format:</p>
  <div class="evidence-box">{"timestamp":"2024-01-15T08:30:00","event_type":"authentication","source_ip":"192.168.1.10","username":"alice.smith","auth_result":"success"}
{"timestamp":"2024-01-15T08:31:00","event_type":"authentication","source_ip":"198.51.100.1","username":"bob.jones","auth_result":"failure"}</div>
</div>
</div>

{% if result %}
<div class="detail-card" style="margin-bottom:16px;border-left:3px solid
  {% if result.errors %}var(--yellow){% else %}var(--green){% endif %};">
  <h3>Ingestion Result — {{ result.filename }}</h3>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:12px 0;">
    <div style="text-align:center;">
      <div style="font-size:24px;font-weight:700;color:var(--cyan);">{{ result.total }}</div>
      <div style="font-size:11px;color:var(--muted);">Total Parsed</div>
    </div>
    <div style="text-align:center;">
      <div style="font-size:24px;font-weight:700;color:var(--green);">{{ result.accepted }}</div>
      <div style="font-size:11px;color:var(--muted);">Accepted</div>
    </div>
    <div style="text-align:center;">
      <div style="font-size:24px;font-weight:700;color:var(--red);">{{ result.rejected }}</div>
      <div style="font-size:11px;color:var(--muted);">Rejected</div>
    </div>
    <div style="text-align:center;">
      <div style="font-size:24px;font-weight:700;color:var(--yellow);">{{ result.alerts_created }}</div>
      <div style="font-size:11px;color:var(--muted);">Alerts Generated</div>
    </div>
  </div>
  {% if result.parse_errors %}
  <details style="margin-top:8px;">
    <summary style="cursor:pointer;font-size:12px;color:var(--yellow);">{{ result.parse_errors|length }} parse error(s) — click to expand</summary>
    <div class="evidence-box" style="margin-top:8px;">{% for e in result.parse_errors %}{{ e }}
{% endfor %}</div>
  </details>
  {% endif %}
</div>
{% endif %}

<div class="table-card">
  <div class="table-card-header"><h3>Ingestion History</h3></div>
  {% if batches %}
  <table>
    <thead><tr><th>#</th><th>Filename</th><th>Format</th><th>Accepted</th><th>Rejected</th><th>Alerts</th><th>Ingested At</th></tr></thead>
    <tbody>
    {% for b in batches %}
    <tr>
      <td style="color:var(--muted);">{{ b['id'] }}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px;">{{ b['filename'] }}</td>
      <td><span class="badge-sev badge-info">{{ b['source_format'] or '?' }}</span></td>
      <td style="color:var(--green);">{{ b['accepted'] }}</td>
      <td style="color:var(--red);">{{ b['rejected'] }}</td>
      <td style="color:var(--yellow);">{{ b.get('alert_count',0) }}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);">{{ b['ingested_at'][:16] }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty-state"><p>No ingestion batches yet.</p></div>
  {% endif %}
</div>

<script>
const dz = document.getElementById('dropZone');
const fi = document.getElementById('fileInput');
const btn = document.getElementById('uploadBtn');
const lbl = document.getElementById('selectedFile');

fi.addEventListener('change', () => {
  if (fi.files.length > 0) {
    lbl.textContent = fi.files[0].name;
    btn.disabled = false;
  }
});
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
dz.addEventListener('drop', e => {
  e.preventDefault(); dz.classList.remove('drag-over');
  const dt = new DataTransfer();
  dt.items.add(e.dataTransfer.files[0]);
  fi.files = dt.files;
  lbl.textContent = fi.files[0].name;
  btn.disabled = false;
});
</script>
{% endblock %}""")


@app.route("/ingestion", methods=["GET", "POST"])
def ingestion():
    db = get_db()
    result = None

    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("No file selected.", "error")
        else:
            filename = os.path.basename(f.filename)[:255]  # path traversal prevention
            # Read content (enforce size via MAX_CONTENT_LENGTH)
            content_bytes = f.read(MAX_UPLOAD_BYTES + 1)
            if len(content_bytes) > MAX_UPLOAD_BYTES:
                flash("File exceeds 5 MB limit.", "error")
            else:
                try:
                    content = content_bytes.decode("utf-8", errors="replace")
                except Exception:
                    flash("Could not decode file as UTF-8.", "error")
                    content = None

                if content is not None:
                    parsed = parse_file_content(filename, content)
                    valid_events, norm_errors = [], []
                    for raw in parsed["records"]:
                        norm = normalize_record(raw)
                        if norm["_error"]:
                            norm_errors.append(norm["_error"])
                        else:
                            del norm["_error"]
                            valid_events.append(norm)

                    all_errors = parsed["errors"] + norm_errors
                    accepted = len(valid_events)
                    rejected = len(all_errors)
                    total    = accepted + rejected

                    # Create batch record
                    db.execute("""INSERT INTO ingestion_batches
                        (filename,record_count,accepted,rejected,source_format)
                        VALUES (?,?,?,?,?)""",
                        (filename, total, accepted, rejected, parsed["format"]))
                    batch_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

                    # Insert valid events
                    if valid_events:
                        db.executemany("""
                            INSERT INTO security_events
                              (timestamp,source_ip,username,event_type,auth_result,description,raw_data,batch_id)
                            VALUES (:timestamp,:source_ip,:username,:event_type,:auth_result,:description,:raw_data,:batch_id)
                        """, [{**e, "batch_id": batch_id} for e in valid_events])

                    db.commit()

                    # Run detection
                    alerts_created = run_detection(db, batch_id=batch_id)

                    result = {
                        "filename": filename,
                        "total": total,
                        "accepted": accepted,
                        "rejected": rejected,
                        "alerts_created": alerts_created,
                        "parse_errors": all_errors[:50],
                    }

    batches = db.execute("""
        SELECT ib.*,
               (SELECT COUNT(*) FROM alerts a
                WHERE a.triggered_at >= ib.ingested_at
                  AND a.triggered_at <= datetime(ib.ingested_at,'+10 seconds')
               ) as alert_count
        FROM ingestion_batches ib
        ORDER BY ingested_at DESC LIMIT 20
    """).fetchall()

    return render_template_string(INGESTION_TMPL,
        page_title="Log Ingestion", active="ingestion",
        result=result, batches=[dict(b) for b in batches],
    )

# ══════════════════════════════════════════════════════════════════
#  ROUTE: DETECTION RULES
# ══════════════════════════════════════════════════════════════════

RULES_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header"><h1>Detection Rules</h1></div>
<p style="color:var(--muted);margin-bottom:20px;font-size:13px;">
  These rules define conditions for generating alerts. Thresholds and windows can be adjusted in Settings.
</p>
{% for rule in rules %}
<div class="detail-card" style="margin-bottom:16px;border-left:3px solid
  {% if rule['severity']=='high' %}var(--high)
  {% elif rule['severity']=='critical' %}var(--crit)
  {% elif rule['severity']=='medium' %}var(--med)
  {% else %}var(--low){% endif %};">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;">
    <div>
      <span style="font-size:10px;color:var(--muted);font-family:'JetBrains Mono',monospace;">{{ rule['rule_key'] }}</span>
      <h3 style="font-size:15px;font-weight:600;color:var(--text);margin-top:2px;">{{ rule['name'] }}</h3>
    </div>
    <div style="display:flex;gap:8px;align-items:center;">
      <span class="badge-sev badge-{{ rule['severity'] }}">{{ rule['severity'] }}</span>
      {% if rule['enabled'] %}
      <span class="badge-sev badge-low">enabled</span>
      {% else %}
      <span class="badge-sev" style="background:rgba(139,148,158,.1);color:var(--muted);">disabled</span>
      {% endif %}
    </div>
  </div>
  <p style="color:var(--text);font-size:13px;line-height:1.7;margin-bottom:12px;">{{ rule['description'] }}</p>
  <div style="display:flex;gap:20px;font-size:12px;color:var(--muted);">
    <span>Threshold: <strong style="color:var(--text);">{{ rule['threshold'] }}</strong></span>
    <span>Window: <strong style="color:var(--text);">{{ rule['window_minutes'] }} min</strong></span>
    <span>Alert count: <strong style="color:var(--cyan);">{{ rule['alert_count'] }}</strong></span>
  </div>
  {% if rule['recommendation'] %}
  <div style="margin-top:12px;padding:10px 12px;background:rgba(88,166,255,.05);
              border:1px solid rgba(88,166,255,.15);border-radius:6px;">
    <span style="font-size:11px;font-weight:600;color:var(--accent);text-transform:uppercase;">Recommendation: </span>
    <span style="font-size:12px;color:var(--muted);">{{ rule['recommendation'] }}</span>
  </div>
  {% endif %}
</div>
{% endfor %}
{% endblock %}""")


@app.route("/rules")
def rules():
    db = get_db()
    rows = db.execute("""
        SELECT r.*,
               (SELECT COUNT(*) FROM alerts a WHERE a.rule_key=r.rule_key) as alert_count
        FROM detection_rules r ORDER BY id
    """).fetchall()
    return render_template_string(RULES_TMPL,
        page_title="Detection Rules", active="rules",
        rules=[dict(r) for r in rows],
    )

# ══════════════════════════════════════════════════════════════════
#  ROUTE: REPORTS
# ══════════════════════════════════════════════════════════════════

REPORTS_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header">
  <h1>Reports</h1>
  <form method="get" style="display:flex;gap:8px;align-items:center;">
    <label style="margin:0;font-size:12px;color:var(--muted);">Period:</label>
    <select name="days" onchange="this.form.submit()" style="width:auto;padding:6px 10px;">
      <option value="7" {% if days==7 %}selected{% endif %}>Last 7 days</option>
      <option value="30" {% if days==30 %}selected{% endif %}>Last 30 days</option>
      <option value="90" {% if days==90 %}selected{% endif %}>Last 90 days</option>
    </select>
  </form>
</div>

<div class="cards" style="grid-template-columns:repeat(auto-fill,minmax(160px,1fr));">
  <div class="card">
    <div class="card-label">Total Events</div>
    <div class="card-value" style="color:var(--cyan);">{{ stats.total_events }}</div>
  </div>
  <div class="card">
    <div class="card-label">Total Alerts</div>
    <div class="card-value" style="color:var(--red);">{{ stats.total_alerts }}</div>
  </div>
  <div class="card">
    <div class="card-label">Incidents</div>
    <div class="card-value" style="color:var(--yellow);">{{ stats.total_incidents }}</div>
  </div>
  <div class="card">
    <div class="card-label">Failed Logins</div>
    <div class="card-value" style="color:var(--orange);">{{ stats.failed_logins }}</div>
  </div>
  <div class="card">
    <div class="card-label">Resolved Alerts</div>
    <div class="card-value" style="color:var(--green);">{{ stats.resolved_alerts }}</div>
  </div>
</div>

<div class="charts-grid" style="margin-bottom:24px;">
  <div class="chart-card">
    <h3>Alert Severity Distribution</h3>
    <div class="chart-wrapper"><canvas id="sevChart"></canvas></div>
  </div>
  <div class="chart-card">
    <h3>Incident Status Breakdown</h3>
    <div class="chart-wrapper"><canvas id="incChart"></canvas></div>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
<div class="table-card">
  <div class="table-card-header"><h3>Most Triggered Rules</h3></div>
  <table>
    <thead><tr><th>Rule</th><th>Alert Count</th><th>Severity</th></tr></thead>
    <tbody>
    {% for r in top_rules %}
    <tr>
      <td>{{ r['rule_name'] }}</td>
      <td style="color:var(--cyan);font-weight:600;">{{ r['cnt'] }}</td>
      <td><span class="badge-sev badge-{{ r['severity'] }}">{{ r['severity'] }}</span></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<div class="table-card">
  <div class="table-card-header"><h3>Top Source IPs (Failures)</h3></div>
  <table>
    <thead><tr><th>Source IP</th><th>Failed Logins</th></tr></thead>
    <tbody>
    {% for r in top_ips %}
    <tr>
      <td style="font-family:'JetBrains Mono',monospace;">{{ r['source_ip'] or '—' }}</td>
      <td style="color:var(--red);font-weight:600;">{{ r['cnt'] }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
</div>

<div class="table-card" style="margin-bottom:16px;">
  <div class="table-card-header">
    <h3>Failed Login Trend (by day)</h3>
  </div>
  <div style="padding:16px;">
    <div class="chart-wrapper" style="height:180px;"><canvas id="failChart"></canvas></div>
  </div>
</div>

<div class="detail-card">
  <h3>Export Data</h3>
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
    <a href="{{ url_for('export_events') }}" class="btn">
      <i data-lucide="download" style="width:13px;height:13px;"></i> Events CSV
    </a>
    <a href="{{ url_for('export_alerts') }}" class="btn">
      <i data-lucide="download" style="width:13px;height:13px;"></i> Alerts CSV
    </a>
    <a href="{{ url_for('export_incidents') }}" class="btn">
      <i data-lucide="download" style="width:13px;height:13px;"></i> Incidents CSV
    </a>
    <a href="{{ url_for('print_report') }}?days={{ days }}" class="btn" target="_blank">
      <i data-lucide="printer" style="width:13px;height:13px;"></i> Print Report
    </a>
  </div>
</div>

<script>
const co = {plugins:{legend:{labels:{color:'#8b949e',font:{size:11}}}},responsive:true,maintainAspectRatio:false};

new Chart(document.getElementById('sevChart'),{
  type:'doughnut',
  data:{
    labels:{{ sev_labels|tojson }},
    datasets:[{data:{{ sev_values|tojson }},
      backgroundColor:['#f85149','#ff7b72','#e3b341','#3fb950','#58a6ff'],
      borderColor:'#161b22',borderWidth:2}]
  },
  options:{...co,plugins:{legend:{position:'right',labels:{color:'#8b949e',font:{size:11}}}}}
});

new Chart(document.getElementById('incChart'),{
  type:'doughnut',
  data:{
    labels:{{ inc_labels|tojson }},
    datasets:[{data:{{ inc_values|tojson }},
      backgroundColor:['#f85149','#e3b341','#ff7b72','#3fb950','#8b949e'],
      borderColor:'#161b22',borderWidth:2}]
  },
  options:{...co,plugins:{legend:{position:'right',labels:{color:'#8b949e',font:{size:11}}}}}
});

const fd = {{ fail_trend|tojson }};
new Chart(document.getElementById('failChart'),{
  type:'bar',
  data:{
    labels:fd.map(d=>d.date),
    datasets:[{label:'Failed Logins',data:fd.map(d=>d.count),
      backgroundColor:'rgba(248,81,73,.5)',borderColor:'#f85149',borderWidth:1}]
  },
  options:{
    responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:false}},
    scales:{
      x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'rgba(48,54,61,.8)'}},
      y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'rgba(48,54,61,.8)'},beginAtZero:true}
    }
  }
});
</script>
{% endblock %}""")


@app.route("/reports")
def reports():
    days = int(request.args.get("days", 7))
    days = max(1, min(days, 90))
    cutoff = (_utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    db = get_db()

    stats = {
        "total_events":    db.execute("SELECT COUNT(*) FROM security_events WHERE timestamp>=?", (cutoff,)).fetchone()[0],
        "total_alerts":    db.execute("SELECT COUNT(*) FROM alerts WHERE triggered_at>=?", (cutoff,)).fetchone()[0],
        "total_incidents": db.execute("SELECT COUNT(*) FROM incidents WHERE created_at>=?", (cutoff,)).fetchone()[0],
        "failed_logins":   db.execute("SELECT COUNT(*) FROM security_events WHERE auth_result='failure' AND timestamp>=?", (cutoff,)).fetchone()[0],
        "resolved_alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE status='resolved' AND triggered_at>=?", (cutoff,)).fetchone()[0],
    }
    sev_rows = db.execute("SELECT severity,COUNT(*) c FROM alerts WHERE triggered_at>=? GROUP BY severity", (cutoff,)).fetchall()
    sev_labels = [r["severity"].capitalize() for r in sev_rows]
    sev_values = [r["c"] for r in sev_rows]

    inc_rows = db.execute("SELECT status,COUNT(*) c FROM incidents WHERE created_at>=? GROUP BY status", (cutoff,)).fetchall()
    inc_labels = [r["status"].capitalize() for r in inc_rows]
    inc_values = [r["c"] for r in inc_rows]

    top_rules = db.execute("""
        SELECT rule_name,severity,COUNT(*) cnt FROM alerts WHERE triggered_at>=?
        GROUP BY rule_name,severity ORDER BY cnt DESC LIMIT 10
    """, (cutoff,)).fetchall()

    top_ips = db.execute("""
        SELECT source_ip,COUNT(*) cnt FROM security_events
        WHERE auth_result='failure' AND timestamp>=? AND source_ip IS NOT NULL
        GROUP BY source_ip ORDER BY cnt DESC LIMIT 10
    """, (cutoff,)).fetchall()

    fail_trend = db.execute("""
        SELECT substr(timestamp,1,10) as date, COUNT(*) as count
        FROM security_events WHERE auth_result='failure' AND timestamp>=?
        GROUP BY date ORDER BY date
    """, (cutoff,)).fetchall()

    return render_template_string(REPORTS_TMPL,
        page_title="Reports", active="reports", days=days, stats=stats,
        sev_labels=sev_labels, sev_values=sev_values,
        inc_labels=inc_labels, inc_values=inc_values,
        top_rules=[dict(r) for r in top_rules],
        top_ips=[dict(r) for r in top_ips],
        fail_trend=[dict(r) for r in fail_trend],
    )


@app.route("/reports/print")
def print_report():
    days = int(request.args.get("days", 7))
    cutoff = (_utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    db = get_db()
    stats = {
        "total_events":  db.execute("SELECT COUNT(*) FROM security_events WHERE timestamp>=?", (cutoff,)).fetchone()[0],
        "total_alerts":  db.execute("SELECT COUNT(*) FROM alerts WHERE triggered_at>=?", (cutoff,)).fetchone()[0],
        "failed_logins": db.execute("SELECT COUNT(*) FROM security_events WHERE auth_result='failure' AND timestamp>=?", (cutoff,)).fetchone()[0],
        "open_incidents":db.execute("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')").fetchone()[0],
    }
    alerts = db.execute("SELECT * FROM alerts WHERE triggered_at>=? ORDER BY triggered_at DESC", (cutoff,)).fetchall()
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
    <title>SentinelSOC Report</title>
    <style>body{{font-family:Arial,sans-serif;padding:20px;}}
    h1{{color:#1a1a2e;}}table{{width:100%;border-collapse:collapse;margin:16px 0;}}
    th{{background:#eee;padding:8px;text-align:left;font-size:12px;}}
    td{{padding:8px;border-bottom:1px solid #ddd;font-size:12px;}}
    .badge{{padding:2px 6px;border-radius:3px;font-size:11px;font-weight:600;}}
    .high{{background:#ffe0de;color:#c0392b;}}.medium{{background:#fef9e7;color:#d35400;}}
    .low{{background:#eafaf1;color:#27ae60;}}
    </style></head><body>
    <h1>SentinelSOC Security Report</h1>
    <p><strong>Period:</strong> Last {days} days &nbsp; <strong>Generated:</strong> {_utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
    <p style="color:#c0392b;font-weight:600;">⚠ DEMO DATA — For educational purposes only</p>
    <h2>Summary</h2>
    <table><tr><th>Metric</th><th>Value</th></tr>
    {''.join(f"<tr><td>{k.replace('_',' ').title()}</td><td>{v}</td></tr>" for k,v in stats.items())}
    </table>
    <h2>Alerts ({len(alerts)})</h2>
    <table><tr><th>ID</th><th>Severity</th><th>Rule</th><th>Status</th><th>Triggered</th></tr>
    {''.join(f"<tr><td>{r['id']}</td><td class='badge {r['severity']}'>{r['severity']}</td><td>{r['rule_name']}</td><td>{r['status']}</td><td>{r['triggered_at'][:16]}</td></tr>" for r in alerts)}
    </table>
    <script>window.print();</script></body></html>"""
    return html


@app.route("/reports/export/incidents")
def export_incidents():
    db = get_db()
    rows = db.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 5000").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id","title","severity","status","assigned_to","created_at","updated_at"])
    for r in rows:
        writer.writerow([_safe_csv_cell(r[k]) for k in ("id","title","severity","status","assigned_to","created_at","updated_at")])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv",
                     as_attachment=True,
                     download_name=f"sentinel_incidents_{_utcnow().strftime('%Y%m%d_%H%M%S')}.csv")

# ══════════════════════════════════════════════════════════════════
#  ROUTE: SETTINGS
# ══════════════════════════════════════════════════════════════════

SETTINGS_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header"><h1>Settings</h1></div>
<div style="max-width:640px;">
{% for rule in rules %}
<div class="detail-card" style="margin-bottom:16px;">
  <h3>{{ rule['name'] }}</h3>
  <p style="font-size:12px;color:var(--muted);margin-bottom:14px;">Rule key: <code>{{ rule['rule_key'] }}</code></p>
  <form method="post" action="{{ url_for('settings_update') }}">
    <input type="hidden" name="rule_id" value="{{ rule['id'] }}">
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px;">
      <div class="form-group" style="margin:0;">
        <label>Threshold</label>
        <input type="number" name="threshold" value="{{ rule['threshold'] }}" min="1" max="100">
      </div>
      <div class="form-group" style="margin:0;">
        <label>Window (minutes)</label>
        <input type="number" name="window_minutes" value="{{ rule['window_minutes'] }}" min="1" max="1440">
      </div>
      <div class="form-group" style="margin:0;">
        <label>Enabled</label>
        <select name="enabled">
          <option value="1" {% if rule['enabled'] %}selected{% endif %}>Yes</option>
          <option value="0" {% if not rule['enabled'] %}selected{% endif %}>No</option>
        </select>
      </div>
    </div>
    <button type="submit" class="btn btn-primary btn-sm">Save</button>
  </form>
</div>
{% endfor %}

<div class="detail-card" style="margin-top:24px;">
  <h3>Demo Data Controls</h3>
  <p style="font-size:13px;color:var(--muted);margin-bottom:14px;">
    Use these tools to reset or re-run the detection engine for demo purposes.
  </p>
  <div style="display:flex;gap:10px;flex-wrap:wrap;">
    <form method="post" action="{{ url_for('run_detection_manual') }}">
      <button type="submit" class="btn btn-primary">
        <i data-lucide="zap" style="width:13px;height:13px;"></i> Run Detection Engine Now
      </button>
    </form>
    <form method="post" action="{{ url_for('reset_demo') }}" onsubmit="return confirm('Delete ALL events, alerts, and incidents?')">
      <button type="submit" class="btn btn-danger">
        <i data-lucide="trash-2" style="width:13px;height:13px;"></i> Reset All Demo Data
      </button>
    </form>
  </div>
</div>
</div>
{% endblock %}""")


@app.route("/settings", methods=["GET"])
def settings():
    db = get_db()
    rules = db.execute("SELECT * FROM detection_rules ORDER BY id").fetchall()
    return render_template_string(SETTINGS_TMPL,
        page_title="Settings", active="settings",
        rules=[dict(r) for r in rules],
    )


@app.route("/settings/update", methods=["POST"])
def settings_update():
    rule_id      = request.form.get("rule_id")
    threshold    = request.form.get("threshold")
    window       = request.form.get("window_minutes")
    enabled      = request.form.get("enabled","1")
    try:
        rule_id   = int(rule_id)
        threshold = max(1, min(int(threshold), 1000))
        window    = max(1, min(int(window), 1440))
        enabled   = 1 if enabled == "1" else 0
    except (ValueError, TypeError):
        flash("Invalid values.", "error")
        return redirect(url_for("settings"))
    db = get_db()
    if not db.execute("SELECT id FROM detection_rules WHERE id=?", (rule_id,)).fetchone():
        abort(404)
    db.execute("UPDATE detection_rules SET threshold=?,window_minutes=?,enabled=? WHERE id=?",
               (threshold, window, enabled, rule_id))
    db.commit()
    flash("Rule updated.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/run-detection", methods=["POST"])
def run_detection_manual():
    db = get_db()
    n = run_detection(db)
    flash(f"Detection engine ran — {n} new alert(s) created.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/reset-demo", methods=["POST"])
def reset_demo():
    with raw_db() as db:
        db.executescript("""
            DELETE FROM incident_notes;
            DELETE FROM incident_alerts;
            DELETE FROM incidents;
            DELETE FROM alerts;
            DELETE FROM security_events;
            DELETE FROM ingestion_batches;
        """)
    seed_demo_data()
    flash("Demo data has been reset and re-seeded.", "success")
    return redirect(url_for("dashboard"))

# ══════════════════════════════════════════════════════════════════
#  ROUTE: ABOUT
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
#  ROUTE: LOGIN / LOGOUT
# ══════════════════════════════════════════════════════════════════

LOGIN_TMPL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelSOC — Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Inter',sans-serif;background:#0d1117;color:#e6edf3;
     min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
.login-card{
  background:#161b22;border:1px solid #30363d;border-radius:14px;
  padding:40px 36px;width:100%;max-width:400px;
  box-shadow:0 20px 60px rgba(0,0,0,.5);
}
.login-logo{
  display:flex;align-items:center;gap:12px;justify-content:center;margin-bottom:28px;
}
.logo-icon{
  width:44px;height:44px;background:linear-gradient(135deg,#1f6feb,#388bfd);
  border-radius:10px;display:flex;align-items:center;justify-content:center;
}
.brand-name{font-size:22px;font-weight:800;color:#e6edf3;}
.brand-tag{font-size:11px;color:#8b949e;letter-spacing:.1em;text-transform:uppercase;margin-top:2px;}
h2{font-size:17px;font-weight:600;color:#e6edf3;text-align:center;margin-bottom:6px;}
.subtitle{font-size:13px;color:#8b949e;text-align:center;margin-bottom:24px;}
label{display:block;font-size:12px;font-weight:500;color:#8b949e;margin-bottom:6px;}
.form-group{margin-bottom:16px;position:relative;}
input[type=text],input[type=password]{
  width:100%;padding:10px 14px;background:#21262d;border:1px solid #30363d;
  border-radius:8px;color:#e6edf3;font-size:14px;font-family:inherit;
  transition:border-color .15s;
}
input:focus{outline:none;border-color:#58a6ff;box-shadow:0 0 0 3px rgba(88,166,255,.12);}
.btn-login{
  width:100%;padding:11px;background:#388bfd;border:none;border-radius:8px;
  color:#fff;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;
  transition:background .15s;margin-top:4px;
}
.btn-login:hover{background:#58a6ff;}
.flash-err{
  background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);color:#f85149;
  border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:16px;
}
.flash-warn{
  background:rgba(227,179,65,.1);border:1px solid rgba(227,179,65,.3);color:#e3b341;
  border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:16px;
}
.demo-creds{
  background:#0d1117;border:1px solid #30363d;border-radius:8px;
  padding:14px 16px;margin-top:20px;font-size:12px;
}
.demo-creds h4{font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;
               letter-spacing:.07em;margin-bottom:10px;}
.cred-row{display:flex;justify-content:space-between;padding:5px 0;
          border-bottom:1px solid #21262d;align-items:center;}
.cred-row:last-child{border-bottom:none;}
.cred-user{font-weight:600;color:#79c0ff;font-family:'Courier New',monospace;}
.cred-pass{color:#e6edf3;font-family:'Courier New',monospace;}
.cred-role{font-size:10px;color:#8b949e;text-transform:uppercase;}
.warning-note{font-size:11px;color:#8b949e;text-align:center;margin-top:14px;line-height:1.6;}
</style>
</head>
<body>
<div class="login-card">
  <div class="login-logo">
    <div class="logo-icon">
      <i data-lucide="shield-check" style="width:22px;height:22px;color:#fff;"></i>
    </div>
    <div>
      <div class="brand-name">SentinelSOC</div>
      <div class="brand-tag">Detect · Investigate · Defend</div>
    </div>
  </div>

  <h2>Sign in to your account</h2>
  <p class="subtitle">Enter your credentials to access the dashboard</p>

  {% for msg in error_msgs %}<div class="flash-err">{{ msg }}</div>{% endfor %}
  {% for msg in warn_msgs %}<div class="flash-warn">{{ msg }}</div>{% endfor %}

  <form method="post" action="/login">
    <input type="hidden" name="next" value="{{ next_url }}">
    <div class="form-group">
      <label>Username</label>
      <input type="text" name="username" autocomplete="username"
             value="{{ last_username }}" required placeholder="Enter username">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password"
             required placeholder="Enter password">
    </div>
    <button type="submit" class="btn-login">
      Sign In →
    </button>
  </form>

  <div class="demo-creds">
    <h4>Demo Accounts</h4>
    <div class="cred-row">
      <span class="cred-user">admin</span>
      <span class="cred-pass">Admin@1234</span>
      <span class="cred-role">Admin</span>
    </div>
    <div class="cred-row">
      <span class="cred-user">analyst</span>
      <span class="cred-pass">Analyst@1234</span>
      <span class="cred-role">Analyst</span>
    </div>
    <div class="cred-row">
      <span class="cred-user">viewer</span>
      <span class="cred-pass">Viewer@1234</span>
      <span class="cred-role">Viewer</span>
    </div>
  </div>

  <p class="warning-note">
    ⚠ This is a local educational prototype.<br>
    Do not use real credentials. For demo purposes only.
  </p>
</div>
<script>lucide.createIcons();</script>
</body>
</html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error_msgs = []
    warn_msgs  = []
    # collect flashed warnings (from before_request redirects)
    for cat, msg in get_flashed_messages(with_categories=True):
        if cat == "warning":
            warn_msgs.append(msg)
        else:
            error_msgs.append(msg)

    next_url = request.args.get("next") or request.form.get("next") or "/"

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = DEMO_USERS.get(username)
        if user and user["password"] == password:
            session.clear()
            session["username"] = username
            session.permanent = True
            # safe redirect — only allow relative paths
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = "/"
            return redirect(next_url)
        error_msgs.append("Invalid username or password. Please try again.")

    last_username = request.form.get("username", "") if request.method == "POST" else ""
    return render_template_string(LOGIN_TMPL,
        error_msgs=error_msgs, warn_msgs=warn_msgs,
        next_url=next_url, last_username=last_username,
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ══════════════════════════════════════════════════════════════════
#  ROUTE: ABOUT WEBSITE  (replaces "About Project")
# ══════════════════════════════════════════════════════════════════

ABOUT_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header"><h1>About SentinelSOC</h1></div>
<div style="max-width:760px;">

<div class="detail-card" style="margin-bottom:16px;border-left:3px solid var(--accent);">
  <h3>What is SentinelSOC?</h3>
  <p style="color:var(--text);line-height:1.8;margin-bottom:8px;">
    <strong>SentinelSOC</strong> is a web-based <strong>Mini Security Operations Center</strong> platform.
    It helps security analysts monitor authentication events, automatically detect suspicious patterns,
    manage security alerts, and track incident investigations — all from a single dashboard.
  </p>
  <p style="color:var(--muted);font-size:13px;">
    Built with Python · Flask · SQLite · Chart.js &nbsp;|&nbsp; Version 1.0 &nbsp;|&nbsp; IBM Cybersecurity Bootcamp
  </p>
</div>

<div class="detail-card" style="margin-bottom:16px;">
  <h3>Website Features</h3>
  <table>
    <thead><tr><th>Section</th><th>What You Can Do</th></tr></thead>
    <tbody>
      <tr><td><strong>Overview</strong></td><td>View live event counts, trend charts, recent alerts and events</td></tr>
      <tr><td><strong>Security Events</strong></td><td>Browse, search, filter, and export all ingested log events</td></tr>
      <tr><td><strong>Alerts</strong></td><td>Review auto-generated alerts, read evidence, update investigation status</td></tr>
      <tr><td><strong>Incidents</strong></td><td>Create incidents, link alerts, write notes, track resolution</td></tr>
      <tr><td><strong>Log Ingestion</strong></td><td>Upload CSV or JSON Lines log files for automatic analysis</td></tr>
      <tr><td><strong>Detection Rules</strong></td><td>View the 5 active detection rules and their trigger counts</td></tr>
      <tr><td><strong>Reports</strong></td><td>Generate security summaries and export CSV reports</td></tr>
      <tr><td><strong>Settings</strong></td><td>Tune detection thresholds, re-run the engine, reset demo data</td></tr>
    </tbody>
  </table>
</div>

<div class="detail-card" style="margin-bottom:16px;">
  <h3>User Accounts</h3>
  <table>
    <thead><tr><th>Role</th><th>Access Level</th><th>Default Username</th></tr></thead>
    <tbody>
      <tr>
        <td><span class="badge-sev badge-high">Admin</span></td>
        <td>Full access — manage settings, reset data, configure rules</td>
        <td style="font-family:'JetBrains Mono',monospace;">admin</td>
      </tr>
      <tr>
        <td><span class="badge-sev badge-medium">Analyst</span></td>
        <td>Standard analyst access — investigate alerts, manage incidents</td>
        <td style="font-family:'JetBrains Mono',monospace;">analyst</td>
      </tr>
      <tr>
        <td><span class="badge-sev badge-low">Viewer</span></td>
        <td>Read-only access — view dashboard, events, alerts, reports</td>
        <td style="font-family:'JetBrains Mono',monospace;">viewer</td>
      </tr>
    </tbody>
  </table>
</div>

<div class="detail-card" style="margin-bottom:16px;">
  <h3>Technology Stack</h3>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
    {% for item in tech %}
    <div class="detail-row"><span class="detail-key">{{ item[0] }}</span><span class="detail-val">{{ item[1] }}</span></div>
    {% endfor %}
  </div>
</div>

<div class="detail-card" style="border-left:3px solid var(--yellow);">
  <h3>Important Notices</h3>
  <ul style="color:var(--muted);font-size:13px;line-height:2;padding-left:18px;">
    <li>All displayed data is <strong>synthetic demo data</strong> — no real credentials or logs are used.</li>
    <li>This platform is an <strong>educational prototype</strong> for the IBM Cybersecurity Bootcamp.</li>
    <li>Detections flag <strong>suspicious behaviour</strong> — they do not confirm a real attack.</li>
    <li>Never automatically block IPs or lock accounts based solely on these alerts.</li>
    <li>Deploy only on a trusted local machine — no public exposure without proper hardening.</li>
  </ul>
</div>
</div>
{% endblock %}""")


@app.route("/about")
def about():
    tech = [
        ("Backend", "Python 3.14 + Flask 3.1"),
        ("Database", "SQLite (WAL mode)"),
        ("Frontend", "HTML5 / CSS3 / JavaScript"),
        ("Charts", "Chart.js 4"),
        ("Icons", "Lucide Icons"),
        ("Testing", "pytest 8"),
        ("Auth", "Session-based (demo)"),
    ]
    return render_template_string(ABOUT_TMPL,
        page_title="About Website", active="about",
        tech=tech,
    )


# ══════════════════════════════════════════════════════════════════
#  ROUTE: HOW TO USE
# ══════════════════════════════════════════════════════════════════

HOW_TO_USE_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header"><h1>How to Use SentinelSOC</h1></div>
<div style="max-width:780px;">

<div class="detail-card" style="margin-bottom:16px;border-left:3px solid var(--accent);">
  <h3>Getting Started</h3>
  <p style="color:var(--text);line-height:1.8;">
    SentinelSOC comes pre-loaded with <strong>synthetic demo data</strong> so you can explore every feature
    immediately after logging in. Follow the steps below to get the most out of the platform.
  </p>
</div>

<!-- Step by step -->
<div class="detail-card" style="margin-bottom:16px;">
  <h3>Step-by-Step Workflow</h3>

  <div style="margin-top:4px;">
  {% set steps = [
    ("1","View the Overview Dashboard",
     "Go to <strong>Overview</strong> in the sidebar. You will see total event counts, active alerts,
      open incidents, and chart visualisations of security activity over time. Use the Period filter
      (top right) to switch between 24 hours, 7 days, and 30 days."),
    ("2","Explore Security Events",
     "Click <strong>Security Events</strong>. Use the search box to filter by IP address, username,
      or description. Use the <em>Result</em> dropdown to show only failures or lockouts.
      Click <strong>Export CSV</strong> to download the filtered results."),
    ("3","Investigate an Alert",
     "Click <strong>Alerts</strong>. Each alert shows the detection rule that fired, severity level,
      affected IP/user, and a plain-language explanation. Click <strong>View</strong> on any alert
      to read the full evidence. Update the status to <em>Acknowledged</em> or <em>Investigating</em>
      as you review it."),
    ("4","Create and Manage Incidents",
     "On the alert detail page, click <strong>Create Incident from Alert</strong> to automatically
      open a new incident linked to that alert. Or go to <strong>Incidents → New Incident</strong>
      to create one manually. Add investigation notes, link additional alerts, assign the incident
      to an analyst, and update the status as the investigation progresses."),
    ("5","Upload Your Own Log File",
     "Go to <strong>Log Ingestion</strong>. Drag and drop (or browse for) a CSV or JSON Lines file.
      Click <strong>Process &amp; Ingest</strong>. The system will validate the file, insert valid
      events, run all detection rules automatically, and show you a summary of accepted/rejected
      records and new alerts generated."),
    ("6","Review Detection Rules",
     "Go to <strong>Detection Rules</strong> to read what each of the 5 rules detects, its
      threshold, time window, and how many alerts it has produced. Rules can be tuned in Settings."),
    ("7","Generate a Report",
     "Click <strong>Reports</strong>. Select a reporting period. View aggregated metrics, top
      triggered rules, top source IPs, and failed-login trends. Click <strong>Print Report</strong>
      for a printable summary, or use the export buttons for CSV files."),
    ("8","Tune Settings",
     "Go to <strong>Settings</strong> to adjust each rule&rsquo;s threshold and time window.
      You can also manually trigger the detection engine or reset all demo data to start fresh."),
  ] %}
  {% for num, title, desc in steps %}
  <div style="display:flex;gap:14px;margin-bottom:18px;padding-bottom:18px;
              border-bottom:1px solid var(--border);">
    <div style="width:30px;height:30px;border-radius:50%;background:var(--accent2);
                color:#fff;display:flex;align-items:center;justify-content:center;
                font-size:13px;font-weight:700;flex-shrink:0;margin-top:1px;">{{ num }}</div>
    <div>
      <div style="font-size:14px;font-weight:600;color:var(--text);margin-bottom:4px;">{{ title }}</div>
      <div style="font-size:13px;color:var(--muted);line-height:1.7;">{{ desc|safe }}</div>
    </div>
  </div>
  {% endfor %}
  </div>
</div>

<!-- Log file formats -->
<div class="detail-card" style="margin-bottom:16px;">
  <h3>Supported Log File Formats</h3>
  <p style="color:var(--muted);font-size:13px;margin-bottom:12px;">
    The ingestion page accepts two file formats. Both must be UTF-8 encoded and under 5 MB.
  </p>
  <div style="margin-bottom:14px;">
    <div style="font-size:12px;font-weight:600;color:var(--accent);margin-bottom:6px;">CSV FORMAT</div>
    <div class="evidence-box">timestamp,event_type,source_ip,username,auth_result,description
2024-06-01T08:00:00,authentication,192.168.1.10,alice,success,Successful login
2024-06-01T08:01:00,authentication,198.51.100.5,alice,failure,Wrong password
2024-06-01T08:02:00,authentication,198.51.100.5,alice,lockout,Account locked</div>
    <p style="font-size:11px;color:var(--muted);margin-top:6px;">
      Required columns: <code>timestamp</code>, <code>event_type</code> &nbsp;|&nbsp;
      Optional: <code>source_ip</code>, <code>username</code>, <code>auth_result</code>, <code>description</code>
    </p>
  </div>
  <div>
    <div style="font-size:12px;font-weight:600;color:var(--accent);margin-bottom:6px;">JSON LINES FORMAT</div>
    <div class="evidence-box">{"timestamp":"2024-06-01T08:00:00","event_type":"authentication","source_ip":"192.168.1.10","username":"alice","auth_result":"success"}
{"timestamp":"2024-06-01T08:01:00","event_type":"authentication","source_ip":"198.51.100.5","username":"alice","auth_result":"failure"}</div>
    <p style="font-size:11px;color:var(--muted);margin-top:6px;">One JSON object per line. Keys are case-insensitive.</p>
  </div>
</div>

<!-- Alert statuses -->
<div class="detail-card" style="margin-bottom:16px;">
  <h3>Alert Statuses Explained</h3>
  <table>
    <thead><tr><th>Status</th><th>When to Use</th></tr></thead>
    <tbody>
      <tr><td><span class="badge-status st-new">New</span></td><td>Alert just generated — not yet reviewed</td></tr>
      <tr><td><span class="badge-status st-acknowledged">Acknowledged</span></td><td>Alert seen by an analyst — under initial review</td></tr>
      <tr><td><span class="badge-status st-investigating">Investigating</span></td><td>Active investigation underway</td></tr>
      <tr><td><span class="badge-status st-resolved">Resolved</span></td><td>Root cause identified and addressed</td></tr>
      <tr><td><span class="badge-status st-false_positive">False Positive</span></td><td>Alert was triggered by benign activity</td></tr>
    </tbody>
  </table>
</div>

<!-- Tips -->
<div class="detail-card" style="border-left:3px solid var(--green);">
  <h3>Tips &amp; Best Practices</h3>
  <ul style="color:var(--muted);font-size:13px;line-height:2;padding-left:18px;">
    <li>Always <strong>read the evidence</strong> on an alert before changing its status.</li>
    <li>Use <strong>incident notes</strong> to record your investigation steps — they create an audit trail.</li>
    <li>Link all related alerts to a single incident to keep investigations organised.</li>
    <li>Use the <strong>Reports</strong> page at the end of a shift to summarise activity.</li>
    <li>Reset demo data in Settings whenever you want a clean slate for a new demonstration.</li>
    <li>Detections are indicators — always verify before taking action.</li>
  </ul>
</div>

</div>
{% endblock %}""")


@app.route("/how-to-use")
def how_to_use():
    return render_template_string(HOW_TO_USE_TMPL,
        page_title="How to Use", active="how_to_use")


# ══════════════════════════════════════════════════════════════════
#  ROUTE: CUSTOMER CARE
# ══════════════════════════════════════════════════════════════════

CUSTOMER_CARE_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="page-header"><h1>Customer Care &amp; Support</h1></div>
<div style="max-width:760px;">

<div class="detail-card" style="margin-bottom:16px;border-left:3px solid var(--accent);">
  <h3>We're Here to Help</h3>
  <p style="color:var(--text);line-height:1.8;">
    SentinelSOC is an educational prototype. If you have questions, encounter a bug, or need help
    understanding a feature, use the resources below.
  </p>
</div>

<!-- Contact cards -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">

<div class="detail-card" style="text-align:center;padding:28px 20px;">
  <div style="font-size:32px;margin-bottom:10px;">📧</div>
  <div style="font-size:14px;font-weight:600;color:var(--text);margin-bottom:6px;">Email Support</div>
  <div style="font-size:13px;color:var(--muted);margin-bottom:12px;">
    Send us a detailed description of your issue and we will respond within 24 hours.
  </div>
  <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent);">
    support@sentinelsoc.local
  </div>
  <div style="font-size:11px;color:var(--muted);margin-top:6px;">
    (Demo address — for illustration only)
  </div>
</div>

<div class="detail-card" style="text-align:center;padding:28px 20px;">
  <div style="font-size:32px;margin-bottom:10px;">💬</div>
  <div style="font-size:14px;font-weight:600;color:var(--text);margin-bottom:6px;">Live Chat</div>
  <div style="font-size:13px;color:var(--muted);margin-bottom:12px;">
    Available Monday – Friday, 09:00 – 18:00 UTC. Average response time: under 5 minutes.
  </div>
  <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent);">
    chat.sentinelsoc.local
  </div>
  <div style="font-size:11px;color:var(--muted);margin-top:6px;">
    (Demo address — for illustration only)
  </div>
</div>

<div class="detail-card" style="text-align:center;padding:28px 20px;">
  <div style="font-size:32px;margin-bottom:10px;">📞</div>
  <div style="font-size:14px;font-weight:600;color:var(--text);margin-bottom:6px;">Phone Support</div>
  <div style="font-size:13px;color:var(--muted);margin-bottom:12px;">
    For urgent issues call our SOC help desk during business hours.
  </div>
  <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent);">
    +1 (800) 555-SOC1
  </div>
  <div style="font-size:11px;color:var(--muted);margin-top:6px;">
    (Demo number — for illustration only)
  </div>
</div>

<div class="detail-card" style="text-align:center;padding:28px 20px;">
  <div style="font-size:32px;margin-bottom:10px;">📖</div>
  <div style="font-size:14px;font-weight:600;color:var(--text);margin-bottom:6px;">Documentation</div>
  <div style="font-size:13px;color:var(--muted);margin-bottom:12px;">
    Step-by-step guides, log format references, and detection rule explanations.
  </div>
  <a href="{{ url_for('how_to_use') }}" class="btn btn-sm btn-primary" style="margin-top:4px;">
    Open User Guide
  </a>
</div>

</div>

<!-- FAQ -->
<div class="detail-card" style="margin-bottom:16px;">
  <h3>Frequently Asked Questions</h3>
  {% set faqs = [
    ("Why am I not seeing any alerts?",
     "Make sure you have ingested some log data first (Log Ingestion page). After uploading a file,
      the detection engine runs automatically. If you uploaded the demo seed data, click
      Settings → Run Detection Engine Now to trigger detection on existing events."),
    ("How do I add more users?",
     "This demo version uses three built-in accounts (admin, analyst, viewer). In a production
      deployment you would store users in the database with hashed passwords.
      See the README for details."),
    ("Can I upload real log files?",
     "Technically yes, but this is an educational prototype. Do not upload files containing
      real usernames, passwords, or sensitive IP addresses. Use anonymised or synthetic data only."),
    ("The detection engine generated an alert — does that mean I was attacked?",
     "No. Alerts indicate suspicious patterns that require investigation. A brute-force alert
      could simply be a user who forgot their password. Always verify before taking any action."),
    ("How do I reset everything and start fresh?",
     "Go to Settings and click Reset All Demo Data. This will delete all events, alerts,
      and incidents and re-seed the database with fresh synthetic data."),
    ("I found a bug — how do I report it?",
     "Open an issue on the project repository, or email support@sentinelsoc.local with steps
      to reproduce the problem."),
  ] %}
  {% for q, a in faqs %}
  <details style="border-bottom:1px solid var(--border);padding:14px 0;">
    <summary style="cursor:pointer;font-size:13px;font-weight:600;color:var(--text);
                    list-style:none;display:flex;justify-content:space-between;align-items:center;">
      {{ q }}
      <span style="color:var(--accent);font-size:16px;margin-left:10px;flex-shrink:0;">+</span>
    </summary>
    <p style="font-size:13px;color:var(--muted);line-height:1.75;margin-top:10px;
              padding-left:4px;">{{ a|safe }}</p>
  </details>
  {% endfor %}
</div>

<!-- Send message form -->
<div class="detail-card" style="margin-bottom:16px;">
  <h3>Send Us a Message</h3>
  <p style="font-size:13px;color:var(--muted);margin-bottom:16px;">
    Fill in the form below and we will get back to you as soon as possible.
  </p>
  <form method="post" action="{{ url_for('customer_care') }}">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
      <div class="form-group">
        <label>Your Name</label>
        <input type="text" name="care_name" placeholder="Full name" maxlength="100">
      </div>
      <div class="form-group">
        <label>Email Address</label>
        <input type="text" name="care_email" placeholder="you@example.com" maxlength="200">
      </div>
    </div>
    <div class="form-group">
      <label>Topic</label>
      <select name="care_topic">
        <option value="general">General Question</option>
        <option value="bug">Bug Report</option>
        <option value="feature">Feature Request</option>
        <option value="account">Account / Login Issue</option>
        <option value="other">Other</option>
      </select>
    </div>
    <div class="form-group">
      <label>Message</label>
      <textarea name="care_message" rows="4" placeholder="Describe your question or issue…" maxlength="2000"></textarea>
    </div>
    <button type="submit" class="btn btn-primary">
      <i data-lucide="send" style="width:13px;height:13px;"></i> Send Message
    </button>
  </form>
</div>

<div class="detail-card" style="border-left:3px solid var(--yellow);">
  <h3>Responsible Use Reminder</h3>
  <p style="color:var(--muted);font-size:13px;line-height:1.8;">
    SentinelSOC is for <strong>educational and demonstration purposes only</strong>.
    It must not be used to monitor real users without their knowledge, process real authentication
    credentials, or take automated remediation actions. Always follow your organisation's security
    policies and applicable laws.
  </p>
</div>

</div>
{% endblock %}""")


@app.route("/customer-care", methods=["GET", "POST"])
def customer_care():
    if request.method == "POST":
        name    = request.form.get("care_name","").strip()[:100]
        email   = request.form.get("care_email","").strip()[:200]
        topic   = request.form.get("care_topic","general")
        message = request.form.get("care_message","").strip()[:2000]
        if not message:
            flash("Please enter a message before submitting.", "error")
        else:
            # In a real app this would send an email or create a ticket.
            # Here we simply acknowledge receipt.
            flash(f"Thank you{', ' + name if name else ''}! Your message has been received. "
                  f"We will respond to {email if email else 'you'} shortly.", "success")
        return redirect(url_for("customer_care"))
    return render_template_string(CUSTOMER_CARE_TMPL,
        page_title="Customer Care", active="customer_care")

# ══════════════════════════════════════════════════════════════════
#  API ENDPOINTS (used by JS / AJAX)
# ══════════════════════════════════════════════════════════════════

@app.route("/api/stats")
def api_stats():
    db = get_db()
    return jsonify({
        "total_events":   db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0],
        "total_alerts":   db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "new_alerts":     db.execute("SELECT COUNT(*) FROM alerts WHERE status='new'").fetchone()[0],
        "open_incidents": db.execute("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')").fetchone()[0],
    })

# ══════════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ══════════════════════════════════════════════════════════════════

ERR_TMPL = BASE.replace("{% block content %}{% endblock %}", """{% block content %}
<div class="empty-state" style="padding:80px 20px;">
  <div class="empty-icon">⚠</div>
  <h3>{{ code }} — {{ message }}</h3>
  <p style="margin-top:10px;"><a href="{{ url_for('dashboard') }}" class="table-link">Return to Dashboard</a></p>
</div>
{% endblock %}""")


@app.errorhandler(404)
def err_404(e):
    return render_template_string(ERR_TMPL, page_title="404 Not Found",
                                  active="", code=404, message="Page Not Found"), 404


@app.errorhandler(413)
def err_413(e):
    return render_template_string(ERR_TMPL, page_title="File Too Large",
                                  active="", code=413, message="Uploaded file is too large (max 5 MB)"), 413


@app.errorhandler(500)
def err_500(e):
    log.exception("Internal server error")
    return render_template_string(ERR_TMPL, page_title="500 Error",
                                  active="", code=500, message="Internal Server Error"), 500

# ══════════════════════════════════════════════════════════════════
#  SECURITY HEADERS
# ══════════════════════════════════════════════════════════════════

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    return response

# ══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  SentinelSOC — Mini Security Operations Center")
    print("  Detect. Investigate. Defend.")
    print("=" * 60)
    print(f"  Database : {DATABASE}")
    print(f"  URL      : http://127.0.0.1:5000")
    print(f"  Debug    : {DEBUG}")
    print("  ⚠  DEMO DATA — For educational purposes only")
    print("=" * 60)

    init_db()
    seed_demo_data()
    app.run(debug=DEBUG, host="127.0.0.1", port=5000)
