"""
Database management module for AIORI-3 PS-011.
Manages SQLite schemas, parameterised queries, connection handling, and initial seeding.
"""

import sqlite3
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from config import (
    DATABASE_PATH, MAX_APPROVED_DOMAINS, MAX_APPROVED_HOSTS,
    DEFAULT_APPROVED_PORTS, DEFAULT_BASELINE_SERVICES
)


def get_db_connection():
    """Returns a SQLite connection with row factory and foreign keys enabled."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Initializes all required database tables with proper constraints."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Assets Table (Approved Domains & Hosts)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL CHECK(asset_type IN ('domain', 'host')),
            value TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            is_approved INTEGER DEFAULT 1,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # 2. Scan Runs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL CHECK(scan_type IN ('live', 'simulated')),
            status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')),
            start_time TEXT NOT NULL,
            end_time TEXT,
            domains_scanned INTEGER DEFAULT 0,
            hosts_scanned INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            changes_count INTEGER DEFAULT 0,
            notes TEXT
        )
    """)

    # 3. DNS Observations Table (Check 1)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL,
            asset_id INTEGER,
            domain TEXT NOT NULL,
            record_type TEXT NOT NULL,
            record_value TEXT NOT NULL,
            ttl INTEGER DEFAULT 300,
            is_dangling_candidate INTEGER DEFAULT 0,
            dangling_provider TEXT,
            dangling_reason TEXT,
            observed_at TEXT NOT NULL,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs (id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE SET NULL
        )
    """)

    # 4. TLS Observations Table (Check 2)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tls_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL,
            asset_id INTEGER,
            domain TEXT NOT NULL,
            port INTEGER DEFAULT 443,
            is_valid INTEGER DEFAULT 0,
            is_expired INTEGER DEFAULT 0,
            days_to_expiry INTEGER,
            not_before TEXT,
            not_after TEXT,
            issuer TEXT,
            subject TEXT,
            sans TEXT,
            signature_algo TEXT,
            serial_number TEXT,
            tls_version TEXT,
            cipher_suite TEXT,
            error_message TEXT,
            observed_at TEXT NOT NULL,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs (id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE SET NULL
        )
    """)

    # 5. Port Observations Table (Check 3)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL,
            asset_id INTEGER,
            host_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'TCP',
            state TEXT NOT NULL CHECK(state IN ('OPEN', 'CLOSED', 'FILTERED')),
            latency_ms REAL,
            service_name TEXT,
            banner TEXT,
            is_http INTEGER DEFAULT 0,
            http_status INTEGER,
            http_title TEXT,
            server_header TEXT,
            tech_stack TEXT,
            security_headers TEXT,
            is_unexpected INTEGER DEFAULT 0,
            observed_at TEXT NOT NULL,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs (id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE SET NULL
        )
    """)

    # 6. Baseline Snapshots Table (Check 4)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS baseline_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_name TEXT NOT NULL,
            scan_run_id INTEGER NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs (id) ON DELETE CASCADE
        )
    """)

    # 7. Change Events Table (Check 4 Deltas)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS change_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL,
            baseline_id INTEGER,
            asset_id INTEGER,
            change_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT,
            detected_at TEXT NOT NULL,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs (id) ON DELETE CASCADE,
            FOREIGN KEY (baseline_id) REFERENCES baseline_snapshots (id) ON DELETE SET NULL,
            FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE SET NULL
        )
    """)

    # 8. Security Findings Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL,
            change_event_id INTEGER,
            asset_id INTEGER,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT,
            defensive_action TEXT,
            status TEXT DEFAULT 'OPEN' CHECK(status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')),
            confidence TEXT DEFAULT 'HIGH',
            false_positive_risk TEXT DEFAULT 'LOW',
            false_positive_reason TEXT,
            review_notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs (id) ON DELETE CASCADE,
            FOREIGN KEY (change_event_id) REFERENCES change_events (id) ON DELETE SET NULL,
            FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE SET NULL
        )
    """)

    # 9. Settings Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Initialize default settings if not existing
    now = datetime.now(timezone.utc).isoformat()
    default_settings = [
        ("scan_interval_minutes", "60"),
        ("auto_monitoring_enabled", "0"),
        ("socket_timeout_seconds", "3.0"),
        ("allowed_ports", ",".join(map(str, DEFAULT_APPROVED_PORTS))),
        ("max_domains", str(MAX_APPROVED_DOMAINS)),
        ("max_hosts", str(MAX_APPROVED_HOSTS)),
        ("organization_name", "AIORI-3 Cyber Lab Infrastructure")
    ]
    for key, val in default_settings:
        cursor.execute("INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", (key, val, now))

    conn.commit()
    conn.close()


def seed_initial_lab_data():
    """
    Seeds the initial 20 approved domains and 10 hosts as specified in PS-011.
    If assets are already present, skips duplication.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM assets")
    if cursor.fetchone()[0] > 0:
        conn.close()
        return  # Already seeded

    now = datetime.now(timezone.utc).isoformat()

    # The 20 Approved Lab Domains (bounded scope)
    initial_domains = [
        ("Lab Main Portal", "lab-portal.aiori.internal", "10.0.1.10"),
        ("API Gateway", "api.lab-portal.aiori.internal", "10.0.1.10"),
        ("Authentication Server", "auth.lab-portal.aiori.internal", "10.0.1.11"),
        ("Staging API", "staging-api.aiori.internal", "10.0.1.12"),
        ("Edge CDN Distribution", "test-cdn.aiori.internal", "10.0.1.10"),
        ("Legacy Internal App", "legacy-app.aiori.internal", "10.0.2.20"),
        ("Developer Documentation", "docs.aiori.internal", "10.0.1.10"),
        ("Remote Access VPN", "vpn.aiori.internal", "10.0.1.11"),
        ("Metrics Exporter", "metrics.aiori.internal", "10.0.2.25"),
        ("System Status Page", "status.aiori.internal", "10.0.1.10"),
        ("Cloud Asset Mirror", "cloud-assets.aiori.internal", "10.0.3.30"),
        ("Developer Sandbox", "dev-sandbox.aiori.internal", "10.0.1.15"),
        ("Orphaned Storage Bucket", "orphaned-bucket.aiori.internal", None),
        ("Expired TLS Test Service", "expired-tls.aiori.internal", "10.0.3.35"),
        ("Engineering Blog", "blog.aiori.internal", None),
        ("Corporate Webmail", "mail.aiori.internal", "10.0.1.11"),
        ("Internal Git Repository", "git.aiori.internal", "10.0.2.25"),
        ("CI/CD Build Pipeline", "ci-cd.aiori.internal", "10.0.4.50"),
        ("Security Monitoring", "monitoring.aiori.internal", "10.0.2.25"),
        ("External Security Gateway", "external-gateway.aiori.internal", "10.0.4.50")
    ]

    for name, domain, ip in initial_domains:
        cursor.execute("""
            INSERT INTO assets (name, asset_type, value, ip_address, is_approved, notes, created_at, updated_at)
            VALUES (?, 'domain', ?, ?, 1, 'Pre-configured approved lab domain', ?, ?)
        """, (name, domain, ip, now, now))

    # The 10 Approved Lab Hosts (bounded scope)
    initial_hosts = [
        ("Localhost Test Environment", "127.0.0.1", "127.0.0.1"),
        ("Core Application Server", "10.0.1.10", "10.0.1.10"),
        ("Authentication & SSH Gateway", "10.0.1.11", "10.0.1.11"),
        ("Staging Container Node", "10.0.1.12", "10.0.1.12"),
        ("Sandbox Dev Node", "10.0.1.15", "10.0.1.15"),
        ("Legacy Web Host", "10.0.2.20", "10.0.2.20"),
        ("Monitoring & Metrics Node", "10.0.2.25", "10.0.2.25"),
        ("Static Media Host", "10.0.3.30", "10.0.3.30"),
        ("TLS Test Endpoint", "10.0.3.35", "10.0.3.35"),
        ("CI/CD Pipeline Runner", "10.0.4.50", "10.0.4.50")
    ]

    for name, host, ip in initial_hosts:
        cursor.execute("""
            INSERT INTO assets (name, asset_type, value, ip_address, is_approved, notes, created_at, updated_at)
            VALUES (?, 'host', ?, ?, 1, 'Pre-configured approved lab host', ?, ?)
        """, (name, host, ip, now, now))

    conn.commit()

    # Pre-populate golden baseline snapshot so the system has an established baseline on day 1
    _seed_initial_golden_baseline(cursor, now)
    conn.commit()
    conn.close()


def _seed_initial_golden_baseline(cursor, now_str):
    """Creates initial scan run and golden baseline snapshot."""
    cursor.execute("""
        INSERT INTO scan_runs (scan_type, status, start_time, end_time, domains_scanned, hosts_scanned, findings_count, changes_count, notes)
        VALUES ('simulated', 'completed', ?, ?, 20, 10, 0, 0, 'Initial Golden Baseline Scan')
    """, (now_str, now_str))
    scan_run_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO baseline_snapshots (snapshot_name, scan_run_id, is_active, created_at, notes)
        VALUES ('Baseline-Golden-Standard-v1', ?, 1, ?, 'Authorised initial baseline inventory')
    """, (scan_run_id, now_str))
    baseline_id = cursor.lastrowid

    # Retrieve assets to attach baseline observations
    cursor.execute("SELECT id, asset_type, value FROM assets")
    all_assets = cursor.fetchall()

    for a in all_assets:
        a_id = a["id"]
        a_type = a["asset_type"]
        val = a["value"]

        if a_type == "domain":
            cursor.execute("""
                INSERT INTO dns_observations (scan_run_id, asset_id, domain, record_type, record_value, ttl, observed_at)
                VALUES (?, ?, ?, 'A', '10.0.1.10', 300, ?)
            """, (scan_run_id, a_id, val, now_str))

            if val == "lab-portal.aiori.internal":
                not_before = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
                not_after = (datetime.now(timezone.utc) + timedelta(days=180)).isoformat()
                cursor.execute("""
                    INSERT INTO tls_observations (
                        scan_run_id, asset_id, domain, port, is_valid, is_expired,
                        days_to_expiry, not_before, not_after, issuer, subject, sans,
                        tls_version, cipher_suite, observed_at
                    ) VALUES (?, ?, ?, 443, 1, 0, 180, ?, ?, 'DigiCert Global Root CA', ?, ?, 'TLSv1.3', 'TLS_AES_256_GCM_SHA384', ?)
                """, (scan_run_id, a_id, val, not_before, not_after, val, json.dumps([val, f"api.{val}"]), now_str))

        elif a_type == "host":
            # Approved baseline services: 80 and 443
            for port in [80, 443]:
                svc_name = "HTTP" if port == 80 else "HTTPS"
                cursor.execute("""
                    INSERT INTO port_observations (
                        scan_run_id, asset_id, host_ip, port, protocol, state,
                        latency_ms, service_name, is_http, http_status, http_title,
                        server_header, is_unexpected, observed_at
                    ) VALUES (?, ?, ?, ?, 'TCP', 'OPEN', 1.5, ?, 1, 200, 'AIORI Lab Internal Portal', 'nginx/1.24.0', 0, ?)
                """, (scan_run_id, a_id, val, port, svc_name, now_str))
