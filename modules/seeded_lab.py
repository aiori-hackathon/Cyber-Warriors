"""
Seeded Issue Testing and Synthetic Fixtures Module for AIORI-3 PS-011.
Provides a reproducible lab demonstration environment:
  1. Expired TLS Certificate (expired-tls.aiori.internal)
  2. Unexpected Open Service (10.0.1.15:8888 - Rogue Debug Console)
  3. Potential Dangling DNS (orphaned-bucket.aiori.internal -> S3 NoSuchBucket, blog.aiori.internal -> GitHub 404)
  4. False-Positive Control (test-cdn.aiori.internal -> CloudFront edge 404)
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from database import get_db_connection
from modules.change_detector import ChangeDetector


class SeededLabHarness:
    @classmethod
    def run_seeded_simulation_scan(cls) -> Dict[str, Any]:
        """
        Executes a safe, self-contained demonstration scan containing all mandated seeded vulnerabilities.
        Records observations in the database and computes deltas against the golden baseline.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now(timezone.utc)
        now_str = now.isoformat()

        # 1. Create Scan Run record clearly labelled as 'simulated'
        cursor.execute("""
            INSERT INTO scan_runs (
                scan_type, status, start_time, end_time,
                domains_scanned, hosts_scanned, findings_count, changes_count, notes
            ) VALUES ('simulated', 'running', ?, ?, 20, 10, 0, 0, 'AIORI-3 Seeded Issue Demonstration Scan [SYNTHETIC]')
        """, (now_str, now_str))
        scan_run_id = cursor.lastrowid

        # Retrieve assets to attach observations
        cursor.execute("SELECT id, name, asset_type, value FROM assets WHERE is_approved = 1")
        assets = cursor.fetchall()
        asset_map = {a["value"]: a["id"] for a in assets}

        # ----------------------------------------------------------------------
        # Seeded Issue 1: Expired TLS Certificate on expired-tls.aiori.internal
        # ----------------------------------------------------------------------
        exp_domain = "expired-tls.aiori.internal"
        exp_asset_id = asset_map.get(exp_domain)
        not_before = (now - timedelta(days=395)).isoformat()
        not_after = (now - timedelta(days=30)).isoformat()  # Expired 30 days ago

        cursor.execute("""
            INSERT INTO tls_observations (
                scan_run_id, asset_id, domain, port, is_valid, is_expired,
                days_to_expiry, not_before, not_after, issuer, subject, sans,
                signature_algo, serial_number, tls_version, cipher_suite, observed_at
            ) VALUES (?, ?, ?, 443, 0, 1, -30, ?, ?, 'AIORI Lab Internal CA', ?, ?, 'sha256WithRSAEncryption', '0xdeadbeef1001', 'TLSv1.2', 'ECDHE-RSA-AES256-GCM-SHA384', ?)
        """, (scan_run_id, exp_asset_id, exp_domain, not_before, not_after, exp_domain, json.dumps([exp_domain]), now_str))

        # ----------------------------------------------------------------------
        # Seeded Issue 2: Unexpected Service on host 10.0.1.15 (Port 8888)
        # ----------------------------------------------------------------------
        dev_host = "10.0.1.15"
        dev_asset_id = asset_map.get(dev_host)

        # Baseline ports: 443, 8443
        # Seeded unexpected port: 8888 (Werkzeug debug console)
        cursor.execute("""
            INSERT INTO port_observations (
                scan_run_id, asset_id, host_ip, port, protocol, state,
                latency_ms, service_name, banner, is_http, http_status,
                http_title, server_header, tech_stack, is_unexpected, observed_at
            ) VALUES (?, ?, ?, 8888, 'TCP', 'OPEN', 2.3, 'HTTP-Dev-Console',
                      'HTTP/1.1 200 OK\r\nServer: Python/Werkzeug\r\n',
                      1, 200, 'Unauthorized Debug Admin Dashboard', 'Python/Werkzeug',
                      ?, 1, ?)
        """, (scan_run_id, dev_asset_id, dev_host, json.dumps(["Python", "Flask", "Werkzeug"]), now_str))

        # ----------------------------------------------------------------------
        # Seeded Issue 3: Potential Dangling DNS (AWS S3) on orphaned-bucket.aiori.internal
        # ----------------------------------------------------------------------
        s3_domain = "orphaned-bucket.aiori.internal"
        s3_asset_id = asset_map.get(s3_domain)
        cursor.execute("""
            INSERT INTO dns_observations (
                scan_run_id, asset_id, domain, record_type, record_value, ttl,
                is_dangling_candidate, dangling_provider, dangling_reason, observed_at
            ) VALUES (?, ?, ?, 'CNAME', 'aiori-decommissioned-assets.s3.amazonaws.com', 300,
                      1, 'AWS S3', 'Target matches AWS S3 unlinked signature: NoSuchBucket with HTTP 404', ?)
        """, (scan_run_id, s3_asset_id, s3_domain, now_str))

        # ----------------------------------------------------------------------
        # Seeded Issue 4: Potential Dangling DNS (GitHub Pages) on blog.aiori.internal
        # ----------------------------------------------------------------------
        gh_domain = "blog.aiori.internal"
        gh_asset_id = asset_map.get(gh_domain)
        cursor.execute("""
            INSERT INTO dns_observations (
                scan_run_id, asset_id, domain, record_type, record_value, ttl,
                is_dangling_candidate, dangling_provider, dangling_reason, observed_at
            ) VALUES (?, ?, ?, 'CNAME', 'aiori-legacy-blog.github.io', 300,
                      1, 'GitHub Pages', 'Target matches GitHub Pages unlinked signature: There isnt a GitHub Pages site here with HTTP 404', ?)
        """, (scan_run_id, gh_asset_id, gh_domain, now_str))

        # ----------------------------------------------------------------------
        # Seeded Issue 5: False-Positive Control on test-cdn.aiori.internal
        # ----------------------------------------------------------------------
        cdn_domain = "test-cdn.aiori.internal"
        cdn_asset_id = asset_map.get(cdn_domain)
        cursor.execute("""
            INSERT INTO dns_observations (
                scan_run_id, asset_id, domain, record_type, record_value, ttl,
                is_dangling_candidate, dangling_provider, dangling_reason, observed_at
            ) VALUES (?, ?, ?, 'CNAME', 'd123456789.cloudfront.net', 300,
                      1, 'AWS CloudFront', 'Target returned HTTP 404 (Multi-tenant edge distribution)', ?)
        """, (scan_run_id, cdn_asset_id, cdn_domain, now_str))

        # Normal observations for other assets so the inventory is fully populated
        for a in assets:
            val = a["value"]
            a_id = a["id"]
            a_type = a["asset_type"]

            if a_type == "domain" and val not in [s3_domain, gh_domain, cdn_domain]:
                cursor.execute("""
                    INSERT INTO dns_observations (scan_run_id, asset_id, domain, record_type, record_value, ttl, observed_at)
                    VALUES (?, ?, ?, 'A', '10.0.1.10', 300, ?)
                """, (scan_run_id, a_id, val, now_str))
                if val == "lab-portal.aiori.internal":
                    valid_before = (now - timedelta(days=60)).isoformat()
                    valid_after = (now + timedelta(days=180)).isoformat()
                    cursor.execute("""
                        INSERT INTO tls_observations (
                            scan_run_id, asset_id, domain, port, is_valid, is_expired,
                            days_to_expiry, not_before, not_after, issuer, subject, sans,
                            tls_version, cipher_suite, observed_at
                        ) VALUES (?, ?, ?, 443, 1, 0, 180, ?, ?, 'DigiCert Global Root CA', ?, ?, 'TLSv1.3', 'TLS_AES_256_GCM_SHA384', ?)
                    """, (scan_run_id, a_id, val, valid_before, valid_after, val, json.dumps([val]), now_str))

            elif a_type == "host" and val != dev_host:
                for port in [80, 443]:
                    svc = "HTTP" if port == 80 else "HTTPS"
                    cursor.execute("""
                        INSERT INTO port_observations (
                            scan_run_id, asset_id, host_ip, port, protocol, state,
                            latency_ms, service_name, is_http, http_status, is_unexpected, observed_at
                        ) VALUES (?, ?, ?, ?, 'TCP', 'OPEN', 1.4, ?, 1, 200, 0, ?)
                    """, (scan_run_id, a_id, val, port, svc, now_str))

        conn.commit()
        conn.close()

        # Run Check 4: Compare newly recorded observations against baseline
        diff_result = ChangeDetector.compare_scan_with_baseline(scan_run_id)
        return {
            "scan_run_id": scan_run_id,
            "status": "completed",
            "type": "simulated",
            "changes_detected": diff_result["new_changes_count"],
            "findings_generated": diff_result["new_findings_count"]
        }
