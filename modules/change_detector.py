"""
Check 4: Baseline Comparison and Change Detection Engine.

Purpose:
  Compares a completed scan run against the active golden baseline inventory,
  identifies asset and service drift, classifies severity, records change events,
  and manages security findings lifecycle (OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE).

Inputs:
  - scan_run_id (int): Identifier of the completed scan.
  - baseline_id (Optional[int]): Identifier of baseline snapshot (defaults to active baseline).

Outputs:
  - Dictionary summarizing new changes, created findings, and delta statistics.

Duplicate Prevention:
  - Checks existing security_findings to avoid creating duplicate OPEN alerts for identical assets and categories.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from database import get_db_connection


class ChangeDetector:
    @classmethod
    def compare_scan_with_baseline(cls, scan_run_id: int, baseline_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Executes Check 4: Deep delta comparison between current scan observations and golden baseline.
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        # Find active baseline if not explicitly specified
        if not baseline_id:
            cursor.execute("SELECT id, scan_run_id FROM baseline_snapshots WHERE is_active = 1 ORDER BY id DESC LIMIT 1")
            b_row = cursor.fetchone()
            if not b_row:
                # If no baseline exists, set this scan as baseline!
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute("""
                    INSERT INTO baseline_snapshots (snapshot_name, scan_run_id, is_active, created_at, notes)
                    VALUES (?, ?, 1, ?, 'Auto-established initial baseline')
                """, (f"Baseline-Scan-{scan_run_id}", scan_run_id, now))
                baseline_id = cursor.lastrowid
                baseline_scan_run_id = scan_run_id
            else:
                baseline_id = b_row["id"]
                baseline_scan_run_id = b_row["scan_run_id"]
        else:
            cursor.execute("SELECT scan_run_id FROM baseline_snapshots WHERE id = ?", (baseline_id,))
            b_row = cursor.fetchone()
            baseline_scan_run_id = b_row["scan_run_id"] if b_row else scan_run_id

        now_str = datetime.now(timezone.utc).isoformat()
        new_changes = 0
        new_findings = 0

        # ----------------------------------------------------------------------
        # 1. Compare Port & Service Observations (Unexpected Services)
        # ----------------------------------------------------------------------
        # Fetch current open ports
        cursor.execute("""
            SELECT id, asset_id, host_ip, port, service_name, banner, is_unexpected, http_status, http_title
            FROM port_observations
            WHERE scan_run_id = ? AND state = 'OPEN'
        """, (scan_run_id,))
        current_open_ports = cursor.fetchall()

        # Fetch baseline open ports
        cursor.execute("""
            SELECT host_ip, port FROM port_observations
            WHERE scan_run_id = ? AND state = 'OPEN'
        """, (baseline_scan_run_id,))
        baseline_open_ports = {(r["host_ip"], r["port"]) for r in cursor.fetchall()}

        for p_row in current_open_ports:
            host_ip = p_row["host_ip"]
            port = p_row["port"]
            asset_id = p_row["asset_id"]
            svc_name = p_row["service_name"] or "TCP"
            is_unexp = p_row["is_unexpected"]

            # If port was NOT in baseline
            if (host_ip, port) not in baseline_open_ports:
                change_type = "NEW_UNEXPECTED_SERVICE" if is_unexp else "NEW_OPEN_PORT"
                severity = "HIGH" if is_unexp else "MEDIUM"
                title = f"Unexpected Open Service Detected on {host_ip}:{port} ({svc_name})"
                desc = (
                    f"Host '{host_ip}' has newly opened port {port} ({svc_name}). "
                    f"This service was not present in the baseline inventory."
                )
                evidence = json.dumps({
                    "host": host_ip, "port": port, "service": svc_name,
                    "banner": p_row["banner"], "http_title": p_row["http_title"]
                })
                defensive_action = (
                    f"Inspect process listening on {host_ip}:{port}. "
                    f"If unauthorized, shut down service and block port at firewall."
                )

                # Record Change Event
                cursor.execute("""
                    INSERT INTO change_events (scan_run_id, baseline_id, asset_id, change_type, severity, title, description, evidence, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (scan_run_id, baseline_id, asset_id, change_type, severity, title, desc, evidence, now_str))
                change_event_id = cursor.lastrowid
                new_changes += 1

                # Record Security Finding (with deduplication)
                if not cls._finding_exists(cursor, host_ip, "UNEXPECTED_SERVICE"):
                    cursor.execute("""
                        INSERT INTO security_findings (
                            scan_run_id, change_event_id, asset_id, category, severity,
                            title, description, evidence, defensive_action, status,
                            confidence, false_positive_risk, created_at, updated_at
                        ) VALUES (?, ?, ?, 'UNEXPECTED_SERVICE', ?, ?, ?, ?, ?, 'OPEN', 'HIGH', 'LOW', ?, ?)
                    """, (scan_run_id, change_event_id, asset_id, severity, title, desc, evidence, defensive_action, now_str, now_str))
                    new_findings += 1

        # ----------------------------------------------------------------------
        # 2. Check TLS Observations (Expired & Expiring Certificates)
        # ----------------------------------------------------------------------
        cursor.execute("""
            SELECT id, asset_id, domain, port, is_expired, days_to_expiry, issuer, not_after, error_message
            FROM tls_observations
            WHERE scan_run_id = ?
        """, (scan_run_id,))
        tls_obs = cursor.fetchall()

        for t_row in tls_obs:
            domain = t_row["domain"]
            asset_id = t_row["asset_id"]
            is_expired = t_row["is_expired"]
            days_left = t_row["days_to_expiry"]
            issuer = t_row["issuer"] or "Unknown CA"
            not_after = t_row["not_after"] or "Unknown"

            if is_expired:
                title = f"Critical: Expired TLS Certificate on {domain}"
                desc = f"Domain '{domain}' presents an expired TLS certificate issued by '{issuer}'. Expired on {not_after}."
                evidence = json.dumps({"domain": domain, "issuer": issuer, "not_after": not_after, "days_expired": abs(days_left or 0)})
                action = "Immediately renew certificate with authoritative CA and deploy to load balancer or web server."

                cursor.execute("""
                    INSERT INTO change_events (scan_run_id, baseline_id, asset_id, change_type, severity, title, description, evidence, detected_at)
                    VALUES (?, ?, ?, 'TLS_CERT_EXPIRED', 'CRITICAL', ?, ?, ?, ?)
                """, (scan_run_id, baseline_id, asset_id, title, desc, evidence, now_str))
                change_event_id = cursor.lastrowid
                new_changes += 1

                if not cls._finding_exists(cursor, domain, "EXPIRED_CERTIFICATE"):
                    cursor.execute("""
                        INSERT INTO security_findings (
                            scan_run_id, change_event_id, asset_id, category, severity,
                            title, description, evidence, defensive_action, status,
                            confidence, false_positive_risk, created_at, updated_at
                        ) VALUES (?, ?, ?, 'EXPIRED_CERTIFICATE', 'CRITICAL', ?, ?, ?, ?, 'OPEN', 'HIGH', 'LOW', ?, ?)
                    """, (scan_run_id, change_event_id, asset_id, title, desc, evidence, action, now_str, now_str))
                    new_findings += 1

            elif days_left is not None and days_left <= 14:
                title = f"Warning: TLS Certificate Expiring in {days_left} Days on {domain}"
                desc = f"Domain '{domain}' certificate expires on {not_after}."
                evidence = json.dumps({"domain": domain, "days_remaining": days_left, "issuer": issuer})
                action = "Initiate automated ACME renewal or contact PKI administrator before service disruption."

                cursor.execute("""
                    INSERT INTO change_events (scan_run_id, baseline_id, asset_id, change_type, severity, title, description, evidence, detected_at)
                    VALUES (?, ?, ?, 'TLS_CERT_EXPIRING', 'MEDIUM', ?, ?, ?, ?)
                """, (scan_run_id, baseline_id, asset_id, title, desc, evidence, now_str))
                new_changes += 1

        # ----------------------------------------------------------------------
        # 3. Check DNS Observations (Potential Dangling DNS CNAMEs)
        # ----------------------------------------------------------------------
        cursor.execute("""
            SELECT id, asset_id, domain, record_value, is_dangling_candidate, dangling_provider, dangling_reason
            FROM dns_observations
            WHERE scan_run_id = ? AND is_dangling_candidate = 1
        """, (scan_run_id,))
        dangling_obs = cursor.fetchall()

        for d_row in dangling_obs:
            domain = d_row["domain"]
            asset_id = d_row["asset_id"]
            provider = d_row["dangling_provider"] or "Cloud Provider"
            cname = d_row["record_value"]
            reason = d_row["dangling_reason"] or ""

            # False-positive triage scoring
            confidence = "HIGH"
            fp_risk = "LOW"
            if "CloudFront" in provider or "Fastly" in provider or "Cloudflare" in provider:
                confidence = "LOW"
                fp_risk = "HIGH"

            title = f"Potential Dangling DNS Record Pointing to {provider} ({domain})"
            desc = (
                f"Domain '{domain}' possesses a CNAME pointing to '{cname}' ({provider}). "
                f"Detection indicator: {reason}. Bounded verification only: no exploitability claimed."
            )
            evidence = json.dumps({"domain": domain, "cname_target": cname, "provider": provider, "reason": reason})
            action = f"Verify whether the {provider} resource was deleted. Remove orphan CNAME from authoritative DNS zone or reclaim asset."

            cursor.execute("""
                INSERT INTO change_events (scan_run_id, baseline_id, asset_id, change_type, severity, title, description, evidence, detected_at)
                VALUES (?, ?, ?, 'DANGLING_DNS_DETECTED', 'HIGH', ?, ?, ?, ?)
            """, (scan_run_id, baseline_id, asset_id, title, desc, evidence, now_str))
            change_event_id = cursor.lastrowid
            new_changes += 1

            if not cls._finding_exists(cursor, domain, "POTENTIAL_DANGLING_DNS"):
                cursor.execute("""
                    INSERT INTO security_findings (
                        scan_run_id, change_event_id, asset_id, category, severity,
                        title, description, evidence, defensive_action, status,
                        confidence, false_positive_risk, created_at, updated_at
                    ) VALUES (?, ?, ?, 'POTENTIAL_DANGLING_DNS', 'HIGH', ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)
                """, (scan_run_id, change_event_id, asset_id, title, desc, evidence, action, confidence, fp_risk, now_str, now_str))
                new_findings += 1

        # Update Scan Run statistics
        cursor.execute("""
            UPDATE scan_runs
            SET changes_count = ?, findings_count = ?, status = 'completed'
            WHERE id = ?
        """, (new_changes, new_findings, scan_run_id))

        conn.commit()
        conn.close()

        return {
            "scan_run_id": scan_run_id,
            "baseline_id": baseline_id,
            "new_changes_count": new_changes,
            "new_findings_count": new_findings
        }

    @classmethod
    def _finding_exists(cls, cursor, target_str: str, category: str) -> bool:
        """Helper to avoid creating duplicate OPEN alerts for unchanged findings."""
        cursor.execute("""
            SELECT id FROM security_findings
            WHERE title LIKE ? AND category = ? AND status = 'OPEN'
        """, (f"%{target_str}%", category))
        return cursor.fetchone() is not None

    @classmethod
    def update_finding_status(cls, finding_id: int, new_status: str, notes: str = "", fp_reason: str = "") -> bool:
        """Supports acknowledging, resolving, and reviewing findings (including marking False Positives)."""
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            UPDATE security_findings
            SET status = ?, review_notes = ?, false_positive_reason = ?, updated_at = ?
            WHERE id = ?
        """, (new_status, notes, fp_reason, now, finding_id))
        rows = cursor.rowcount
        conn.commit()
        conn.close()
        return rows > 0
