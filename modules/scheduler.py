"""
Background Scheduler module for AIORI-3 PS-011.
Manages continuous periodic monitoring on Windows using safe daemon threads,
preventing overlapping scans and handling task execution safely.
"""

import threading
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from database import get_db_connection
from modules.scope_manager import ScopeManager
from modules.dns_checker import DNSChecker
from modules.tls_checker import TLSChecker
from modules.port_checker import PortChecker
from modules.change_detector import ChangeDetector
from modules.seeded_lab import SeededLabHarness


class BackgroundMonitor:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.is_scanning = False
        self.last_scan_time = None
        self.last_scan_status = "IDLE"
        self.scheduler_thread: Optional[threading.Thread] = None
        self.stop_requested = False

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = BackgroundMonitor()
            return cls._instance

    def run_live_scan(self) -> Dict[str, Any]:
        """
        Executes an authorized live discovery scan across all approved lab targets.
        Enforces strict limit and prevents overlapping scans.
        """
        if self.is_scanning:
            return {"status": "rejected", "message": "A scan is already in progress. Overlapping scans are prevented."}

        with self._lock:
            self.is_scanning = True
            self.last_scan_status = "SCANNING"

        conn = get_db_connection()
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).isoformat()

        try:
            # 1. Create Scan Run Record
            cursor.execute("""
                INSERT INTO scan_runs (scan_type, status, start_time, domains_scanned, hosts_scanned, notes)
                VALUES ('live', 'running', ?, 0, 0, 'Authorised Live Attack-Surface Scan')
            """, (now_str,))
            scan_run_id = cursor.lastrowid
            conn.commit()

            # 2. Retrieve Approved Targets
            targets = ScopeManager.get_approved_targets()
            domains = targets["domains"]
            hosts = targets["hosts"]

            dns_checker = DNSChecker()
            tls_checker = TLSChecker()
            port_checker = PortChecker()

            domains_done = 0
            hosts_done = 0

            # 3. Check 1 (DNS) and Check 2 (TLS) on Approved Domains
            for d in domains:
                dom_val = d["value"]
                asset_id = d["id"]

                # Run DNS Check
                try:
                    records = dns_checker.check_domain_dns(dom_val)
                    for r in records:
                        cursor.execute("""
                            INSERT INTO dns_observations (
                                scan_run_id, asset_id, domain, record_type, record_value,
                                ttl, is_dangling_candidate, dangling_provider, dangling_reason, observed_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (scan_run_id, asset_id, dom_val, r["record_type"], r["value"],
                              r.get("ttl", 300), r.get("is_dangling_candidate", 0),
                              r.get("dangling_provider"), r.get("dangling_reason"), now_str))
                except Exception:
                    pass

                # Run TLS Check
                try:
                    tls_info = tls_checker.check_tls_certificate(dom_val, 443)
                    cursor.execute("""
                        INSERT INTO tls_observations (
                            scan_run_id, asset_id, domain, port, is_valid, is_expired,
                            days_to_expiry, not_before, not_after, issuer, subject, sans,
                            signature_algo, serial_number, tls_version, cipher_suite, error_message, observed_at
                        ) VALUES (?, ?, ?, 443, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (scan_run_id, asset_id, dom_val, tls_info.get("is_valid", 0),
                          tls_info.get("is_expired", 0), tls_info.get("days_to_expiry"),
                          tls_info.get("not_before"), tls_info.get("not_after"),
                          tls_info.get("issuer"), tls_info.get("subject"),
                          tls_info.get("sans"), tls_info.get("signature_algo"),
                          tls_info.get("serial_number"), tls_info.get("tls_version"),
                          tls_info.get("cipher_suite"), tls_info.get("error_message"), now_str))
                except Exception:
                    pass

                domains_done += 1

            # 4. Check 3 on Approved Hosts
            for h in hosts:
                host_val = h["value"]
                asset_id = h["id"]
                try:
                    port_results = port_checker.inspect_host_ports(host_val)
                    for p in port_results:
                        cursor.execute("""
                            INSERT INTO port_observations (
                                scan_run_id, asset_id, host_ip, port, protocol, state,
                                latency_ms, service_name, banner, is_http, http_status,
                                http_title, server_header, tech_stack, security_headers,
                                is_unexpected, observed_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (scan_run_id, asset_id, host_val, p["port"], p["protocol"],
                              p["state"], p["latency_ms"], p["service_name"], p["banner"],
                              p["is_http"], p["http_status"], p["http_title"], p["server_header"],
                              p.get("tech_stack"), p.get("security_headers"), p.get("is_unexpected", 0), now_str))
                except Exception:
                    pass
                hosts_done += 1

            # Update scan run metadata
            cursor.execute("""
                UPDATE scan_runs
                SET domains_scanned = ?, hosts_scanned = ?, end_time = ?
                WHERE id = ?
            """, (domains_done, hosts_done, datetime.now(timezone.utc).isoformat(), scan_run_id))
            conn.commit()
            conn.close()

            # 5. Check 4: Baseline comparison & change detection
            diff_res = ChangeDetector.compare_scan_with_baseline(scan_run_id)

            self.last_scan_time = now_str
            self.last_scan_status = "COMPLETED"

            return {
                "status": "success",
                "scan_run_id": scan_run_id,
                "scan_type": "live",
                "domains_scanned": domains_done,
                "hosts_scanned": hosts_done,
                "changes_count": diff_res["new_changes_count"],
                "findings_count": diff_res["new_findings_count"]
            }

        except Exception as e:
            conn.close()
            self.last_scan_status = "FAILED"
            return {"status": "error", "message": f"Scan failed: {str(e)}"}
        finally:
            with self._lock:
                self.is_scanning = False

    def trigger_simulated_scan(self) -> Dict[str, Any]:
        """Triggers the synthetic seeded demonstration scan."""
        if self.is_scanning:
            return {"status": "rejected", "message": "A scan is already running."}

        with self._lock:
            self.is_scanning = True

        try:
            res = SeededLabHarness.run_seeded_simulation_scan()
            self.last_scan_time = datetime.now(timezone.utc).isoformat()
            self.last_scan_status = "COMPLETED (SIMULATED)"
            return {"status": "success", "data": res}
        finally:
            with self._lock:
                self.is_scanning = False
