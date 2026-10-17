"""
Unit tests for Check 4: Baseline Comparison, Drift Detection, and Triage Lifecycle.
"""

import unittest
from modules.change_detector import ChangeDetector
from modules.seeded_lab import SeededLabHarness
from database import init_db, seed_initial_lab_data, get_db_connection


class TestChangeDetector(unittest.TestCase):
    def setUp(self):
        init_db()
        seed_initial_lab_data()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_findings")
        cursor.execute("DELETE FROM change_events")
        conn.commit()
        conn.close()

    def test_seeded_simulation_and_change_detection(self):
        # Run seeded simulation
        sim_res = SeededLabHarness.run_seeded_simulation_scan()
        self.assertEqual(sim_res["status"], "completed")
        self.assertGreater(sim_res["changes_detected"], 0)
        self.assertGreater(sim_res["findings_generated"], 0)

        # Inspect generated findings in database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT category, severity, title FROM security_findings WHERE scan_run_id = ?", (sim_res["scan_run_id"],))
        findings = cursor.fetchall()
        conn.close()

        categories = [f["category"] for f in findings]
        self.assertIn("EXPIRED_CERTIFICATE", categories)
        self.assertIn("UNEXPECTED_SERVICE", categories)
        self.assertIn("POTENTIAL_DANGLING_DNS", categories)

    def test_triage_status_lifecycle(self):
        # Insert a test finding
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_findings (
                scan_run_id, category, severity, title, description, defensive_action,
                status, confidence, false_positive_risk, created_at, updated_at
            ) VALUES (1, 'UNEXPECTED_SERVICE', 'HIGH', 'Test Finding', 'Test Desc', 'Action', 'OPEN', 'HIGH', 'LOW', '2026-10-15T00:00:00', '2026-10-15T00:00:00')
        """)
        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Update status to ACKNOWLEDGED
        success = ChangeDetector.update_finding_status(finding_id, "ACKNOWLEDGED", notes="Assigned to SecOps")
        self.assertTrue(success)

        # Update status to FALSE_POSITIVE
        success = ChangeDetector.update_finding_status(finding_id, "FALSE_POSITIVE", notes="Verified CDN edge", fp_reason="Multi-tenant edge")
        self.assertTrue(success)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT status, false_positive_reason FROM security_findings WHERE id = ?", (finding_id,))
        row = cursor.fetchone()
        conn.close()
        self.assertEqual(row["status"], "FALSE_POSITIVE")
        self.assertEqual(row["false_positive_reason"], "Multi-tenant edge")

    def test_unexpected_service_deduplication_distinguishes_ports(self):
        """
        Regression test:
        1. Two unexpected open ports on the same host (e.g. 8888 and 9090 on 10.0.1.15)
           must produce TWO distinct UNEXPECTED_SERVICE findings.
        2. Rerunning the scan with the same unexpected ports must NOT create duplicate findings.
        3. Opening a port whose number is a prefix of an existing port (e.g. 88 vs 8888)
           must generate a new distinct finding rather than being incorrectly skipped.
        """
        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()

        # Step 1: Create Scan 1 with two unexpected open ports on 10.0.1.15 (8888 and 9090)
        cursor.execute("""
            INSERT INTO scan_runs (scan_type, status, start_time, notes)
            VALUES ('simulated', 'completed', ?, 'Regression Test Scan 1')
        """, (now_str,))
        scan1_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO port_observations (scan_run_id, host_ip, port, protocol, state, is_unexpected, service_name, observed_at)
            VALUES (?, '10.0.1.15', 8888, 'TCP', 'OPEN', 1, 'HTTP-Dev-Console', ?)
        """, (scan1_id, now_str))

        cursor.execute("""
            INSERT INTO port_observations (scan_run_id, host_ip, port, protocol, state, is_unexpected, service_name, observed_at)
            VALUES (?, '10.0.1.15', 9090, 'TCP', 'OPEN', 1, 'Prometheus-Metrics', ?)
        """, (scan1_id, now_str))

        conn.commit()
        conn.close()

        # Execute change comparison on Scan 1
        res1 = ChangeDetector.compare_scan_with_baseline(scan1_id)
        self.assertEqual(res1["new_findings_count"], 2)

        # Verify two distinct findings exist in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT title FROM security_findings
            WHERE category = 'UNEXPECTED_SERVICE' AND status = 'OPEN'
        """)
        titles = [r["title"] for r in cursor.fetchall()]
        conn.close()

        self.assertEqual(len(titles), 2)
        self.assertTrue(any("10.0.1.15:8888" in t for t in titles))
        self.assertTrue(any("10.0.1.15:9090" in t for t in titles))

        # Step 2: Create Scan 2 with the exact same open ports (testing deduplication)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_runs (scan_type, status, start_time, notes)
            VALUES ('simulated', 'completed', ?, 'Regression Test Scan 2')
        """, (now_str,))
        scan2_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO port_observations (scan_run_id, host_ip, port, protocol, state, is_unexpected, service_name, observed_at)
            VALUES (?, '10.0.1.15', 8888, 'TCP', 'OPEN', 1, 'HTTP-Dev-Console', ?)
        """, (scan2_id, now_str))

        cursor.execute("""
            INSERT INTO port_observations (scan_run_id, host_ip, port, protocol, state, is_unexpected, service_name, observed_at)
            VALUES (?, '10.0.1.15', 9090, 'TCP', 'OPEN', 1, 'Prometheus-Metrics', ?)
        """, (scan2_id, now_str))

        conn.commit()
        conn.close()

        # Execute change comparison on Scan 2
        res2 = ChangeDetector.compare_scan_with_baseline(scan2_id)
        # 0 new findings generated because both are already OPEN
        self.assertEqual(res2["new_findings_count"], 0)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM security_findings
            WHERE category = 'UNEXPECTED_SERVICE' AND status = 'OPEN'
        """)
        open_count = cursor.fetchone()[0]
        conn.close()
        self.assertEqual(open_count, 2)

        # Step 3: Prefix boundary test (Port 88 vs Port 8888)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_runs (scan_type, status, start_time, notes)
            VALUES ('simulated', 'completed', ?, 'Regression Test Scan 3')
        """, (now_str,))
        scan3_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO port_observations (scan_run_id, host_ip, port, protocol, state, is_unexpected, service_name, observed_at)
            VALUES (?, '10.0.1.15', 88, 'TCP', 'OPEN', 1, 'Kerberos', ?)
        """, (scan3_id, now_str))

        conn.commit()
        conn.close()

        res3 = ChangeDetector.compare_scan_with_baseline(scan3_id)
        self.assertEqual(res3["new_findings_count"], 1)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM security_findings
            WHERE category = 'UNEXPECTED_SERVICE' AND status = 'OPEN'
        """)
        final_count = cursor.fetchone()[0]
        conn.close()
        self.assertEqual(final_count, 3)

    def test_triage_status_and_notes_persistence_across_scans(self):
        """
        Regression test:
        1. When an investigator triages a finding as ACKNOWLEDGED or FALSE_POSITIVE with notes,
           subsequent scans observing the same issue must NOT create duplicate findings.
        2. The investigator's status, review notes, and false-positive rationale must persist.
        3. The active finding count in the registry must NOT be inflated.
        """
        # Step 1: Run seeded scan to generate baseline findings
        sim_res = SeededLabHarness.run_seeded_simulation_scan()
        scan1_id = sim_res["scan_run_id"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, category, title FROM security_findings ORDER BY id ASC")
        findings = cursor.fetchall()
        initial_finding_count = len(findings)
        self.assertGreater(initial_finding_count, 0)

        # Pick one UNEXPECTED_SERVICE finding to acknowledge
        unexp_f = next(f for f in findings if f["category"] == "UNEXPECTED_SERVICE")
        unexp_id = unexp_f["id"]

        # Pick one POTENTIAL_DANGLING_DNS finding to mark false positive
        dangling_f = next(f for f in findings if f["category"] == "POTENTIAL_DANGLING_DNS")
        dangling_id = dangling_f["id"]
        conn.close()

        # Step 2: Investigator triages both findings
        ack_notes = "Ticket SEC-2026: Service under active review by DevOps team"
        ChangeDetector.update_finding_status(unexp_id, "ACKNOWLEDGED", notes=ack_notes)

        fp_notes = "Investigated CDN routing distribution configuration"
        fp_reason = "Multi-tenant CDN edge 404 is default behavior"
        ChangeDetector.update_finding_status(dangling_id, "FALSE_POSITIVE", notes=fp_notes, fp_reason=fp_reason)

        # Step 3: Run a second scan with identical observations (e.g. repeated scan)
        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_runs (scan_type, status, start_time, notes)
            VALUES ('simulated', 'completed', ?, 'Repeated Scan Run 2')
        """, (now_str,))
        scan2_id = cursor.lastrowid

        # Copy observations from scan1 to scan2
        cursor.execute("""
            INSERT INTO port_observations (scan_run_id, host_ip, port, protocol, state, is_unexpected, service_name, banner, observed_at)
            SELECT ?, host_ip, port, protocol, state, is_unexpected, service_name, banner, ?
            FROM port_observations WHERE scan_run_id = ?
        """, (scan2_id, now_str, scan1_id))

        cursor.execute("""
            INSERT INTO tls_observations (scan_run_id, domain, port, is_valid, is_expired, days_to_expiry, issuer, not_after, observed_at)
            SELECT ?, domain, port, is_valid, is_expired, days_to_expiry, issuer, not_after, ?
            FROM tls_observations WHERE scan_run_id = ?
        """, (scan2_id, now_str, scan1_id))

        cursor.execute("""
            INSERT INTO dns_observations (scan_run_id, domain, record_type, record_value, is_dangling_candidate, dangling_provider, dangling_reason, observed_at)
            SELECT ?, domain, record_type, record_value, is_dangling_candidate, dangling_provider, dangling_reason, ?
            FROM dns_observations WHERE scan_run_id = ?
        """, (scan2_id, now_str, scan1_id))

        conn.commit()
        conn.close()

        # Step 4: Compare scan2 with baseline
        res2 = ChangeDetector.compare_scan_with_baseline(scan2_id)
        # No new findings should be created since all issues are already tracked (OPEN, ACKNOWLEDGED, or FALSE_POSITIVE)
        self.assertEqual(res2["new_findings_count"], 0)

        # Step 5: Verify findings registry integrity
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_findings")
        total_findings_after = cursor.fetchone()[0]
        self.assertEqual(total_findings_after, initial_finding_count)

        # Verify acknowledged finding preserved its status and notes
        cursor.execute("SELECT status, review_notes FROM security_findings WHERE id = ?", (unexp_id,))
        row_ack = cursor.fetchone()
        self.assertEqual(row_ack["status"], "ACKNOWLEDGED")
        self.assertEqual(row_ack["review_notes"], ack_notes)

        # Verify false positive finding preserved its status, notes, and rationale
        cursor.execute("SELECT status, review_notes, false_positive_reason FROM security_findings WHERE id = ?", (dangling_id,))
        row_fp = cursor.fetchone()
        self.assertEqual(row_fp["status"], "FALSE_POSITIVE")
        self.assertEqual(row_fp["review_notes"], fp_notes)
        self.assertEqual(row_fp["false_positive_reason"], fp_reason)
        conn.close()

    def test_technical_report_includes_triage_status_notes_and_fp_reason(self):
        """Verifies generated technical report includes triage status, investigator notes, and rationales."""
        from modules.report_generator import ReportGenerator

        # Insert a triaged finding
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_findings (
                scan_run_id, category, severity, title, description, defensive_action,
                status, confidence, false_positive_risk, review_notes, false_positive_reason,
                created_at, updated_at
            ) VALUES (1, 'POTENTIAL_DANGLING_DNS', 'HIGH', 'Test Dangling DNS (cdn.aiori.internal)',
                      'Description', 'Defensive action', 'FALSE_POSITIVE', 'LOW', 'HIGH',
                      'Verified by Analyst Alice', 'CloudFront multi-tenant default 404',
                      '2026-10-17T00:00:00', '2026-10-17T00:00:00')
        """)
        conn.commit()
        conn.close()

        report_data = ReportGenerator.generate_full_technical_report()
        md = report_data["markdown"]

        # Assert status and notes appear in report
        self.assertIn("FALSE_POSITIVE", md)
        self.assertIn("Verified by Analyst Alice", md)
        self.assertIn("CloudFront multi-tenant default 404", md)
        self.assertIn("False Positive", md)

        # Assert CSV export also includes notes and reason
        csv_out = ReportGenerator.export_csv("findings")
        self.assertIn("Verified by Analyst Alice", csv_out)
        self.assertIn("CloudFront multi-tenant default 404", csv_out)


if __name__ == "__main__":
    unittest.main()
