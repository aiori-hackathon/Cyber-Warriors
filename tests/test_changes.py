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


if __name__ == "__main__":
    unittest.main()
