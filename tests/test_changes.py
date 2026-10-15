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


if __name__ == "__main__":
    unittest.main()
