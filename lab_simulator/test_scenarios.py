"""
Test Scenarios and Verification Suite for AIORI-3 PS-011.
Proves end-to-end functionality of:
  1. Scope Enforcement (blocks unauthorized scans)
  2. The 4 Documented Checks execution
  3. Detection of all Seeded Issues (Expired Cert, Unexpected Port, Dangling DNS)
  4. False-Positive Analysis and Confidence Scoring
"""

import unittest
from core.scope_guard import ScopeGuard, ScopeViolationError
from core.diff_engine import DiffEngine
from core.models import AlertCategory, Severity, Confidence
from lab_simulator.mock_targets import LabSimulator
from checks.service_inspector import ServiceInspector


class TestAttackSurfaceMonitor(unittest.TestCase):
    def setUp(self):
        self.scope_guard = ScopeGuard()
        self.diff_engine = DiffEngine()
        self.service_inspector = ServiceInspector(scope_guard=self.scope_guard)

    def test_01_scope_guard_enforcement(self):
        """Verify strict adherence to organiser-approved scope; blocks out-of-scope targets."""
        # In-scope targets should pass
        self.assertTrue(self.scope_guard.is_domain_in_scope("lab-portal.aiori.internal"))
        self.assertTrue(self.scope_guard.is_host_in_scope("127.0.0.1"))
        
        # Out-of-scope targets MUST be rejected
        self.assertFalse(self.scope_guard.is_domain_in_scope("unauthorized-target.com"))
        self.assertFalse(self.scope_guard.is_host_in_scope("8.8.8.8"))
        
        with self.assertRaises(ScopeViolationError):
            self.scope_guard.validate_domain("google.com")
            
        with self.assertRaises(ScopeViolationError):
            self.scope_guard.validate_host("192.168.100.1")

    def test_02_seeded_issue_detection(self):
        """Verify detection of Expired Certificates, Unexpected Services, and Dangling DNS."""
        baseline = LabSimulator.get_baseline_snapshot().to_dict()
        current = LabSimulator.get_current_scan_with_seeded_issues().to_dict()
        
        diff = self.diff_engine.compare(baseline, current)
        
        categories = [a.category for a in diff.alerts]
        targets = [a.target for a in diff.alerts]
        
        # 1. Expired Certificate Seeded Detection
        self.assertIn(AlertCategory.EXPIRED_CERTIFICATE, categories)
        self.assertIn("expired-tls.aiori.internal", targets)
        
        # 2. Unexpected Service Seeded Detection (Port 8888 on 10.0.1.15)
        self.assertIn(AlertCategory.UNEXPECTED_SERVICE, categories)
        self.assertIn("10.0.1.15:8888", targets)
        
        # 3. Dangling DNS Seeded Detection
        self.assertIn(AlertCategory.POTENTIAL_DANGLING_DNS, categories)
        self.assertIn("orphaned-bucket.aiori.internal", targets)
        self.assertIn("blog.aiori.internal", targets)

    def test_03_false_positive_analysis(self):
        """Verify false-positive scoring engine distinguishes high-risk from low-risk alerts."""
        baseline = LabSimulator.get_baseline_snapshot().to_dict()
        current = LabSimulator.get_current_scan_with_seeded_issues().to_dict()
        
        diff = self.diff_engine.compare(baseline, current)
        
        s3_alert = next((a for a in diff.alerts if "orphaned-bucket" in a.target), None)
        self.assertIsNotNone(s3_alert)
        self.assertEqual(s3_alert.confidence, Confidence.HIGH)
        self.assertEqual(s3_alert.false_positive_risk, "LOW")
        
        cdn_alert = next((a for a in diff.alerts if "test-cdn" in a.target), None)
        self.assertIsNotNone(cdn_alert)
        self.assertEqual(cdn_alert.confidence, Confidence.LOW)
        self.assertEqual(cdn_alert.false_positive_risk, "HIGH")

    def test_04_four_documented_checks_interface(self):
        """Verify 4 documented checks structure and data contracts."""
        # Run Check 1 & Check 2 against 127.0.0.1 on a closed port
        result = self.service_inspector.inspect_port("127.0.0.1", 45678)
        self.assertEqual(result.state, "CLOSED")
        self.assertEqual(result.port, 45678)
        self.assertIsNone(result.banner)


if __name__ == "__main__":
    unittest.main()
