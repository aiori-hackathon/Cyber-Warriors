"""
Unit tests for Scope Manager and Target Boundary Enforcement.
"""

import unittest
from modules.scope_manager import ScopeManager, ScopeViolationError
from database import init_db, seed_initial_lab_data


class TestScopeManager(unittest.TestCase):
    def setUp(self):
        init_db()
        seed_initial_lab_data()

    def test_domain_validation(self):
        # Valid domains
        valid, _ = ScopeManager.validate_asset_input("domain", "test.aiori.internal")
        self.assertTrue(valid)
        valid, _ = ScopeManager.validate_asset_input("domain", "api.example.com")
        self.assertTrue(valid)

        # Invalid domains
        valid, err = ScopeManager.validate_asset_input("domain", "invalid..domain")
        self.assertFalse(valid)
        valid, err = ScopeManager.validate_asset_input("domain", "-starts-with-dash.com")
        self.assertFalse(valid)

    def test_host_validation(self):
        # Valid hosts
        valid, _ = ScopeManager.validate_asset_input("host", "127.0.0.1")
        self.assertTrue(valid)
        valid, _ = ScopeManager.validate_asset_input("host", "10.0.1.15")
        self.assertTrue(valid)

        # Invalid hosts
        valid, err = ScopeManager.validate_asset_input("host", "999.999.999.999")
        self.assertFalse(valid)

    def test_scope_rejection_for_unapproved_targets(self):
        # In-scope approved targets should pass
        ScopeManager.verify_target_in_scope("lab-portal.aiori.internal", "domain")
        ScopeManager.verify_target_in_scope("127.0.0.1", "host")

        # Out-of-scope targets MUST raise ScopeViolationError
        with self.assertRaises(ScopeViolationError):
            ScopeManager.verify_target_in_scope("unauthorised-target.com", "domain")

        with self.assertRaises(ScopeViolationError):
            ScopeManager.verify_target_in_scope("8.8.8.8", "host")

    def test_counts_and_limits(self):
        counts = ScopeManager.get_counts()
        self.assertLessEqual(counts["approved_domains"], counts["max_domains"])
        self.assertLessEqual(counts["approved_hosts"], counts["max_hosts"])


if __name__ == "__main__":
    unittest.main()
