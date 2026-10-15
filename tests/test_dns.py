"""
Unit tests for Check 1: DNS Records & Dangling CNAME Candidate Detection.
"""

import unittest
from unittest.mock import patch, MagicMock
from modules.dns_checker import DNSChecker
from database import init_db, seed_initial_lab_data


class TestDNSChecker(unittest.TestCase):
    def setUp(self):
        init_db()
        seed_initial_lab_data()
        self.checker = DNSChecker(timeout=1.0)

    def test_dangling_cname_detection_s3(self):
        """Verify that an S3 CNAME matching NoSuchBucket signature is flagged as a candidate."""
        with patch.object(self.checker, "_check_target_resolves", return_value=True):
            with patch.object(self.checker, "_probe_unclaimed_signature", return_value=(True, "Target matches AWS S3 unlinked signature: NoSuchBucket")):
                is_dangling, provider, reason = self.checker.evaluate_dangling_cname(
                    "orphaned-bucket.aiori.internal",
                    "my-test-bucket.s3.amazonaws.com"
                )
                self.assertTrue(is_dangling)
                self.assertEqual(provider, "AWS S3")
                self.assertIn("NoSuchBucket", reason)

    def test_dangling_cname_detection_nxdomain(self):
        """Verify that a CNAME returning NXDOMAIN is flagged as potential dangling."""
        with patch.object(self.checker, "_check_target_resolves", return_value=False):
            is_dangling, provider, reason = self.checker.evaluate_dangling_cname(
                "app.aiori.internal",
                "non-existent-app.elasticbeanstalk.com"
            )
            self.assertTrue(is_dangling)
            self.assertEqual(provider, "AWS Elastic Beanstalk")
            self.assertIn("NXDOMAIN", reason)

    def test_clean_cname_record(self):
        """Verify that an active, resolving CNAME with no orphan signature is not flagged."""
        with patch.object(self.checker, "_check_target_resolves", return_value=True):
            with patch.object(self.checker, "_probe_unclaimed_signature", return_value=(False, None)):
                is_dangling, provider, reason = self.checker.evaluate_dangling_cname(
                    "portal.aiori.internal",
                    "live-target.com"
                )
                self.assertFalse(is_dangling)
                self.assertIsNone(provider)


if __name__ == "__main__":
    unittest.main()
