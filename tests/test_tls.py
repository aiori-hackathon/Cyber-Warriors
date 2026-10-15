"""
Unit tests for Check 2: TLS Certificate Monitoring.
"""

import unittest
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from modules.tls_checker import TLSChecker
from database import init_db, seed_initial_lab_data


class TestTLSChecker(unittest.TestCase):
    def setUp(self):
        init_db()
        seed_initial_lab_data()
        self.checker = TLSChecker(timeout=1.0)

    def _generate_test_cert_der(self, is_expired: bool = False) -> bytes:
        """Generates a cryptographic X.509 cert in DER bytes for testing."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        if is_expired:
            not_before = now - timedelta(days=60)
            not_after = now - timedelta(days=10)
        else:
            not_before = now - timedelta(days=10)
            not_after = now + timedelta(days=90)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test.aiori.internal"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AIORI Test Org")
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(123456789)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("test.aiori.internal")]),
                critical=False
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_parse_valid_certificate(self):
        der_bytes = self._generate_test_cert_der(is_expired=False)
        parsed = self.checker._parse_x509_der(der_bytes, "test.aiori.internal")
        self.assertEqual(parsed["is_valid"], 1)
        self.assertEqual(parsed["is_expired"], 0)
        self.assertGreater(parsed["days_to_expiry"], 0)
        self.assertEqual(parsed["status_category"], "VALID")
        self.assertEqual(parsed["subject"], "test.aiori.internal")
        self.assertEqual(parsed["issuer"], "AIORI Test Org")

    def test_parse_expired_certificate(self):
        der_bytes = self._generate_test_cert_der(is_expired=True)
        parsed = self.checker._parse_x509_der(der_bytes, "test.aiori.internal")
        self.assertEqual(parsed["is_valid"], 0)
        self.assertEqual(parsed["is_expired"], 1)
        self.assertLess(parsed["days_to_expiry"], 0)
        self.assertEqual(parsed["status_category"], "EXPIRED")


if __name__ == "__main__":
    unittest.main()
