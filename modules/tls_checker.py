"""
Check 2: TLS Certificate Monitoring and Validity Verification.

Purpose:
  Inspects certificates on approved HTTPS/TLS endpoints, records validity dates, issuer,
  subject alternative names (SANs), cipher suites, and reliably identifies expired or
  approaching-expiry certificates.

Inputs:
  - domain_or_host (str): Approved domain or IP to probe.
  - port (int): Target TLS port (default 443).
  - timeout (float): Socket connect timeout in seconds.

Outputs:
  - Dictionary with keys: is_valid, is_expired, days_to_expiry, not_before, not_after,
    issuer, subject, sans, tls_version, cipher_suite, error_message, status_category.

Distinctions & Error Handling:
  - Explicitly distinguishes an EXPIRED certificate from other network failures (e.g. connection refused, timeout, handshake failure).
  - Uses cryptography library for robust X.509 parsing.
  - Uses CERT_NONE so even invalid/expired certificates can be parsed and audited.
"""

import socket
import ssl
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

from config import DEFAULT_SOCKET_TIMEOUT, CERT_EXPIRY_WARNING_DAYS
from modules.scope_manager import ScopeManager


class TLSChecker:
    def __init__(self, timeout: float = DEFAULT_SOCKET_TIMEOUT):
        self.timeout = timeout

    def check_tls_certificate(self, domain_or_host: str, port: int = 443) -> Dict[str, Any]:
        """
        Executes Check 2: TLS Certificate inspection on an approved target.
        Enforces scope validation prior to execution.
        """
        # Validate scope
        try:
            ScopeManager.verify_target_in_scope(domain_or_host, "domain")
        except Exception:
            ScopeManager.verify_target_in_scope(domain_or_host, "host")

        result = {
            "domain": domain_or_host,
            "port": port,
            "is_valid": 0,
            "is_expired": 0,
            "days_to_expiry": None,
            "not_before": None,
            "not_after": None,
            "issuer": None,
            "subject": None,
            "sans": json.dumps([]),
            "signature_algo": None,
            "serial_number": None,
            "tls_version": None,
            "cipher_suite": None,
            "error_message": None,
            "status_category": "UNKNOWN"  # VALID, EXPIRED, EXPIRING_SOON, CONNECTION_FAILED, TIMEOUT, NO_TLS
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Read certificate even if expired/untrusted

        try:
            with socket.create_connection((domain_or_host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain_or_host) as ssock:
                    result["tls_version"] = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result["cipher_suite"] = cipher_info[0]

                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        result["error_message"] = "No peer certificate returned by remote endpoint"
                        result["status_category"] = "NO_TLS"
                        return result

                    # Parse certificate cryptographically
                    parsed = self._parse_x509_der(der_cert, domain_or_host)
                    result.update(parsed)

        except socket.timeout:
            result["error_message"] = "Connection timed out during TLS handshake"
            result["status_category"] = "TIMEOUT"
        except ConnectionRefusedError:
            result["error_message"] = f"Connection refused on port {port}"
            result["status_category"] = "CONNECTION_FAILED"
        except ssl.SSLError as ssl_err:
            result["error_message"] = f"TLS handshake error: {str(ssl_err)}"
            result["status_category"] = "HANDSHAKE_FAILED"
        except Exception as e:
            result["error_message"] = f"TLS check failed: {str(e)}"
            result["status_category"] = "CONNECTION_FAILED"

        return result

    def _parse_x509_der(self, der_bytes: bytes, target_label: str) -> Dict[str, Any]:
        """Parses DER bytes and calculates exact expiry days relative to UTC."""
        out = {}
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
            now = datetime.now(timezone.utc)

            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            time_diff = not_after - now
            days_remaining = time_diff.days
            is_expired = 1 if now > not_after else 0
            is_valid = 1 if (now >= not_before and now <= not_after) else 0

            # Subject Common Name
            subject_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            subject_cn = subject_attrs[0].value if subject_attrs else "Unknown Subject"

            # Issuer Organization or Common Name
            issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if not issuer_attrs:
                issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer_name = issuer_attrs[0].value if issuer_attrs else "Unknown Issuer"

            # Subject Alternative Names
            sans: List[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = [name.value for name in san_ext.value if hasattr(name, 'value')]
            except x509.ExtensionNotFound:
                sans = []

            # Serial and Signature Algo
            serial = hex(cert.serial_number)
            algo = getattr(cert.signature_algorithm_oid, '_name', str(cert.signature_algorithm_oid))

            status_cat = "VALID"
            if is_expired:
                status_cat = "EXPIRED"
            elif days_remaining <= CERT_EXPIRY_WARNING_DAYS:
                status_cat = "EXPIRING_SOON"

            out = {
                "is_valid": is_valid,
                "is_expired": is_expired,
                "days_to_expiry": days_remaining,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "issuer": issuer_name,
                "subject": subject_cn,
                "sans": json.dumps(sans),
                "signature_algo": algo,
                "serial_number": serial,
                "status_category": status_cat,
                "error_message": None
            }
        except Exception as e:
            out["error_message"] = f"Failed to parse X.509 certificate: {str(e)}"
            out["status_category"] = "PARSE_ERROR"

        return out
