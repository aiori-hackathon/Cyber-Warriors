"""
TLS Certificate Inspector module for Authorised Attack-Surface Inventory and Change Monitor.
Verifies TLS certificate validity, expiration dates, subject alternative names (SANs),
and flags expired or impending-expiration certificates as mandated by AIORI-3 PS-011.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional, List
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

from core.models import TLSCertificate
from core.scope_guard import ScopeGuard


class TLSInspector:
    def __init__(self, scope_guard: Optional[ScopeGuard] = None, timeout: float = 3.5):
        self.scope_guard = scope_guard or ScopeGuard()
        self.timeout = timeout

    def inspect_tls(self, host_or_domain: str, port: int = 443) -> TLSCertificate:
        """
        Inspects TLS certificate on the target domain/host.
        Performs SNI handshake and extracts full cryptographic metadata.
        """
        cert_result = TLSCertificate(domain=host_or_domain, port=port)
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Read certificate even if expired or untrusted
        
        try:
            with socket.create_connection((host_or_domain, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host_or_domain) as ssock:
                    cert_result.tls_version = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cert_result.cipher_suite = cipher_info[0]
                    
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        cert_result.error_message = "No peer certificate returned by server"
                        return cert_result
                    
                    parsed = self.parse_der_certificate(der_cert, host_or_domain, port)
                    if parsed:
                        parsed.tls_version = cert_result.tls_version
                        parsed.cipher_suite = cert_result.cipher_suite
                        return parsed
                        
        except (ssl.SSLError, socket.error, TimeoutError) as e:
            cert_result.error_message = f"TLS handshake failed: {str(e)}"
        except Exception as e:
            cert_result.error_message = f"TLS inspection error: {str(e)}"
            
        return cert_result

    @staticmethod
    def parse_der_certificate(der_bytes: bytes, target_domain: str, port: int = 443) -> Optional[TLSCertificate]:
        """
        Parses binary DER X.509 certificate using the cryptography library.
        Accurately calculates expiration status, days remaining, SANs, and issuer.
        """
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
            now = datetime.now(timezone.utc)
            
            # Validity boundaries
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            
            time_diff = not_after - now
            days_remaining = time_diff.days
            is_expired = now > not_after
            is_valid = (now >= not_before) and (now <= not_after)
            
            # Subject Common Name
            subject_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            subject_cn = subject_attrs[0].value if subject_attrs else "Unknown Subject"
            
            # Issuer
            issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if not issuer_attrs:
                issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer_name = issuer_attrs[0].value if issuer_attrs else "Unknown Issuer"
            
            # Subject Alternative Names (SANs)
            sans: List[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = [name.value for name in san_ext.value if hasattr(name, 'value')]
            except x509.ExtensionNotFound:
                sans = []
            
            # Serial Number & Algorithm
            serial = hex(cert.serial_number)
            algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
            
            return TLSCertificate(
                domain=target_domain,
                port=port,
                is_valid=is_valid,
                is_expired=is_expired,
                days_to_expiry=days_remaining,
                not_before=not_before.isoformat(),
                not_after=not_after.isoformat(),
                issuer=issuer_name,
                subject=subject_cn,
                sans=sans,
                signature_algorithm=algo,
                serial_number=serial,
                error_message=None
            )
        except Exception as e:
            return TLSCertificate(
                domain=target_domain,
                port=port,
                error_message=f"Failed to parse DER certificate: {str(e)}"
            )
