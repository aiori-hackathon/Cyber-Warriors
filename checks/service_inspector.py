"""
Service Inspector module for Authorised Attack-Surface Inventory and Change Monitor.
Implements the 4 DOCUMENTED CHECKS mandated by AIORI-3 PS-011:
  - Check 1: TCP Port State & Latency Probe (RFC 793)
  - Check 2: Service Banner Grab & Protocol Fingerprint
  - Check 3: TLS/SSL Handshake & Negotiation Probe
  - Check 4: Application-Layer HTTP/HTTPS Inspection
"""

import socket
import ssl
import time
import re
import urllib.parse
from typing import Optional, Dict, Any, Tuple
import requests

from core.models import PortScanResult, TLSCertificate
from core.scope_guard import ScopeGuard


class ServiceInspector:
    def __init__(self, scope_guard: Optional[ScopeGuard] = None, timeout: float = 3.0):
        self.scope_guard = scope_guard or ScopeGuard()
        self.timeout = timeout
        self.user_agent = "AIORI-ASM-Monitor/1.0 (Authorised Security Research; +https://github.com/aiori-hackathon)"

    def inspect_port(self, host: str, port: int, domain_hint: Optional[str] = None) -> PortScanResult:
        """
        Executes all 4 documented checks on a target host and port.
        Enforces scope validation prior to initiation.
        """
        # Validate scope
        self.scope_guard.validate_host(host)
        
        result = PortScanResult(host=host, port=port)
        
        # Check 1: TCP Port State & Connection Probe
        is_open, latency = self.check_1_tcp_connect(host, port)
        result.latency_ms = latency
        if not is_open:
            result.state = "CLOSED"
            return result
        
        result.state = "OPEN"
        
        # Determine whether port is unexpected according to baseline policy
        result.is_unexpected = not self.scope_guard.is_service_expected(host, port)
        
        # Check 2: Service Banner Grab & Protocol Fingerprint
        banner, identified_service = self.check_2_banner_grab(host, port)
        result.banner = banner
        result.identified_service = identified_service
        
        # Check 3: TLS/SSL Handshake & Negotiation Probe
        sni_target = domain_hint or host
        has_tls, tls_version, cipher, cert = self.check_3_tls_negotiation(host, port, sni_target)
        result.has_tls = has_tls
        result.tls_version = tls_version
        result.cipher = cipher
        result.certificate = cert
        
        # Check 4: Application-Layer HTTP/HTTPS Inspection
        http_data = self.check_4_http_inspection(host, port, has_tls, domain_hint)
        if http_data.get("is_http"):
            result.is_http = True
            result.http_status = http_data.get("status")
            result.http_title = http_data.get("title")
            result.server_header = http_data.get("server")
            result.tech_stack = http_data.get("tech_stack", [])
            result.security_headers = http_data.get("security_headers", {})
            if not result.identified_service:
                result.identified_service = "HTTPS" if has_tls else "HTTP"
        
        return result

    # --------------------------------------------------------------------------
    # CHECK 1: TCP Port State & Latency Probe
    # --------------------------------------------------------------------------
    def check_1_tcp_connect(self, host: str, port: int) -> Tuple[bool, Optional[float]]:
        """
        [CHECK 1] TCP Port State & Latency Probe (RFC 793)
        Performs a full TCP three-way handshake (SYN-SYN/ACK-ACK) using non-blocking socket connect.
        Measures millisecond round-trip time.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        start_time = time.perf_counter()
        try:
            err = s.connect_ex((host, port))
            latency = round((time.perf_counter() - start_time) * 1000, 2)
            if err == 0:
                return True, latency
            return False, None
        except socket.timeout:
            return False, None
        except Exception:
            return False, None
        finally:
            try:
                s.close()
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # CHECK 2: Service Banner Grab & Protocol Fingerprint
    # --------------------------------------------------------------------------
    def check_2_banner_grab(self, host: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """
        [CHECK 2] Service Banner Grab & Protocol Fingerprint
        Connects and passively listens for greeting banners (e.g. SSH, SMTP, FTP).
        If no passive banner is received, transmits a safe generic probe (\\r\\n)
        and parses raw responses with regex heuristics to identify protocol and version.
        """
        banner_clean: Optional[str] = None
        service: Optional[str] = None
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect((host, port))
            # Try passive read first
            try:
                data = s.recv(1024)
            except socket.timeout:
                # Active gentle probe
                s.sendall(b"\r\n\r\n")
                try:
                    data = s.recv(1024)
                except socket.timeout:
                    data = b""
            
            if data:
                raw_text = data.decode("utf-8", errors="replace").strip()
                banner_clean = raw_text[:200]  # truncate for safe logging
                
                # Fingerprint matching
                if re.search(r"^SSH-\d", raw_text, re.IGNORECASE):
                    service = "SSH"
                elif re.search(r"^220.*FTP", raw_text, re.IGNORECASE):
                    service = "FTP"
                elif re.search(r"^220.*SMTP|ESMTP", raw_text, re.IGNORECASE):
                    service = "SMTP"
                elif "redis_version" in raw_text or raw_text.startswith("-ERR"):
                    service = "Redis"
                elif "mysql" in raw_text.lower():
                    service = "MySQL"
                elif raw_text.startswith("HTTP/"):
                    service = "HTTP"
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
                
        # Common port fallbacks if banner was quiet
        if not service:
            port_map = {
                22: "SSH", 21: "FTP", 25: "SMTP", 53: "DNS",
                80: "HTTP", 443: "HTTPS", 3306: "MySQL",
                5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
                8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9090: "Prometheus/Metrics"
            }
            service = port_map.get(port)
            
        return banner_clean, service

    # --------------------------------------------------------------------------
    # CHECK 3: TLS/SSL Handshake & Negotiation Probe
    # --------------------------------------------------------------------------
    def check_3_tls_negotiation(
        self, host: str, port: int, sni_domain: str
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[TLSCertificate]]:
        """
        [CHECK 3] TLS/SSL Handshake & Negotiation Probe
        Attempts standard TLS handshake with Server Name Indication (SNI).
        Extracts negotiated protocol (e.g. TLSv1.3, TLSv1.2) and cipher suite.
        Passes peer certificate for full cryptographic chain & expiration verification.
        """
        if port not in [443, 8443, 9443] and not ("443" in str(port)):
            # Check only ports commonly or opportunistically TLS
            # Test with a quick probe to see if it responds to TLS ClientHello
            pass

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Authorised inventory must read even self-signed or expired certs!
        
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni_domain) as ssock:
                    tls_ver = ssock.version()
                    cipher_info = ssock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else None
                    
                    # Inspect cert details
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert_obj = None
                    if der_cert:
                        from checks.tls_inspector import TLSInspector
                        cert_obj = TLSInspector.parse_der_certificate(der_cert, sni_domain, port)
                        if cert_obj:
                            cert_obj.tls_version = tls_ver
                            cert_obj.cipher_suite = cipher_name
                    
                    return True, tls_ver, cipher_name, cert_obj
        except (ssl.SSLError, socket.error):
            return False, None, None, None
        except Exception:
            return False, None, None, None

    # --------------------------------------------------------------------------
    # CHECK 4: Application-Layer HTTP/HTTPS Inspection
    # --------------------------------------------------------------------------
    def check_4_http_inspection(
        self, host: str, port: int, has_tls: bool, domain_hint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        [CHECK 4] Application-Layer HTTP/HTTPS Inspection
        Performs an authenticated/authorised safe HTTP probe (GET).
        Inspects:
          - HTTP Status Code & Redirects
          - Web Application HTML Title (<title>...</title>)
          - Server Banner & Technology stack disclosure (X-Powered-By, Server)
          - Defensive posture (HSTS, CSP, X-Frame-Options)
        """
        protocol = "https" if has_tls or port in [443, 8443] else "http"
        host_header = domain_hint if domain_hint else host
        url = f"{protocol}://{host}:{port}/"
        
        headers = {
            "User-Agent": self.user_agent,
            "Host": host_header,
            "Accept": "text/html,application/xhtml+xml,application/json,*/*"
        }
        
        out: Dict[str, Any] = {
            "is_http": False,
            "status": None,
            "title": None,
            "server": None,
            "tech_stack": [],
            "security_headers": {}
        }
        
        try:
            # Safe non-exploitative request with 3 second timeout and no verification rejection
            resp = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                stream=True
            )
            out["is_http"] = True
            out["status"] = resp.status_code
            out["server"] = resp.headers.get("Server")
            
            # Extract title from first 8KB of content
            raw_chunk = b""
            for chunk in resp.iter_content(chunk_size=4096):
                raw_chunk += chunk
                if len(raw_chunk) >= 8192:
                    break
            
            html_text = raw_chunk.decode("utf-8", errors="replace")
            m = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
            if m:
                out["title"] = m.group(1).strip()[:120]
            
            # Security headers check
            for sec_h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
                if sec_h in resp.headers:
                    out["security_headers"][sec_h] = resp.headers[sec_h]
            
            # Technology discovery
            techs = []
            if "X-Powered-By" in resp.headers:
                techs.append(f"Powered-By: {resp.headers['X-Powered-By']}")
            if out["server"]:
                techs.append(f"Server: {out['server']}")
            if "flask" in html_text.lower() or "werkzeug" in (out["server"] or "").lower():
                techs.append("Flask/Python")
            if "express" in html_text.lower() or "express" in (resp.headers.get("X-Powered-By") or "").lower():
                techs.append("Express.js")
            if "nginx" in (out["server"] or "").lower():
                techs.append("Nginx")
            if "apache" in (out["server"] or "").lower():
                techs.append("Apache HTTPD")
            out["tech_stack"] = list(set(techs))
            
        except requests.exceptions.RequestException:
            out["is_http"] = False
        except Exception:
            out["is_http"] = False
            
        return out
