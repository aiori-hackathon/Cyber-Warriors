"""
Check 3: Selected TCP Ports and Services Monitoring.

Purpose:
  Inspects only explicitly configured ports on approved lab hosts, records reachability
  (OPEN/CLOSED/FILTERED) and round-trip latency, identifies running application protocols/banners,
  and identifies unexpected open services when compared against approved baseline policies.

Inputs:
  - host_ip (str): Approved host IP address.
  - ports (List[int]): Documented list of ports to inspect.
  - timeout (float): Socket connect timeout.

Outputs:
  - List of port observation dictionaries: port, state, latency_ms, service_name, banner,
    is_http, http_status, http_title, server_header, is_unexpected.

Limitations & Safety:
  - Strictly restricted to documented allowlist of ports on approved hosts.
  - Never performs brute-force attacks, exploitation, or vulnerability probing.
  - Standard RFC 793 TCP connect handshake only.
"""

import socket
import re
import json
from typing import List, Dict, Any, Tuple, Optional
import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning

from config import (
    DEFAULT_SOCKET_TIMEOUT, DEFAULT_APPROVED_PORTS, DEFAULT_BASELINE_SERVICES,
    DEFAULT_USER_AGENT
)
from modules.scope_manager import ScopeManager


class PortChecker:
    def __init__(self, timeout: float = DEFAULT_SOCKET_TIMEOUT):
        self.timeout = timeout
        self.baseline_matrix = DEFAULT_BASELINE_SERVICES

    def inspect_host_ports(self, host_ip: str, port_list: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """
        Executes Check 3: Port and Service inspection on an approved host.
        Enforces scope validation prior to execution.
        """
        ScopeManager.verify_target_in_scope(host_ip, "host")
        ports_to_check = port_list or DEFAULT_APPROVED_PORTS

        results: List[Dict[str, Any]] = []

        for port in ports_to_check:
            obs = self.check_single_port(host_ip, port)
            results.append(obs)

        return results

    def check_single_port(self, host_ip: str, port: int) -> Dict[str, Any]:
        """Performs connection probe, banner grab, and application-layer inspection on a single port."""
        obs = {
            "host_ip": host_ip,
            "port": port,
            "protocol": "TCP",
            "state": "CLOSED",
            "latency_ms": None,
            "service_name": None,
            "banner": None,
            "is_http": 0,
            "http_status": None,
            "http_title": None,
            "server_header": None,
            "tech_stack": json.dumps([]),
            "security_headers": json.dumps({}),
            "is_unexpected": 0
        }

        # 1. TCP Connect Handshake (RFC 793)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        import time
        t_start = time.perf_counter()
        try:
            err = s.connect_ex((host_ip, port))
            latency = round((time.perf_counter() - t_start) * 1000, 2)
            if err == 0:
                obs["state"] = "OPEN"
                obs["latency_ms"] = latency
            else:
                obs["state"] = "CLOSED"
                return obs
        except socket.timeout:
            obs["state"] = "FILTERED"
            return obs
        except Exception:
            obs["state"] = "CLOSED"
            return obs
        finally:
            try:
                s.close()
            except Exception:
                pass

        # 2. Check if port is unexpected for this host in baseline policy
        approved_ports = self.baseline_matrix.get(host_ip, [80, 443])
        if port not in approved_ports:
            obs["is_unexpected"] = 1

        # 3. Banner Grab & Service Fingerprint
        banner, service = self._grab_banner(host_ip, port)
        obs["banner"] = banner
        obs["service_name"] = service

        # 4. HTTP Application Probe (if web port or potential HTTP)
        if port in [80, 443, 8080, 8443, 8888, 9090] or (banner and "HTTP" in banner):
            http_info = self._probe_http(host_ip, port)
            if http_info.get("is_http"):
                obs["is_http"] = 1
                obs["http_status"] = http_info.get("status")
                obs["http_title"] = http_info.get("title")
                obs["server_header"] = http_info.get("server")
                obs["tech_stack"] = json.dumps(http_info.get("tech_stack", []))
                obs["security_headers"] = json.dumps(http_info.get("security_headers", {}))
                if not obs["service_name"]:
                    obs["service_name"] = "HTTPS" if port in [443, 8443] else "HTTP"

        return obs

    def _grab_banner(self, host: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """Passively reads initial greeting or sends safe carriage-return probe."""
        banner_clean = None
        service = None

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect((host, port))
            try:
                data = s.recv(1024)
            except socket.timeout:
                s.sendall(b"\r\n\r\n")
                try:
                    data = s.recv(1024)
                except socket.timeout:
                    data = b""

            if data:
                raw_text = data.decode("utf-8", errors="replace").strip()
                banner_clean = raw_text[:200]

                if re.search(r"^SSH-\d", raw_text, re.IGNORECASE):
                    service = "SSH"
                elif re.search(r"^220.*FTP", raw_text, re.IGNORECASE):
                    service = "FTP"
                elif re.search(r"^220.*SMTP", raw_text, re.IGNORECASE):
                    service = "SMTP"
                elif "redis" in raw_text.lower():
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

        if not service:
            well_known = {
                22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
                443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
                6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
                8888: "HTTP-Dev", 9090: "Prometheus-Metrics"
            }
            service = well_known.get(port, "TCP-Service")

        return banner_clean, service

    def _probe_http(self, host: str, port: int) -> Dict[str, Any]:
        """Performs authorized safe GET probe to catalog web metadata."""
        scheme = "https" if port in [443, 8443] else "http"
        url = f"{scheme}://{host}:{port}/"
        headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/json,*/*"
        }
        out = {"is_http": False}
        try:
            # Security rationale for verify=False:
            # Internal lab endpoints (e.g. 10.0.1.15:8443) frequently use self-signed certificates or
            # private internal CAs. Disabling verification enables banner and application metadata
            # collection on newly discovered ports without aborting on untrusted certs.
            # Dedicated cryptographic validation is performed separately by Check 2 (TLSChecker).
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                resp = requests.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            out["is_http"] = True
            out["status"] = resp.status_code
            out["server"] = resp.headers.get("Server")

            # Extract title
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:8192], re.IGNORECASE | re.DOTALL)
            out["title"] = m.group(1).strip()[:100] if m else None

            # Tech stack heuristics
            tech = []
            if out["server"]:
                tech.append(out["server"])
            if "X-Powered-By" in resp.headers:
                tech.append(resp.headers["X-Powered-By"])
            out["tech_stack"] = list(set(tech))

            # Security headers
            sec_headers = {}
            for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
                if h in resp.headers:
                    sec_headers[h] = resp.headers[h]
            out["security_headers"] = sec_headers
        except Exception:
            pass
        return out
