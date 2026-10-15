"""
Scope Guard module for Authorised Attack-Surface Inventory and Change Monitor.
Enforces strict boundaries adhering to hackathon mandate:
- Use only written, organiser-approved target scope.
- Enforce limit of up to 20 lab domains and 10 hosts.
- Reject any out-of-scope probes or unrestricted scans.
- Enforce non-exploitation safety policy.
"""

import json
import ipaddress
from pathlib import Path
from typing import List, Dict, Any, Optional


class ScopeViolationError(Exception):
    """Raised when an attempt is made to scan or probe an unapproved target."""
    pass


class ScopePolicyViolationError(Exception):
    """Raised when an action violates safety guardrails (e.g. exploitation attempt)."""
    pass


class ScopeGuard:
    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            config_path = Path(__file__).resolve().parent.parent / "config" / "scope.json"
        
        self.config_path = Path(config_path)
        self.config_data = self._load_scope()
        self.metadata = self.config_data.get("metadata", {})
        self.policy = self.config_data.get("policy", {})
        
        targets = self.config_data.get("approved_targets", {})
        # Enforce limits: max 20 domains and 10 hosts as specified in key requirements
        raw_domains = targets.get("domains", [])
        raw_hosts = targets.get("hosts", [])
        
        self.approved_domains = [d.strip().lower() for d in raw_domains[:20]]
        self.approved_hosts = [h.strip() for h in raw_hosts[:10]]
        self.approved_ports = set(targets.get("ports_to_inspect", [80, 443]))
        self.baseline_approved_services = self.config_data.get("baseline_approved_services", {})

    def _load_scope(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Scope configuration file not found at: {self.config_path}")
        with open(self.config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def is_domain_in_scope(self, domain: str) -> bool:
        domain = domain.strip().lower()
        if not self.policy.get("enforce_strict_scope", True):
            return True
        for approved in self.approved_domains:
            if domain == approved or domain.endswith("." + approved):
                return True
        return False

    def is_host_in_scope(self, host: str) -> bool:
        host = host.strip()
        if not self.policy.get("enforce_strict_scope", True):
            return True
        if host in self.approved_hosts:
            return True
        
        # Check IP network ranges if defined
        try:
            target_ip = ipaddress.ip_address(host)
            for approved in self.approved_hosts:
                try:
                    if "/" in approved and target_ip in ipaddress.ip_network(approved, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def validate_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        if not self.is_domain_in_scope(domain):
            raise ScopeViolationError(
                f"[SCOPE REJECTION] Domain '{domain}' is NOT in the organiser-approved target scope! "
                f"Scanning restricted targets is strictly forbidden."
            )
        return domain

    def validate_host(self, host: str) -> str:
        host = host.strip()
        if not self.is_host_in_scope(host):
            raise ScopeViolationError(
                f"[SCOPE REJECTION] Host/IP '{host}' is NOT in the organiser-approved target scope! "
                f"Scanning restricted targets is strictly forbidden."
            )
        return host

    def validate_action_safety(self, action_name: str):
        if action_name.lower() in ["exploit", "takeover", "bruteforce", "payload_injection"]:
            raise ScopePolicyViolationError(
                f"[POLICY REJECTION] Action '{action_name}' is forbidden by project safety guidelines. "
                f"Mandate strictly specifies: No exploitation or claims that every dangling record is exploitable."
            )

    def is_service_expected(self, host: str, port: int) -> bool:
        """Checks if a port is in the host's approved baseline services."""
        approved_for_host = self.baseline_approved_services.get(host)
        if approved_for_host is None:
            # Fallback to general allowed ports
            return port in [80, 443]
        return port in approved_for_host

    def get_approved_domains(self) -> List[str]:
        return list(self.approved_domains)

    def get_approved_hosts(self) -> List[str]:
        return list(self.approved_hosts)

    def get_approved_ports(self) -> List[int]:
        return sorted(list(self.approved_ports))
