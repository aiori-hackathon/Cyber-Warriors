"""
Check 1: DNS Records Monitoring and Dangling CNAME Candidate Detection.

Purpose:
  Retrieves and catalogs public DNS records (A, AAAA, CNAME, MX) for approved lab domains,
  monitors record modifications, and flags potential dangling CNAME records for manual verification.

Inputs:
  - domain (str): Target domain in approved scope.
  - timeout (float): Query timeout in seconds.

Outputs:
  - List of records with fields: record_type, value, ttl, is_dangling_candidate, dangling_provider, dangling_reason.

Limitations & Safety:
  - Bounded to approved scope only.
  - Non-intrusive DNS queries only.
  - Does NOT claim a record is exploitable merely because destination fails to resolve.
  - Handles timeouts, SERVFAIL, and NXDOMAIN gracefully without crashing.
"""

import socket
import re
from typing import List, Dict, Any, Tuple, Optional
import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from config import DEFAULT_DNS_TIMEOUT, DANGLING_DNS_PROVIDERS, DEFAULT_USER_AGENT
from modules.scope_manager import ScopeManager


class DNSChecker:
    def __init__(self, timeout: float = DEFAULT_DNS_TIMEOUT):
        self.timeout = timeout
        if HAS_DNSPYTHON:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
        else:
            self.resolver = None

    def check_domain_dns(self, domain: str) -> List[Dict[str, Any]]:
        """
        Executes Check 1: DNS records lookup and dangling CNAME analysis on an approved domain.
        Enforces scope validation prior to execution.
        """
        ScopeManager.verify_target_in_scope(domain, "domain")
        domain = domain.strip().lower()

        results: List[Dict[str, Any]] = []
        record_types = ["A", "AAAA", "CNAME", "MX"]

        for rtype in record_types:
            records = self._query_record_type(domain, rtype)
            for rec in records:
                # If CNAME, check if it points to an unallocated or decommissioned cloud asset
                if rtype == "CNAME":
                    is_dangling, provider, reason = self.evaluate_dangling_cname(domain, rec["value"])
                    if is_dangling:
                        rec["is_dangling_candidate"] = 1
                        rec["dangling_provider"] = provider
                        rec["dangling_reason"] = reason

                results.append(rec)

        return results

    def _query_record_type(self, domain: str, rtype: str) -> List[Dict[str, Any]]:
        """Queries DNS records using dnspython with fallback to socket."""
        records: List[Dict[str, Any]] = []

        if HAS_DNSPYTHON and self.resolver:
            try:
                answers = self.resolver.resolve(domain, rtype)
                ttl = answers.rrset.ttl if answers.rrset else 300
                for rdata in answers:
                    val = rdata.to_text().strip('"').rstrip('.')
                    records.append({
                        "domain": domain,
                        "record_type": rtype,
                        "value": val,
                        "ttl": ttl,
                        "is_dangling_candidate": 0,
                        "dangling_provider": None,
                        "dangling_reason": None,
                        "error": None
                    })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # Normal condition when record type doesn't exist
                pass
            except dns.exception.Timeout:
                records.append({
                    "domain": domain,
                    "record_type": rtype,
                    "value": "TIMEOUT",
                    "ttl": 0,
                    "is_dangling_candidate": 0,
                    "error": "DNS query timed out"
                })
            except Exception as e:
                # Other non-fatal DNS errors
                pass
        else:
            # Socket fallback for A records
            if rtype == "A":
                try:
                    infos = socket.getaddrinfo(domain, None, socket.AF_INET)
                    seen = set()
                    for item in infos:
                        ip = item[4][0]
                        if ip not in seen:
                            seen.add(ip)
                            records.append({
                                "domain": domain,
                                "record_type": "A",
                                "value": ip,
                                "ttl": 300,
                                "is_dangling_candidate": 0,
                                "dangling_provider": None,
                                "dangling_reason": None,
                                "error": None
                            })
                except Exception:
                    pass

        return records

    def evaluate_dangling_cname(self, original_domain: str, cname_target: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Assesses whether a CNAME target exhibits symptoms of an orphaned cloud resource.
        Responsible verification standard: Never executes takeovers; flags candidate for review.
        """
        cname_lower = cname_target.lower().strip()
        matched_provider = None

        # 1. Match against known cloud provider patterns
        for provider, info in DANGLING_DNS_PROVIDERS.items():
            for pattern in info["domains"]:
                if re.search(pattern, cname_lower):
                    matched_provider = provider
                    break
            if matched_provider:
                break

        # 2. Check target resolution (NXDOMAIN test)
        target_resolves = self._check_target_resolves(cname_target)
        if not target_resolves:
            if matched_provider:
                return (
                    True,
                    matched_provider,
                    f"CNAME points to {matched_provider} target '{cname_target}' which returns NXDOMAIN (potential decommissioned resource)."
                )
            else:
                return (
                    True,
                    "Generic External Target",
                    f"CNAME destination '{cname_target}' fails DNS resolution (NXDOMAIN). Manual verification recommended."
                )

        # 3. Non-intrusive HTTP signature verification for active cloud edge endpoints
        if matched_provider:
            is_orphaned, reason = self._probe_unclaimed_signature(cname_target, matched_provider, original_domain)
            if is_orphaned:
                return True, matched_provider, reason

        return False, None, None

    def _check_target_resolves(self, target: str) -> bool:
        """Checks if a target hostname resolves to an IP address."""
        try:
            socket.gethostbyname(target)
            return True
        except (socket.gaierror, socket.herror):
            return False

    def _probe_unclaimed_signature(self, cname_target: str, provider: str, original_domain: str) -> Tuple[bool, Optional[str]]:
        """
        Transmits a safe diagnostic HTTP GET request to inspect for unmapped resource signatures.
        """
        provider_info = DANGLING_DNS_PROVIDERS.get(provider)
        if not provider_info:
            return False, None

        signatures = provider_info.get("signatures", [])
        headers = {
            "Host": original_domain,
            "User-Agent": DEFAULT_USER_AGENT
        }

        for scheme in ["http", "https"]:
            url = f"{scheme}://{cname_target}/"
            try:
                # Security rationale for verify=False:
                # Decommissioned cloud targets (S3, GitHub Pages, etc.) frequently present mismatched
                # certificates on CDN endpoints. Disabling verification allows reading the diagnostic
                # error body (e.g., 'NoSuchBucket') without aborting. Cryptographic certificate auditing
                # is independently handled by Check 2 (TLSChecker).
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                    resp = requests.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
                body = resp.text
                for sig in signatures:
                    if sig.lower() in body.lower():
                        return (
                            True,
                            f"Target response contains {provider} orphan signature: '{sig}' with HTTP status {resp.status_code}."
                        )
            except Exception:
                continue

        return False, None
