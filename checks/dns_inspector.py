"""
DNS Inspector module for Authorised Attack-Surface Inventory and Change Monitor.
Catalogs public DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA) and inspects for
Potential Dangling DNS records pointing to decommissioned/unclaimed cloud assets.
Adheres strictly to the non-exploitation policy mandated by AIORI-3 PS-011.
"""

import socket
import re
from typing import List, Dict, Any, Optional, Tuple
import requests

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from core.models import DNSRecord, DomainAsset
from core.scope_guard import ScopeGuard


class DNSInspector:
    # Known cloud provider CNAME targets and their orphaned signatures
    CLOUD_PROVIDER_PATTERNS = {
        "AWS S3": {
            "domains": [r"s3[\w-]*\.amazonaws\.com", r"s3-website[\w-]*\.amazonaws\.com"],
            "signatures": ["NoSuchBucket", "The specified bucket does not exist"]
        },
        "AWS Elastic Beanstalk": {
            "domains": [r"elasticbeanstalk\.com"],
            "signatures": ["NXDOMAIN"]
        },
        "AWS CloudFront": {
            "domains": [r"cloudfront\.net"],
            "signatures": ["Bad request", "CloudFront", "NoSuchDistribution"]
        },
        "GitHub Pages": {
            "domains": [r"github\.io"],
            "signatures": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"]
        },
        "Azure App Service": {
            "domains": [r"azurewebsites\.net", r"trafficmanager\.net", r"cloudapp\.azure\.com"],
            "signatures": ["404 Web Site not found", "app service not found"]
        },
        "Heroku": {
            "domains": [r"herokuapp\.com", r"herokussl\.com"],
            "signatures": ["No such app", "herokucdn.com/error-pages/no-such-app.html"]
        },
        "Shopify": {
            "domains": [r"myshopify\.com"],
            "signatures": ["Sorry, this shop is currently unavailable"]
        },
        "Fastly": {
            "domains": [r"fastly\.net"],
            "signatures": ["Fastly error: unknown domain"]
        },
        "Pantheon": {
            "domains": [r"pantheonsite\.io"],
            "signatures": ["The gods are wise, but do not know of the site you are looking for"]
        }
    }

    def __init__(self, scope_guard: Optional[ScopeGuard] = None, timeout: float = 3.0):
        self.scope_guard = scope_guard or ScopeGuard()
        self.timeout = timeout
        if HAS_DNSPYTHON:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
        else:
            self.resolver = None

    def inspect_domain(self, domain: str) -> DomainAsset:
        """
        Catalogs all DNS records for an authorised domain and performs dangling DNS checks.
        """
        self.scope_guard.validate_domain(domain)
        
        asset = DomainAsset(domain=domain)
        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
        
        all_records: List[DNSRecord] = []
        resolved_ips: List[str] = []
        
        for rtype in record_types:
            records = self._query_record(domain, rtype)
            for r in records:
                all_records.append(r)
                if rtype in ["A", "AAAA"] and r.value:
                    resolved_ips.append(r.value)
                
                # Check for dangling CNAME
                if rtype == "CNAME":
                    is_dangling, provider, reason = self.check_dangling_cname(domain, r.value)
                    if is_dangling:
                        r.is_dangling_candidate = True
                        r.dangling_provider = provider
                        r.dangling_reason = reason
                        asset.has_dangling_records = True
                        asset.dangling_candidates.append({
                            "domain": domain,
                            "cname_target": r.value,
                            "provider": provider,
                            "reason": reason
                        })
        
        asset.dns_records = all_records
        asset.resolved_ips = list(set(resolved_ips))
        return asset

    def _query_record(self, domain: str, record_type: str) -> List[DNSRecord]:
        results: List[DNSRecord] = []
        if HAS_DNSPYTHON and self.resolver:
            try:
                answers = self.resolver.resolve(domain, record_type)
                ttl = answers.rrset.ttl if answers.rrset else 300
                for rdata in answers:
                    val = rdata.to_text().strip('"').rstrip('.')
                    results.append(DNSRecord(
                        record_type=record_type,
                        name=domain,
                        value=val,
                        ttl=ttl,
                        cname_target=val if record_type == "CNAME" else None
                    ))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception:
                pass
        else:
            # Fallback to standard library socket for A records
            if record_type == "A":
                try:
                    infos = socket.getaddrinfo(domain, None, socket.AF_INET)
                    seen = set()
                    for item in infos:
                        ip = item[4][0]
                        if ip not in seen:
                            seen.add(ip)
                            results.append(DNSRecord(
                                record_type="A",
                                name=domain,
                                value=ip,
                                ttl=300
                            ))
                except Exception:
                    pass
        return results

    def check_dangling_cname(self, domain: str, cname_target: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Assesses if a CNAME points to an unclaimed/decommissioned cloud resource.
        Responsible verification only: NO exploitation or unauthorized takeover claims.
        """
        cname_lower = cname_target.lower().strip()
        matched_provider = None
        
        # 1. Match against known cloud provider patterns
        for provider, info in self.CLOUD_PROVIDER_PATTERNS.items():
            for pattern in info["domains"]:
                if re.search(pattern, cname_lower):
                    matched_provider = provider
                    break
            if matched_provider:
                break
                
        if not matched_provider:
            # Generic CNAME target: check if it resolves at all
            target_resolves = self._check_target_resolution(cname_target)
            if not target_resolves:
                return True, "Generic External Target", f"CNAME target '{cname_target}' does not resolve (NXDOMAIN)."
            return False, None, None

        # 2. Check target resolution (NXDOMAIN test)
        target_resolves = self._check_target_resolution(cname_target)
        if not target_resolves:
            return True, matched_provider, f"CNAME points to {matched_provider} target '{cname_target}' which returns NXDOMAIN (Unregistered/Decommissioned)."

        # 3. Safe non-exploitative HTTP signature verification
        # Inspect HTTP response from target to see if the cloud service reports unmapped/unregistered bucket or tenant
        is_orphaned, reason = self._probe_cloud_signature(cname_target, matched_provider, domain)
        if is_orphaned:
            return True, matched_provider, reason

        return False, None, None

    def _check_target_resolution(self, target: str) -> bool:
        """Determines if a target hostname resolves to an IP address."""
        try:
            socket.gethostbyname(target)
            return True
        except (socket.gaierror, socket.herror):
            return False

    def _probe_cloud_signature(self, cname_target: str, provider: str, original_domain: str) -> Tuple[bool, Optional[str]]:
        """
        Sends a safe, non-exploitative HTTP GET to test for cloud provider "resource not found / unclaimed" signatures.
        """
        provider_info = self.CLOUD_PROVIDER_PATTERNS.get(provider)
        if not provider_info:
            return False, None
            
        signatures = provider_info.get("signatures", [])
        
        # Test HTTP and HTTPS safely
        for scheme in ["http", "https"]:
            url = f"{scheme}://{cname_target}/"
            try:
                resp = requests.get(
                    url,
                    headers={
                        "Host": original_domain,
                        "User-Agent": "AIORI-ASM-Monitor/1.0 (Authorised Security Research)"
                    },
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                body = resp.text
                for sig in signatures:
                    if sig.lower() in body.lower():
                        return True, f"Target matches {provider} unlinked signature: '{sig}' with HTTP {resp.status_code}"
            except Exception:
                continue
                
        return False, None
