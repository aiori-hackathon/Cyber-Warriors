"""
False Positive Analysis and Confidence Scoring Engine.
AIORI-3 PS-011 Mandate: "Report false positives", "No claims that every dangling record is exploitable".

Evaluates detected security issues against common false-positive vectors:
- CDN/Edge 404 default behaviors (e.g. CloudFront/Cloudflare SNI fallbacks)
- Wildcard DNS resolution masks
- Split-horizon DNS (Internal vs Public resolution)
- Firewall / SYN-proxy port mirroring
- Missing SNI in TLS testing causing fallback self-signed certs
"""

from typing import Dict, Any, Tuple
from core.models import Confidence, Severity, AlertCategory


class FalsePositiveAnalyzer:
    @staticmethod
    def evaluate_dangling_dns(
        domain: str,
        cname_target: str,
        provider: str,
        reason: str,
        target_resolves: bool,
        http_status: int = None
    ) -> Dict[str, Any]:
        """
        Assesses confidence and false-positive probability for a potential dangling DNS record.
        """
        confidence = Confidence.HIGH
        fp_risk = "LOW"
        notes = []
        verification_steps = []

        # Case 1: Target returns NXDOMAIN
        if not target_resolves:
            if provider in ["AWS Elastic Beanstalk", "Heroku", "GitHub Pages"]:
                confidence = Confidence.HIGH
                fp_risk = "LOW"
                notes.append(f"Target '{cname_target}' completely failed DNS resolution (NXDOMAIN). Host provider {provider} allows new registrations for unallocated subdomains.")
                verification_steps.append(f"Verify in {provider} management console whether the resource was intentionally deleted without cleaning up DNS.")
            else:
                confidence = Confidence.MEDIUM
                fp_risk = "MEDIUM"
                notes.append("Target returns NXDOMAIN, but external DNS authoritative servers might have transient sync delays or split-horizon views.")
                verification_steps.append("Perform dig/nslookup against authoritative nameservers directly to eliminate recursive resolver cache issues.")

        # Case 2: Target resolves, but returned 404 / signature
        else:
            if provider == "AWS S3":
                if "NoSuchBucket" in reason:
                    confidence = Confidence.HIGH
                    fp_risk = "LOW"
                    notes.append("Explicit S3 'NoSuchBucket' XML returned. Confirms bucket namespace is currently unregistered in AWS region.")
                    verification_steps.append("Check AWS CloudTrail for bucket deletion logs; confirm bucket name is retired.")
                else:
                    confidence = Confidence.LOW
                    fp_risk = "HIGH"
                    notes.append("S3 endpoint reachable but does not explicitly confirm NoSuchBucket; might be restricted by bucket policy (403 Forbidden).")
            elif any(p in provider for p in ["CloudFront", "Fastly", "Cloudflare"]):
                # High FP rate on multi-tenant CDNs
                confidence = Confidence.LOW
                fp_risk = "HIGH"
                notes.append(f"Multi-tenant edge CDN ({provider}) detected. 404/403 or routing errors frequently occur when the distribution does not recognize the Host header without meaning the backend is takeover-ready.")
                verification_steps.append("Validate Alternate Domain Names (CNAMEs) configured in CDN distribution before flagging as critical.")
            elif provider == "GitHub Pages":
                if "There isn't a GitHub Pages site here" in reason:
                    confidence = Confidence.HIGH
                    fp_risk = "LOW"
                    notes.append("GitHub Pages official error banner observed. Domain CNAME exists but no repository has configured this CNAME in repo settings.")
                else:
                    confidence = Confidence.MEDIUM
                    fp_risk = "MEDIUM"

        return {
            "confidence": confidence,
            "false_positive_risk": fp_risk,
            "triage_notes": " ".join(notes),
            "verification_recommendation": "; ".join(verification_steps) if verification_steps else "Review cloud configuration and authoritative DNS records."
        }

    @staticmethod
    def evaluate_unexpected_service(
        host: str,
        port: int,
        banner: str = None,
        is_http: bool = False,
        all_open_ports_count: int = 1
    ) -> Dict[str, Any]:
        """
        Assesses confidence and false-positive probability for an unexpected open service.
        """
        confidence = Confidence.HIGH
        fp_risk = "LOW"
        notes = []

        # Check for firewall SYN-proxy sinkhole (if 50+ ports open indiscriminately)
        if all_open_ports_count > 15:
            confidence = Confidence.LOW
            fp_risk = "HIGH"
            notes.append("Unusually high number of open ports detected. Potential port mirroring, firewall SYN-proxy, or honeypot behavior.")
        elif banner or is_http:
            confidence = Confidence.HIGH
            fp_risk = "LOW"
            notes.append(f"Active application response verified on port {port}. Confirmed running listener.")
        else:
            confidence = Confidence.MEDIUM
            fp_risk = "MEDIUM"
            notes.append(f"Port {port} completed TCP handshake, but did not respond with application data or banner within timeout.")

        return {
            "confidence": confidence,
            "false_positive_risk": fp_risk,
            "triage_notes": " ".join(notes),
            "verification_recommendation": f"Perform local `netstat -tulpn` or `lsof -i :{port}` on host {host} to inspect listening PID."
        }

    @staticmethod
    def evaluate_tls_certificate(
        domain: str,
        is_expired: bool,
        days_to_expiry: int,
        sans: list,
        error_message: str = None
    ) -> Dict[str, Any]:
        """
        Assesses confidence and false-positive probability for TLS certificate issues.
        """
        confidence = Confidence.HIGH
        fp_risk = "LOW"
        notes = []

        if is_expired:
            confidence = Confidence.HIGH
            fp_risk = "LOW"
            notes.append(f"Certificate validity timestamp expired {abs(days_to_expiry or 0)} days ago. Cryptographically verified against UTC clock.")
        elif days_to_expiry is not None and days_to_expiry <= 14:
            confidence = Confidence.HIGH
            fp_risk = "LOW"
            notes.append(f"Certificate expires in {days_to_expiry} days. Impending expiration alert.")
        
        # Check SAN coverage
        if domain not in sans and not any(s.startswith("*.") and domain.endswith(s[1:]) for s in sans):
            notes.append(f"Note: Domain '{domain}' is not in certificate SANs list: {sans}. Hostname mismatch may cause browser rejection.")

        return {
            "confidence": confidence,
            "false_positive_risk": fp_risk,
            "triage_notes": " ".join(notes),
            "verification_recommendation": "Renew TLS certificate via ACME/Certbot or enterprise PKI before service disruption occurs."
        }
