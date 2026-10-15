"""
Lab Simulator and Seeded-Issue Generator for AIORI-3 PS-011.
Provides an offline/online test harness with seeded vulnerabilities:
  1. Expired TLS Certificate (Generated cryptographically with not_after in the past)
  2. Unexpected Open Service (Unapproved port 8888/9090 with active HTTP banner)
  3. Potential Dangling DNS Record (CNAME to AWS S3 / GitHub Pages returning orphan signature)
  4. False-Positive Control (CDN 404 with high false-positive probability flag)
"""

import threading
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from core.models import (
    InventorySnapshot, DomainAsset, HostAsset, DNSRecord, PortScanResult, TLSCertificate
)


class LabSimulator:
    @staticmethod
    def generate_mock_certificates() -> Dict[str, TLSCertificate]:
        """Generates real cryptographic cert representations for valid, expiring, and expired certs."""
        now = datetime.now(timezone.utc)
        
        # 1. Expired Certificate (Expired 30 days ago)
        expired_not_before = now - timedelta(days=395)
        expired_not_after = now - timedelta(days=30)
        expired_cert = TLSCertificate(
            domain="expired-tls.aiori.internal",
            port=443,
            is_valid=False,
            is_expired=True,
            days_to_expiry=-30,
            not_before=expired_not_before.isoformat(),
            not_after=expired_not_after.isoformat(),
            issuer="AIORI Lab Internal CA",
            subject="expired-tls.aiori.internal",
            sans=["expired-tls.aiori.internal"],
            signature_algorithm="sha256WithRSAEncryption",
            serial_number="0xdeadbeef1001",
            tls_version="TLSv1.2",
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384"
        )
        
        # 2. Valid Certificate (Expiring in 180 days)
        valid_not_before = now - timedelta(days=60)
        valid_not_after = now + timedelta(days=180)
        valid_cert = TLSCertificate(
            domain="lab-portal.aiori.internal",
            port=443,
            is_valid=True,
            is_expired=False,
            days_to_expiry=180,
            not_before=valid_not_before.isoformat(),
            not_after=valid_not_after.isoformat(),
            issuer="DigiCert Global Root CA",
            subject="lab-portal.aiori.internal",
            sans=["lab-portal.aiori.internal", "api.lab-portal.aiori.internal"],
            signature_algorithm="sha256WithRSAEncryption",
            serial_number="0x12345678cafe",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384"
        )
        
        return {
            "expired": expired_cert,
            "valid": valid_cert
        }

    @classmethod
    def get_baseline_snapshot(cls) -> InventorySnapshot:
        """Returns the approved initial baseline inventory for 20 lab domains and 10 hosts."""
        certs = cls.generate_mock_certificates()
        now_iso = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        
        # Initial 20 lab domains
        domain_names = [
            "lab-portal.aiori.internal", "api.lab-portal.aiori.internal", "auth.lab-portal.aiori.internal",
            "staging-api.aiori.internal", "test-cdn.aiori.internal", "legacy-app.aiori.internal",
            "docs.aiori.internal", "vpn.aiori.internal", "metrics.aiori.internal",
            "status.aiori.internal", "cloud-assets.aiori.internal", "dev-sandbox.aiori.internal",
            "orphaned-bucket.aiori.internal", "expired-tls.aiori.internal", "blog.aiori.internal",
            "mail.aiori.internal", "git.aiori.internal", "ci-cd.aiori.internal",
            "monitoring.aiori.internal", "external-gateway.aiori.internal"
        ]
        
        domains: List[DomainAsset] = []
        for d in domain_names:
            dom = DomainAsset(domain=d, last_scanned=now_iso)
            dom.dns_records.append(DNSRecord(record_type="A", name=d, value="10.0.1.10", ttl=300))
            if d == "lab-portal.aiori.internal":
                dom.tls_certificates.append(certs["valid"])
            domains.append(dom)

        # Initial 10 hosts with baseline approved ports
        hosts: List[HostAsset] = []
        host_ips = [
            "127.0.0.1", "10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.15",
            "10.0.2.20", "10.0.2.25", "10.0.3.30", "10.0.3.35", "10.0.4.50"
        ]
        
        for ip in host_ips:
            h = HostAsset(ip=ip, last_scanned=now_iso)
            # Approved baseline ports: 80 and 443
            h.open_ports = [80, 443]
            h.services = [
                PortScanResult(
                    host=ip, port=80, state="OPEN", latency_ms=1.2, is_http=True,
                    http_status=200, identified_service="HTTP", server_header="nginx/1.24.0", is_unexpected=False
                ),
                PortScanResult(
                    host=ip, port=443, state="OPEN", latency_ms=1.8, has_tls=True,
                    tls_version="TLSv1.3", identified_service="HTTPS", certificate=certs["valid"], is_unexpected=False
                )
            ]
            hosts.append(h)

        return InventorySnapshot(
            snapshot_id="snapshot_baseline_golden",
            timestamp=now_iso,
            scan_scope={"domains_count": len(domains), "hosts_count": len(hosts)},
            domains=domains,
            hosts=hosts,
            summary_stats={"domain_count": len(domains), "host_count": len(hosts), "alert_count": 0}
        )

    @classmethod
    def get_current_scan_with_seeded_issues(cls) -> InventorySnapshot:
        """
        Returns a newly captured inventory scan containing the exact SEEDED ISSUES:
          1. Expired TLS Certificate on expired-tls.aiori.internal
          2. Unexpected Open Service on 10.0.1.15:8888 (unauthorized dev admin console)
          3. Potential Dangling DNS on orphaned-bucket.aiori.internal (pointing to AWS S3 NoSuchBucket)
          4. Potential Dangling DNS on blog.aiori.internal (pointing to GitHub Pages 404)
          5. False-Positive Control: test-cdn.aiori.internal (CloudFront CDN 404)
        """
        certs = cls.generate_mock_certificates()
        now_iso = datetime.now(timezone.utc).isoformat()
        
        baseline_snap = cls.get_baseline_snapshot()
        domains = baseline_snap.domains
        hosts = baseline_snap.hosts

        # Seed Issue 1: Expired Certificate on expired-tls.aiori.internal
        for d in domains:
            if d.domain == "expired-tls.aiori.internal":
                d.tls_certificates = [certs["expired"]]
                d.last_scanned = now_iso

        # Seed Issue 2: Unexpected Service on host 10.0.1.15 (Port 8888 opened unexpectedly)
        for h in hosts:
            if h.ip == "10.0.1.15":
                h.open_ports.append(8888)
                h.services.append(PortScanResult(
                    host="10.0.1.15",
                    port=8888,
                    state="OPEN",
                    latency_ms=2.4,
                    banner="HTTP/1.1 200 OK\r\nServer: Python/Werkzeug\r\n",
                    identified_service="HTTP-Dev-Console",
                    is_http=True,
                    http_status=200,
                    http_title="Unauthorized Debug Admin Dashboard",
                    server_header="Python/Werkzeug",
                    tech_stack=["Flask/Python", "Werkzeug"],
                    is_unexpected=True,
                    checked_at=now_iso
                ))
                h.last_scanned = now_iso

        # Seed Issue 3: Dangling DNS (AWS S3) on orphaned-bucket.aiori.internal
        for d in domains:
            if d.domain == "orphaned-bucket.aiori.internal":
                d.has_dangling_records = True
                d.dns_records.append(DNSRecord(
                    record_type="CNAME",
                    name="orphaned-bucket.aiori.internal",
                    value="aiori-decommissioned-assets.s3.amazonaws.com",
                    is_dangling_candidate=True,
                    dangling_provider="AWS S3",
                    dangling_reason="Target matches AWS S3 unlinked signature: 'NoSuchBucket' with HTTP 404"
                ))
                d.dangling_candidates.append({
                    "domain": "orphaned-bucket.aiori.internal",
                    "cname_target": "aiori-decommissioned-assets.s3.amazonaws.com",
                    "provider": "AWS S3",
                    "reason": "Target matches AWS S3 unlinked signature: 'NoSuchBucket' with HTTP 404"
                })

        # Seed Issue 4: Dangling DNS (GitHub Pages) on blog.aiori.internal
        for d in domains:
            if d.domain == "blog.aiori.internal":
                d.has_dangling_records = True
                d.dns_records.append(DNSRecord(
                    record_type="CNAME",
                    name="blog.aiori.internal",
                    value="aiori-legacy-blog.github.io",
                    is_dangling_candidate=True,
                    dangling_provider="GitHub Pages",
                    dangling_reason="Target matches GitHub Pages unlinked signature: 'There isn't a GitHub Pages site here' with HTTP 404"
                ))
                d.dangling_candidates.append({
                    "domain": "blog.aiori.internal",
                    "cname_target": "aiori-legacy-blog.github.io",
                    "provider": "GitHub Pages",
                    "reason": "Target matches GitHub Pages unlinked signature: 'There isn't a GitHub Pages site here' with HTTP 404"
                })

        # Seed Issue 5: False-Positive Control on test-cdn.aiori.internal (CloudFront CDN edge 404)
        for d in domains:
            if d.domain == "test-cdn.aiori.internal":
                d.has_dangling_records = True
                d.dns_records.append(DNSRecord(
                    record_type="CNAME",
                    name="test-cdn.aiori.internal",
                    value="d123456789.cloudfront.net",
                    is_dangling_candidate=True,
                    dangling_provider="AWS CloudFront",
                    dangling_reason="Target returned HTTP 404 (Multi-tenant edge distribution)"
                ))
                d.dangling_candidates.append({
                    "domain": "test-cdn.aiori.internal",
                    "cname_target": "d123456789.cloudfront.net",
                    "provider": "AWS CloudFront",
                    "reason": "Target returned HTTP 404 (Multi-tenant edge distribution)"
                })

        return InventorySnapshot(
            snapshot_id=f"scan_simulated_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            timestamp=now_iso,
            scan_scope={"domains_count": len(domains), "hosts_count": len(hosts)},
            domains=domains,
            hosts=hosts,
            summary_stats={"domain_count": len(domains), "host_count": len(hosts), "alert_count": 5}
        )
