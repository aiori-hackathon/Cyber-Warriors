"""
Data models for Authorised Attack-Surface Inventory and Change Monitor (AIORI-3 PS-011).
Defines standard dataclasses for assets, DNS, TLS, ports, services, inventory snapshots, and alerts.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Optional, Any


class AssetType(str, Enum):
    DOMAIN = "domain"
    HOST = "host"
    SERVICE = "service"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AlertCategory(str, Enum):
    EXPIRED_CERTIFICATE = "EXPIRED_CERTIFICATE"
    CERTIFICATE_EXPIRING = "CERTIFICATE_EXPIRING"
    UNEXPECTED_SERVICE = "UNEXPECTED_SERVICE"
    POTENTIAL_DANGLING_DNS = "POTENTIAL_DANGLING_DNS"
    NEW_ASSET_DETECTED = "NEW_ASSET_DETECTED"
    ASSET_REMOVED = "ASSET_REMOVED"
    PORT_STATE_CHANGED = "PORT_STATE_CHANGED"
    DNS_RECORD_CHANGED = "DNS_RECORD_CHANGED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"


@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: int = 300
    target_resolves: bool = True
    cname_target: Optional[str] = None
    is_dangling_candidate: bool = False
    dangling_provider: Optional[str] = None
    dangling_reason: Optional[str] = None


@dataclass
class TLSCertificate:
    domain: str
    port: int = 443
    is_valid: bool = False
    is_expired: bool = False
    days_to_expiry: Optional[int] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    sans: List[str] = field(default_factory=list)
    signature_algorithm: Optional[str] = None
    serial_number: Optional[str] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class PortScanResult:
    """Represents the results of the 4 Documented Checks on a specific port."""
    host: str
    port: int
    protocol: str = "TCP"
    # Check 1: TCP Port State & Connection Probe
    state: str = "CLOSED"  # OPEN, CLOSED, FILTERED
    latency_ms: Optional[float] = None
    
    # Check 2: Service Banner Grab & Protocol Fingerprint
    banner: Optional[str] = None
    identified_service: Optional[str] = None
    
    # Check 3: TLS/SSL Handshake & Negotiation Probe
    has_tls: bool = False
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    certificate: Optional[TLSCertificate] = None
    
    # Check 4: Application-Layer HTTP/HTTPS Inspection
    is_http: bool = False
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    server_header: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    
    is_unexpected: bool = False
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class HostAsset:
    ip: str
    hostname: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: List[PortScanResult] = field(default_factory=list)
    os_hint: Optional[str] = None
    last_scanned: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class DomainAsset:
    domain: str
    dns_records: List[DNSRecord] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)
    tls_certificates: List[TLSCertificate] = field(default_factory=list)
    has_dangling_records: bool = False
    dangling_candidates: List[Dict[str, Any]] = field(default_factory=list)
    last_scanned: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Alert:
    alert_id: str
    category: AlertCategory
    severity: Severity
    target: str
    title: str
    description: str
    confidence: Confidence = Confidence.HIGH
    false_positive_risk: str = "LOW"
    triage_notes: str = ""
    remediation_recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class InventorySnapshot:
    snapshot_id: str
    timestamp: str
    scan_scope: Dict[str, Any]
    domains: List[DomainAsset] = field(default_factory=list)
    hosts: List[HostAsset] = field(default_factory=list)
    summary_stats: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InventoryDiff:
    baseline_id: str
    current_id: str
    timestamp: str
    added_domains: List[str] = field(default_factory=list)
    removed_domains: List[str] = field(default_factory=list)
    added_hosts: List[str] = field(default_factory=list)
    removed_hosts: List[str] = field(default_factory=list)
    new_open_ports: List[Dict[str, Any]] = field(default_factory=list)
    closed_ports: List[Dict[str, Any]] = field(default_factory=list)
    dns_changes: List[Dict[str, Any]] = field(default_factory=list)
    tls_changes: List[Dict[str, Any]] = field(default_factory=list)
    unexpected_services: List[Dict[str, Any]] = field(default_factory=list)
    dangling_dns_alerts: List[Dict[str, Any]] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
