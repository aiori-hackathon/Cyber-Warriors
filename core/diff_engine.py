"""
Diff Engine for Authorised Attack-Surface Inventory and Change Monitor.
Compares a newly captured inventory snapshot against the authorised baseline,
identifying asset drift, new/unexpected open services, expired TLS certificates,
and potential dangling DNS records as mandated by AIORI-3 PS-011.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from core.models import (
    InventoryDiff, Alert, AlertCategory, Severity, Confidence
)
from analysis.false_positive import FalsePositiveAnalyzer


class DiffEngine:
    def __init__(self, expiry_warning_days: int = 14):
        self.expiry_warning_days = expiry_warning_days

    def compare(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> InventoryDiff:
        """
        Executes deep delta analysis between baseline inventory and current scan.
        Generates actionable, prioritized security alerts with false-positive analysis.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        diff = InventoryDiff(
            baseline_id=baseline.get("snapshot_id", "baseline_initial"),
            current_id=current.get("snapshot_id", f"scan_{uuid.uuid4().hex[:8]}"),
            timestamp=now_iso
        )
        
        alerts: List[Alert] = []

        # ----------------------------------------------------------------------
        # 1. Compare Domain Assets & DNS Records
        # ----------------------------------------------------------------------
        baseline_domains = {d["domain"]: d for d in baseline.get("domains", [])}
        current_domains = {d["domain"]: d for d in current.get("domains", [])}
        
        # New Domains
        for d_name in current_domains:
            if d_name not in baseline_domains:
                diff.added_domains.append(d_name)
                alerts.append(Alert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:6].upper()}",
                    category=AlertCategory.NEW_ASSET_DETECTED,
                    severity=Severity.MEDIUM,
                    target=d_name,
                    title="New Domain Discovered in Attack Surface",
                    description=f"Domain '{d_name}' was discovered in the current scan but was not in the baseline inventory.",
                    confidence=Confidence.HIGH,
                    false_positive_risk="LOW",
                    triage_notes="Check DNS registrar or provisioning pipeline to confirm if this subdomain is officially designated.",
                    remediation_recommendation="Add to authorized asset registry or decommission if unauthorized."
                ))

        # Removed Domains
        for d_name in baseline_domains:
            if d_name not in current_domains:
                diff.removed_domains.append(d_name)
                alerts.append(Alert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:6].upper()}",
                    category=AlertCategory.ASSET_REMOVED,
                    severity=Severity.INFO,
                    target=d_name,
                    title="Domain Removed from Active Inventory",
                    description=f"Domain '{d_name}' is no longer present or resolving in current scans.",
                    confidence=Confidence.HIGH,
                    false_positive_risk="LOW"
                ))

        # Check DNS Records and Dangling DNS
        for d_name, cur_dom in current_domains.items():
            # Check Dangling DNS candidates
            dangling_list = cur_dom.get("dangling_candidates", [])
            for dang in dangling_list:
                provider = dang.get("provider", "Unknown Cloud Provider")
                cname = dang.get("cname_target", "")
                reason = dang.get("reason", "")
                
                # False positive assessment
                fp_eval = FalsePositiveAnalyzer.evaluate_dangling_dns(
                    domain=d_name,
                    cname_target=cname,
                    provider=provider,
                    reason=reason,
                    target_resolves=not ("NXDOMAIN" in reason)
                )
                
                diff.dangling_dns_alerts.append(dang)
                alerts.append(Alert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:6].upper()}",
                    category=AlertCategory.POTENTIAL_DANGLING_DNS,
                    severity=Severity.HIGH,
                    target=d_name,
                    title=f"Potential Dangling DNS Record Pointing to {provider}",
                    description=(
                        f"Domain '{d_name}' possesses a CNAME record pointing to '{cname}' ({provider}). "
                        f"Inspection indicator: {reason}."
                    ),
                    confidence=fp_eval["confidence"],
                    false_positive_risk=fp_eval["false_positive_risk"],
                    triage_notes=fp_eval["triage_notes"],
                    remediation_recommendation=(
                        f"Immediately remove the orphan CNAME record from DNS zone files if the cloud resource "
                        f"is retired, or re-claim the resource in the {provider} account. {fp_eval['verification_recommendation']}"
                    ),
                    evidence={"cname_target": cname, "provider": provider, "reason": reason}
                ))

            # Check TLS Certificates on Domain
            tls_certs = cur_dom.get("tls_certificates", [])
            for cert in tls_certs:
                self._evaluate_cert_alert(cert, d_name, alerts, diff)

        # ----------------------------------------------------------------------
        # 2. Compare Hosts, Open Ports, and Unexpected Services
        # ----------------------------------------------------------------------
        baseline_hosts = {h["ip"]: h for h in baseline.get("hosts", [])}
        current_hosts = {h["ip"]: h for h in current.get("hosts", [])}
        
        # New Hosts
        for ip in current_hosts:
            if ip not in baseline_hosts:
                diff.added_hosts.append(ip)
                alerts.append(Alert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:6].upper()}",
                    category=AlertCategory.NEW_ASSET_DETECTED,
                    severity=Severity.HIGH,
                    target=ip,
                    title="New Active Host Detected",
                    description=f"Host IP '{ip}' is responding to probes but was absent in the initial baseline.",
                    confidence=Confidence.HIGH,
                    false_positive_risk="LOW"
                ))

        # Removed Hosts
        for ip in baseline_hosts:
            if ip not in current_hosts:
                diff.removed_hosts.append(ip)

        # Port and Service Level Comparison
        for ip, cur_host in current_hosts.items():
            base_host = baseline_hosts.get(ip, {})
            base_ports = set(base_host.get("open_ports", []))
            cur_ports = set(cur_host.get("open_ports", []))
            
            # Newly Opened Ports
            opened = cur_ports - base_ports
            for p in opened:
                diff.new_open_ports.append({"host": ip, "port": p})
                
                # Retrieve service details for this port
                svc = next((s for s in cur_host.get("services", []) if s.get("port") == p), {})
                banner = svc.get("banner")
                is_http = svc.get("is_http", False)
                ident = svc.get("identified_service", "Unknown")
                
                fp_eval = FalsePositiveAnalyzer.evaluate_unexpected_service(
                    host=ip,
                    port=p,
                    banner=banner,
                    is_http=is_http,
                    all_open_ports_count=len(cur_ports)
                )
                
                is_unexpected = svc.get("is_unexpected", True)
                category = AlertCategory.UNEXPECTED_SERVICE if is_unexpected else AlertCategory.PORT_STATE_CHANGED
                sev = Severity.HIGH if is_unexpected else Severity.MEDIUM
                
                if is_unexpected:
                    diff.unexpected_services.append({"host": ip, "port": p, "service": ident})

                alerts.append(Alert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:6].upper()}",
                    category=category,
                    severity=sev,
                    target=f"{ip}:{p}",
                    title=f"Unexpected Open Service: Port {p} ({ident})",
                    description=(
                        f"Host '{ip}' has newly opened port {p} ({ident}). "
                        f"This port was not present in the baseline inventory or approved service matrix."
                    ),
                    confidence=fp_eval["confidence"],
                    false_positive_risk=fp_eval["false_positive_risk"],
                    triage_notes=fp_eval["triage_notes"],
                    remediation_recommendation=(
                        f"Investigate process listening on {ip}:{p}. If unauthorized, terminate service and "
                        f"close port at host firewall/security group. {fp_eval['verification_recommendation']}"
                    ),
                    evidence={"host": ip, "port": p, "service": ident, "banner": banner}
                ))

            # Closed Ports
            closed = base_ports - cur_ports
            for p in closed:
                diff.closed_ports.append({"host": ip, "port": p})
                alerts.append(Alert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:6].upper()}",
                    category=AlertCategory.PORT_STATE_CHANGED,
                    severity=Severity.INFO,
                    target=f"{ip}:{p}",
                    title=f"Port {p} Closed / Inactive",
                    description=f"Port {p} on host '{ip}' was open in baseline but is now closed or non-responsive.",
                    confidence=Confidence.HIGH,
                    false_positive_risk="LOW"
                ))

            # Check TLS certs from services on this host
            for svc in cur_host.get("services", []):
                cert = svc.get("certificate")
                if cert:
                    self._evaluate_cert_alert(cert, f"{ip}:{svc.get('port')}", alerts, diff)

        diff.alerts = alerts
        return diff

    def _evaluate_cert_alert(self, cert: Dict[str, Any], target_label: str, alerts: List[Alert], diff: InventoryDiff):
        is_expired = cert.get("is_expired", False)
        days = cert.get("days_to_expiry")
        sans = cert.get("sans", [])
        not_after = cert.get("not_after", "Unknown")
        issuer = cert.get("issuer", "Unknown")

        if is_expired:
            fp_eval = FalsePositiveAnalyzer.evaluate_tls_certificate(target_label, True, days, sans)
            diff.tls_changes.append({"target": target_label, "status": "EXPIRED", "days": days})
            alerts.append(Alert(
                alert_id=f"ALT-{uuid.uuid4().hex[:6].upper()}",
                category=AlertCategory.EXPIRED_CERTIFICATE,
                severity=Severity.CRITICAL,
                target=target_label,
                title="Critical: Expired TLS Certificate Detected",
                description=(
                    f"Target '{target_label}' is presenting an expired TLS certificate issued by '{issuer}'. "
                    f"Validity ended on {not_after} ({abs(days or 0)} days ago). "
                    f"Users visiting this service will receive severe security trust warnings."
                ),
                confidence=fp_eval["confidence"],
                false_positive_risk=fp_eval["false_positive_risk"],
                triage_notes=fp_eval["triage_notes"],
                remediation_recommendation="Immediately renew certificate with authorized CA and redeploy to web server.",
                evidence={"issuer": issuer, "not_after": not_after, "days_expired": abs(days or 0)}
            ))
        elif days is not None and days <= self.expiry_warning_days:
            fp_eval = FalsePositiveAnalyzer.evaluate_tls_certificate(target_label, False, days, sans)
            diff.tls_changes.append({"target": target_label, "status": "EXPIRING_SOON", "days": days})
            alerts.append(Alert(
                alert_id=f"ALT-{uuid.uuid4().hex[:6].upper()}",
                category=AlertCategory.CERTIFICATE_EXPIRING,
                severity=Severity.HIGH,
                target=target_label,
                title=f"Warning: TLS Certificate Expiring in {days} Days",
                description=f"Target '{target_label}' certificate expires on {not_after} ({days} days remaining).",
                confidence=fp_eval["confidence"],
                false_positive_risk=fp_eval["false_positive_risk"],
                triage_notes=fp_eval["triage_notes"],
                remediation_recommendation="Schedule automated renewal prior to expiry date to prevent outage."
            ))
