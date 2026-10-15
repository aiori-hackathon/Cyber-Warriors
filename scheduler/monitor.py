"""
Scheduled Monitoring and Change-Detection Engine for AIORI-3 PS-011.
Orchestrates continuous attack-surface scanning, baseline comparison,
and immediate alert dispatching on schedule.
"""

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from core.scope_guard import ScopeGuard
from core.models import InventorySnapshot, HostAsset, DomainAsset
from core.storage import StorageManager
from core.diff_engine import DiffEngine
from checks.dns_inspector import DNSInspector
from checks.tls_inspector import TLSInspector
from checks.service_inspector import ServiceInspector
from analysis.alerts import AlertManager
from lab_simulator.mock_targets import LabSimulator


class AttackSurfaceMonitor:
    def __init__(
        self,
        scope_path: Optional[Path] = None,
        data_dir: Optional[Path] = None,
        scan_interval_seconds: int = 60
    ):
        self.scope_guard = ScopeGuard(config_path=scope_path)
        self.storage = StorageManager(data_dir=data_dir)
        self.diff_engine = DiffEngine()
        self.dns_inspector = DNSInspector(scope_guard=self.scope_guard)
        self.tls_inspector = TLSInspector(scope_guard=self.scope_guard)
        self.service_inspector = ServiceInspector(scope_guard=self.scope_guard)
        self.interval = scan_interval_seconds

    def execute_live_scan(self) -> InventorySnapshot:
        """
        Executes an authorized live discovery scan across all in-scope domains and hosts.
        Enforces strict limit of up to 20 domains and 10 hosts.
        """
        domains = self.scope_guard.get_approved_domains()
        hosts = self.scope_guard.get_approved_hosts()
        ports = self.scope_guard.get_approved_ports()
        
        now_iso = datetime.now(timezone.utc).isoformat()
        snap_id = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}"
        
        domain_assets: List[DomainAsset] = []
        host_assets: List[HostAsset] = []

        # 1. Catalog DNS & TLS on approved domains
        for d in domains:
            try:
                dom_asset = self.dns_inspector.inspect_domain(d)
                # Inspect TLS on domain
                tls_cert = self.tls_inspector.inspect_tls(d, 443)
                if tls_cert.is_valid or tls_cert.is_expired:
                    dom_asset.tls_certificates.append(tls_cert)
                domain_assets.append(dom_asset)
            except Exception:
                pass

        # 2. Inspect Services on approved hosts using the 4 Documented Checks
        for h in hosts:
            try:
                host_asset = HostAsset(ip=h, last_scanned=now_iso)
                for p in ports:
                    # Run the 4 Documented Checks
                    p_res = self.service_inspector.inspect_port(h, p)
                    if p_res.state == "OPEN":
                        host_asset.open_ports.append(p)
                        host_asset.services.append(p_res)
                host_assets.append(host_asset)
            except Exception:
                pass

        snapshot = InventorySnapshot(
            snapshot_id=snap_id,
            timestamp=now_iso,
            scan_scope={"domains_count": len(domain_assets), "hosts_count": len(host_assets)},
            domains=domain_assets,
            hosts=host_assets,
            summary_stats={
                "domain_count": len(domain_assets),
                "host_count": len(host_assets),
                "open_ports_count": sum(len(h.open_ports) for h in host_assets)
            }
        )
        return snapshot

    def run_cycle(self, simulation_mode: bool = False, is_baseline: bool = False) -> Dict[str, Any]:
        """Runs a single monitoring cycle, compares against baseline, and records diffs."""
        if simulation_mode:
            current_snap = LabSimulator.get_current_scan_with_seeded_issues() if not is_baseline else LabSimulator.get_baseline_snapshot()
        else:
            current_snap = self.execute_live_scan()

        self.storage.save_snapshot(current_snap, is_baseline=is_baseline)

        baseline_data = self.storage.load_baseline()
        if not baseline_data:
            # If no baseline exists, designate this scan as initial baseline
            self.storage.save_snapshot(current_snap, is_baseline=True)
            baseline_data = current_snap.to_dict()

        diff = self.diff_engine.compare(baseline_data, current_snap.to_dict())
        current_snap.summary_stats["alert_count"] = len(diff.alerts)

        # Record alerts to SQLite
        self.storage.record_alerts(current_snap.snapshot_id, diff.alerts)

        # Generate report
        report_path = self.storage.reports_dir / f"change_report_{current_snap.snapshot_id}.md"
        latest_report_path = self.storage.reports_dir / "latest_alert_report.md"
        AlertManager.generate_markdown_report(diff, report_path)
        AlertManager.generate_markdown_report(diff, latest_report_path)

        # Terminal output
        AlertManager.print_terminal_summary(diff)

        return {
            "snapshot_id": current_snap.snapshot_id,
            "timestamp": current_snap.timestamp,
            "alerts_count": len(diff.alerts),
            "diff": diff.to_dict(),
            "report_path": str(latest_report_path)
        }

    def start_scheduled_loop(self, iterations: Optional[int] = None, simulation_mode: bool = False):
        """Runs the continuous monitoring loop at configured intervals."""
        print(f"[*] Starting AIORI-3 Attack-Surface Monitor (Interval: {self.interval}s)")
        print(f"[*] Strict Scope: Enforced (Max 20 domains, 10 hosts)")
        print(f"[*] Mode: {'Simulation / Lab Harness' if simulation_mode else 'Live Authorised Scan'}")
        
        cycle_count = 0
        try:
            while True:
                cycle_count += 1
                print(f"\n[+] Executing Scheduled Scan Cycle #{cycle_count} at {datetime.now(timezone.utc).isoformat()}...")
                self.run_cycle(simulation_mode=simulation_mode)
                
                if iterations and cycle_count >= iterations:
                    print(f"[*] Completed requested {iterations} cycles. Exiting.")
                    break
                    
                print(f"[*] Sleeping for {self.interval} seconds until next scheduled cycle...")
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n[*] Scheduled monitor stopped by user.")
