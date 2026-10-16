"""
Main CLI Entrypoint for AIORI-3 PS-011: Authorised Attack-Surface Inventory and Change Monitor.
Supports:
  - scan: Run inventory scan
  - baseline: Establish baseline snapshot
  - diff: Execute delta change detection and alert generation
  - demo / simulate: Run end-to-end prototype demonstration with seeded issues
  - monitor: Start continuous scheduled monitoring loop
  - web: Launch interactive cybersecurity dashboard
  - report: Compile hackathon proposal and markdown reports
  - test: Execute verification test suite
"""

import argparse
import sys
from pathlib import Path
from colorama import Fore, Style, init

from scheduler.monitor import AttackSurfaceMonitor
from core.storage import StorageManager
from core.diff_engine import DiffEngine
from lab_simulator.mock_targets import LabSimulator
from analysis.alerts import AlertManager

init(autoreset=True)


def banner():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
================================================================================
  AIORI-3 PS-011: Authorised Attack-Surface Inventory & Change Monitor
  Scope: Strictly Authorised | 4 Documented Checks | Seeded Issue & FP Engine
================================================================================{Style.RESET_ALL}""")


def cmd_demo(args):
    banner()
    print(f"{Fore.YELLOW}[*] RUNNING END-TO-END PROTOTYPE DEMONSTRATION WITH SEEDED ISSUES...{Style.RESET_ALL}\n")
    monitor = AttackSurfaceMonitor()
    
    # 1. Establish Baseline
    print(f"{Fore.CYAN}[STEP 1] Initializing Golden Baseline Inventory (20 Domains, 10 Hosts)...{Style.RESET_ALL}")
    monitor.run_cycle(simulation_mode=True, is_baseline=True)
    print(f"{Fore.GREEN}[+] Baseline established and persisted to storage.{Style.RESET_ALL}\n")
    
    # 2. Trigger Scan with Seeded Drift
    print(f"{Fore.CYAN}[STEP 2] Simulating Attack Surface Drift with Seeded Vulnerabilities...{Style.RESET_ALL}")
    print(f"  - Seeded Issue 1: Expired TLS Certificate (expired-tls.aiori.internal)")
    print(f"  - Seeded Issue 2: Unexpected Open Port 8888 (10.0.1.15:8888 - Debug Console)")
    print(f"  - Seeded Issue 3: Potential Dangling DNS (AWS S3 NoSuchBucket & GitHub Pages 404)")
    print(f"  - Control Issue 4: False-Positive Triage (CloudFront CDN Edge 404)\n")
    
    result = monitor.run_cycle(simulation_mode=True, is_baseline=False)
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] PROTOTYPE DEMONSTRATION COMPLETE!{Style.RESET_ALL}")
    print(f"    Alerts Captured : {result['alerts_count']}")
    print(f"    Report Output   : {result['report_path']}")
    print(f"\n{Fore.YELLOW}Tip: Launch the Web Dashboard to view visual charts: `python main.py web`{Style.RESET_ALL}")


def cmd_scan(args):
    banner()
    monitor = AttackSurfaceMonitor()
    print(f"[*] Starting discovery scan (Mode: {'Live' if args.live else 'Simulation'})...")
    res = monitor.run_cycle(simulation_mode=not args.live, is_baseline=args.baseline)
    print(f"[+] Scan complete. Captured Snapshot ID: {res['snapshot_id']}")


def cmd_baseline(args):
    banner()
    monitor = AttackSurfaceMonitor()
    print(f"[*] Establishing Baseline Inventory (Mode: {'Live' if args.live else 'Simulation'})...")
    res = monitor.run_cycle(simulation_mode=not args.live, is_baseline=True)
    print(f"[+] Golden Baseline established: {res['snapshot_id']}")


def cmd_diff(args):
    banner()
    storage = StorageManager()
    baseline = storage.load_baseline()
    latest = storage.load_latest()
    if not baseline or not latest:
        print(f"{Fore.RED}[!] Missing baseline or latest scan snapshot. Run `python main.py demo` first.{Style.RESET_ALL}")
        return
    diff_engine = DiffEngine()
    diff = diff_engine.compare(baseline, latest)
    AlertManager.print_terminal_summary(diff)


def cmd_monitor(args):
    banner()
    monitor = AttackSurfaceMonitor(scan_interval_seconds=args.interval)
    monitor.start_scheduled_loop(iterations=args.cycles, simulation_mode=args.simulate)


def cmd_web(args):
    banner()
    print(f"{Fore.GREEN}[*] Starting Interactive Cyber Dashboard at http://{args.host}:{args.port}/{Style.RESET_ALL}")
    print(f"    Press CTRL+C to stop.")
    from app import app
    app.run(host=args.host, port=args.port, debug=False)


def cmd_report(args):
    banner()
    print("[*] Generating Hackathon Proposal PDF and Technical Reports...")
    from generate_proposal_pdf import generate_pdf
    pdf_path = generate_pdf()
    print(f"{Fore.GREEN}[+] Successfully compiled: {pdf_path}{Style.RESET_ALL}")


def cmd_test(args):
    banner()
    print("[*] Executing Automated Verification Test Suite...")
    import unittest
    suite = unittest.defaultTestLoader.discover("lab_simulator", pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)


def main():
    parser = argparse.ArgumentParser(
        description="AIORI-3 PS-011: Authorised Attack-Surface Inventory and Change Monitor CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # demo / simulate
    p_demo = subparsers.add_parser("demo", help="Run full prototype demonstration with seeded issues")
    p_sim = subparsers.add_parser("simulate", help="Alias for demo")

    # scan
    p_scan = subparsers.add_parser("scan", help="Run an authorized attack surface scan")
    p_scan.add_argument("--live", action="store_true", help="Perform live network scan instead of simulation")
    p_scan.add_argument("--baseline", action="store_true", help="Mark this scan as new baseline")

    # baseline
    p_base = subparsers.add_parser("baseline", help="Establish the golden baseline inventory")
    p_base.add_argument("--live", action="store_true", help="Perform live network baseline scan")

    # diff
    subparsers.add_parser("diff", help="Compare current scan against baseline and show alerts")

    # monitor
    p_mon = subparsers.add_parser("monitor", help="Start continuous scheduled monitoring loop")
    p_mon.add_argument("--interval", type=int, default=60, help="Interval in seconds between scans (default: 60)")
    p_mon.add_argument("--cycles", type=int, default=None, help="Stop after N cycles (default: run indefinitely)")
    p_mon.add_argument("--simulate", action="store_true", default=True, help="Use lab simulation mode")

    # web
    p_web = subparsers.add_parser("web", help="Launch Flask cybersecurity dashboard")
    p_web.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    p_web.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")

    # report
    subparsers.add_parser("report", help="Generate hackathon PDF and markdown reports")

    # test
    subparsers.add_parser("test", help="Run test suite verifying seeded issue detection & scope")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command in ["demo", "simulate"]:
        cmd_demo(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "baseline":
        cmd_baseline(args)
    elif args.command == "diff":
        cmd_diff(args)
    elif args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "web":
        cmd_web(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "test":
        cmd_test(args)


if __name__ == "__main__":
    main()
