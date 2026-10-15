"""
Flask Web Dashboard for Authorised Attack-Surface Inventory and Change Monitor.
Provides an interactive visual interface for the mentor demonstration and real-time monitoring.
"""

from flask import Flask, render_template, jsonify, request
from pathlib import Path
import json

from core.storage import StorageManager
from core.diff_engine import DiffEngine
from lab_simulator.mock_targets import LabSimulator
from scheduler.monitor import AttackSurfaceMonitor

app = Flask(__name__, template_folder="templates", static_folder="static")
storage = StorageManager()
monitor = AttackSurfaceMonitor()
diff_engine = DiffEngine()


@app.route("/")
def index():
    # Load baseline and latest scan
    baseline = storage.load_baseline()
    if not baseline:
        # Pre-seed baseline for first launch
        base_snap = LabSimulator.get_baseline_snapshot()
        storage.save_snapshot(base_snap, is_baseline=True)
        baseline = base_snap.to_dict()

    latest = storage.load_latest()
    if not latest:
        curr_snap = LabSimulator.get_current_scan_with_seeded_issues()
        storage.save_snapshot(curr_snap, is_baseline=False)
        latest = curr_snap.to_dict()

    diff = diff_engine.compare(baseline, latest)

    # Calculate stats
    domains_count = len(latest.get("domains", []))
    hosts_count = len(latest.get("hosts", []))
    open_ports_count = sum(len(h.get("open_ports", [])) for h in latest.get("hosts", []))
    alerts = diff.alerts

    critical_count = sum(1 for a in alerts if a.severity.value == "CRITICAL")
    high_count = sum(1 for a in alerts if a.severity.value == "HIGH")
    medium_count = sum(1 for a in alerts if a.severity.value == "MEDIUM")
    low_count = sum(1 for a in alerts if a.severity.value == "LOW")

    return render_template(
        "dashboard.html",
        baseline=baseline,
        latest=latest,
        diff=diff,
        alerts=alerts,
        domains_count=domains_count,
        hosts_count=hosts_count,
        open_ports_count=open_ports_count,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count
    )


@app.route("/api/run-simulation", methods=["POST"])
def api_run_simulation():
    res = monitor.run_cycle(simulation_mode=True)
    return jsonify({"status": "success", "data": res})


@app.route("/api/set-baseline", methods=["POST"])
def api_set_baseline():
    base_snap = LabSimulator.get_baseline_snapshot()
    storage.save_snapshot(base_snap, is_baseline=True)
    return jsonify({"status": "success", "message": "Baseline reset to initial lab golden standard"})


@app.route("/api/inventory")
def api_inventory():
    latest = storage.load_latest() or {}
    return jsonify(latest)


@app.route("/api/alerts")
def api_alerts():
    baseline = storage.load_baseline() or {}
    latest = storage.load_latest() or {}
    diff = diff_engine.compare(baseline, latest)
    return jsonify(diff.to_dict())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
