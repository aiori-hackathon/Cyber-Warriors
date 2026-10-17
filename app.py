"""
Flask Web Application for AIORI-3 PS-011: Authorised Attack-Surface Inventory and Change Monitor.
Provides an interactive, light-themed cybersecurity dashboard with navy-blue accents,
connected to SQLite database and security monitoring modules.
"""

import os
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify, Response, send_file
)
from datetime import datetime, timezone

from config import (
    SECRET_KEY, DATABASE_PATH, MAX_APPROVED_DOMAINS, MAX_APPROVED_HOSTS,
    DEFAULT_APPROVED_PORTS, BASE_DIR
)
from database import init_db, seed_initial_lab_data, get_db_connection
from modules.scope_manager import ScopeManager, ScopeViolationError
from modules.scheduler import BackgroundMonitor
from modules.report_generator import ReportGenerator
from modules.change_detector import ChangeDetector
from modules.seeded_lab import SeededLabHarness

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = SECRET_KEY

# Initialize database and seed initial 20 lab domains and 10 hosts on startup
init_db()
seed_initial_lab_data()


# ------------------------------------------------------------------------------
# 1. Dashboard Overview
# ------------------------------------------------------------------------------
@app.route("/")
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Scope metrics
    cursor.execute("SELECT COUNT(*) FROM assets WHERE asset_type = 'domain' AND is_approved = 1")
    approved_domains = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM assets WHERE asset_type = 'host' AND is_approved = 1")
    approved_hosts = cursor.fetchone()[0]

    # Findings metrics
    cursor.execute("SELECT COUNT(*) FROM security_findings WHERE status = 'OPEN'")
    open_findings = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM change_events")
    total_changes = cursor.fetchone()[0]

    # Last scan details
    cursor.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1")
    last_scan = cursor.fetchone()
    last_scan_time = last_scan["start_time"][:19].replace("T", " ") if last_scan else None
    last_scan_type = last_scan["scan_type"].capitalize() if last_scan else "None"

    # Specific seed counts (evaluated from latest completed scan to prevent historical observation accumulation)
    cursor.execute("SELECT id FROM scan_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1")
    comp_scan = cursor.fetchone()
    latest_completed_id = comp_scan["id"] if comp_scan else (last_scan["id"] if last_scan else None)

    if latest_completed_id:
        cursor.execute("SELECT COUNT(DISTINCT domain) FROM tls_observations WHERE scan_run_id = ? AND is_expired = 1", (latest_completed_id,))
        expired_certs = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT host_ip || ':' || port) FROM port_observations WHERE scan_run_id = ? AND is_unexpected = 1", (latest_completed_id,))
        unexpected_services = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT domain) FROM dns_observations WHERE scan_run_id = ? AND is_dangling_candidate = 1", (latest_completed_id,))
        dangling_dns = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM port_observations WHERE scan_run_id = ? AND state = 'OPEN'", (latest_completed_id,))
        open_ports_count = cursor.fetchone()[0]
    else:
        cursor.execute("SELECT COUNT(DISTINCT domain) FROM tls_observations WHERE is_expired = 1")
        expired_certs = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT host_ip || ':' || port) FROM port_observations WHERE is_unexpected = 1")
        unexpected_services = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT domain) FROM dns_observations WHERE is_dangling_candidate = 1")
        dangling_dns = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT host_ip || ':' || port) FROM port_observations WHERE state = 'OPEN'")
        open_ports_count = cursor.fetchone()[0]

    # Severity counts for Chart.js
    cursor.execute("SELECT COUNT(*) FROM security_findings WHERE severity = 'CRITICAL' AND status = 'OPEN'")
    crit_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM security_findings WHERE severity = 'HIGH' AND status = 'OPEN'")
    high_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM security_findings WHERE severity = 'MEDIUM' AND status = 'OPEN'")
    med_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM security_findings WHERE severity = 'LOW' AND status = 'OPEN'")
    low_count = cursor.fetchone()[0]

    # Recent findings
    cursor.execute("SELECT * FROM security_findings ORDER BY id DESC LIMIT 6")
    recent_findings = [dict(r) for r in cursor.fetchall()]

    conn.close()

    stats = {
        "approved_domains": approved_domains,
        "max_domains": MAX_APPROVED_DOMAINS,
        "approved_hosts": approved_hosts,
        "max_hosts": MAX_APPROVED_HOSTS,
        "open_findings": open_findings,
        "total_changes": total_changes,
        "expired_certs": expired_certs,
        "unexpected_services": unexpected_services,
        "dangling_dns": dangling_dns,
        "open_ports_count": open_ports_count,
        "last_scan_time": last_scan_time,
        "last_scan_type": last_scan_type
    }

    chart_data = {
        "critical": crit_count,
        "high": high_count,
        "medium": med_count,
        "low": low_count
    }

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        stats=stats,
        chart_data=chart_data,
        recent_findings=recent_findings
    )


# ------------------------------------------------------------------------------
# 2. Asset Inventory Routes
# ------------------------------------------------------------------------------
@app.route("/assets")
def assets_page():
    filter_type = request.args.get("type")
    assets = ScopeManager.get_all_assets(filter_type)
    counts = ScopeManager.get_counts()
    return render_template(
        "assets.html",
        active_page="assets",
        assets=assets,
        counts=counts,
        filter_type=filter_type
    )


@app.route("/api/assets/add", methods=["POST"])
def api_add_asset():
    name = request.form.get("name", "").strip()
    asset_type = request.form.get("asset_type", "domain").strip().lower()
    value = request.form.get("value", "").strip().lower()
    ip_address = request.form.get("ip_address", "").strip() or None
    notes = request.form.get("notes", "").strip()

    success, msg = ScopeManager.add_asset(name, asset_type, value, ip_address, notes)
    if success:
        flash(msg, "success")
    else:
        flash(msg, "error")
    return redirect(url_for("assets_page"))


@app.route("/api/assets/<int:asset_id>/delete", methods=["POST"])
def api_delete_asset(asset_id):
    success, msg = ScopeManager.delete_asset(asset_id)
    flash(msg, "info" if success else "error")
    return redirect(url_for("assets_page"))


@app.route("/api/assets/<int:asset_id>/toggle", methods=["POST"])
def api_toggle_asset(asset_id):
    success, msg = ScopeManager.toggle_approval(asset_id)
    flash(msg, "info" if success else "error")
    return redirect(url_for("assets_page"))


# ------------------------------------------------------------------------------
# 3. Check 1: DNS Monitoring
# ------------------------------------------------------------------------------
@app.route("/dns")
def dns_page():
    view_mode = request.args.get("view", "latest")
    scan_id = request.args.get("scan_id")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM dns_observations")
    total_obs = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM scan_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1")
    comp_scan = cursor.fetchone()
    latest_scan_id = comp_scan["id"] if comp_scan else None

    if scan_id:
        cursor.execute("""
            SELECT * FROM dns_observations
            WHERE scan_run_id = ?
            ORDER BY is_dangling_candidate DESC, id DESC
        """, (scan_id,))
    elif view_mode == "all" or not latest_scan_id:
        cursor.execute("""
            SELECT * FROM dns_observations
            ORDER BY is_dangling_candidate DESC, id DESC LIMIT 500
        """)
    else:
        cursor.execute("""
            SELECT * FROM dns_observations
            WHERE scan_run_id = ?
            ORDER BY is_dangling_candidate DESC, id DESC
        """, (latest_scan_id,))

    records = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return render_template(
        "dns.html",
        active_page="dns",
        records=records,
        view_mode=view_mode,
        current_scan_id=scan_id or latest_scan_id,
        total_obs=total_obs
    )


# ------------------------------------------------------------------------------
# 4. Check 2: TLS Certificate Monitoring
# ------------------------------------------------------------------------------
@app.route("/tls")
def tls_page():
    view_mode = request.args.get("view", "latest")
    scan_id = request.args.get("scan_id")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM tls_observations")
    total_obs = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM scan_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1")
    comp_scan = cursor.fetchone()
    latest_scan_id = comp_scan["id"] if comp_scan else None

    if scan_id:
        cursor.execute("""
            SELECT * FROM tls_observations
            WHERE scan_run_id = ?
            ORDER BY is_expired DESC, days_to_expiry ASC, id DESC
        """, (scan_id,))
    elif view_mode == "all" or not latest_scan_id:
        cursor.execute("""
            SELECT * FROM tls_observations
            ORDER BY is_expired DESC, days_to_expiry ASC, id DESC LIMIT 500
        """)
    else:
        cursor.execute("""
            SELECT * FROM tls_observations
            WHERE scan_run_id = ?
            ORDER BY is_expired DESC, days_to_expiry ASC, id DESC
        """, (latest_scan_id,))

    certs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return render_template(
        "tls.html",
        active_page="tls",
        certs=certs,
        view_mode=view_mode,
        current_scan_id=scan_id or latest_scan_id,
        total_obs=total_obs
    )


# ------------------------------------------------------------------------------
# 5. Check 3: Port and Service Monitoring
# ------------------------------------------------------------------------------
@app.route("/ports")
def ports_page():
    view_mode = request.args.get("view", "latest")
    scan_id = request.args.get("scan_id")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM port_observations")
    total_obs = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM scan_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1")
    comp_scan = cursor.fetchone()
    latest_scan_id = comp_scan["id"] if comp_scan else None

    if scan_id:
        cursor.execute("""
            SELECT * FROM port_observations
            WHERE scan_run_id = ?
            ORDER BY is_unexpected DESC, state ASC, id DESC
        """, (scan_id,))
    elif view_mode == "all" or not latest_scan_id:
        cursor.execute("""
            SELECT * FROM port_observations
            ORDER BY is_unexpected DESC, state ASC, id DESC LIMIT 500
        """)
    else:
        cursor.execute("""
            SELECT * FROM port_observations
            WHERE scan_run_id = ?
            ORDER BY is_unexpected DESC, state ASC, id DESC
        """, (latest_scan_id,))

    ports = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return render_template(
        "ports.html",
        active_page="ports",
        ports=ports,
        view_mode=view_mode,
        current_scan_id=scan_id or latest_scan_id,
        total_obs=total_obs
    )


# ------------------------------------------------------------------------------
# 6. Check 4: Change History
# ------------------------------------------------------------------------------
@app.route("/changes")
def changes_page():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM change_events ORDER BY id DESC LIMIT 500")
    changes = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT * FROM baseline_snapshots WHERE is_active = 1 ORDER BY id DESC LIMIT 1")
    baseline = cursor.fetchone()
    conn.close()
    return render_template("changes.html", active_page="changes", changes=changes, baseline=baseline)


# ------------------------------------------------------------------------------
# 7. Security Findings Registry & Triage
# ------------------------------------------------------------------------------
@app.route("/findings")
def findings_page():
    filter_status = request.args.get("status")
    conn = get_db_connection()
    cursor = conn.cursor()
    if filter_status:
        cursor.execute("SELECT * FROM security_findings WHERE status = ? ORDER BY id DESC", (filter_status,))
    else:
        cursor.execute("SELECT * FROM security_findings ORDER BY id DESC")
    findings = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return render_template("findings.html", active_page="findings", findings=findings, filter_status=filter_status)


@app.route("/api/findings/<int:finding_id>/update-status", methods=["POST"])
def api_update_finding_status(finding_id):
    status = request.form.get("status", "OPEN")
    notes = request.form.get("notes", "")
    fp_reason = request.form.get("fp_reason", "")
    success = ChangeDetector.update_finding_status(finding_id, status, notes, fp_reason)
    if success:
        flash(f"Finding #{finding_id} status updated to {status}.", "success")
    else:
        flash("Failed to update finding status.", "error")
    return redirect(url_for("findings_page"))


# ------------------------------------------------------------------------------
# 8. Scan History & Scan Triggers
# ------------------------------------------------------------------------------
@app.route("/scans")
def scan_history_page():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 100")
    scans = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return render_template("scan_history.html", active_page="scans", scans=scans)


@app.route("/api/scan/start", methods=["POST"])
def api_start_live_scan():
    monitor = BackgroundMonitor.get_instance()
    res = monitor.run_live_scan()
    return jsonify(res)


@app.route("/api/scan/simulate", methods=["POST"])
def api_start_simulated_scan():
    monitor = BackgroundMonitor.get_instance()
    res = monitor.trigger_simulated_scan()
    return jsonify(res)


@app.route("/api/baseline/reset-golden", methods=["POST"])
def api_reset_golden_baseline():
    """Resets the golden baseline snapshot and cleans transient findings for demonstration."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()

    # Create new clean baseline scan
    cursor.execute("""
        INSERT INTO scan_runs (scan_type, status, start_time, end_time, domains_scanned, hosts_scanned, findings_count, changes_count, notes)
        VALUES ('simulated', 'completed', ?, ?, 20, 10, 0, 0, 'Reset Golden Baseline Standard')
    """, (now_str, now_str))
    new_scan_id = cursor.lastrowid

    # Deactivate older baselines and activate new golden baseline
    cursor.execute("UPDATE baseline_snapshots SET is_active = 0")
    cursor.execute("""
        INSERT INTO baseline_snapshots (snapshot_name, scan_run_id, is_active, created_at, notes)
        VALUES ('Baseline-Golden-Standard-v1', ?, 1, ?, 'Authorised initial baseline standard')
    """, (new_scan_id, now_str))

    # Mark existing open findings as resolved
    cursor.execute("UPDATE security_findings SET status = 'RESOLVED', review_notes = 'Cleared during baseline re-synchronization' WHERE status = 'OPEN'")
    cursor.execute("DELETE FROM change_events")

    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "Baseline reset to clean golden standard."})


# ------------------------------------------------------------------------------
# 9. Reports & Downloads
# ------------------------------------------------------------------------------
@app.route("/reports")
def reports_page():
    return render_template("reports.html", active_page="reports")


@app.route("/reports/export/csv/<table_type>")
def export_csv(table_type):
    content = ReportGenerator.export_csv(table_type)
    return Response(
        content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=asm_{table_type}_export.csv"}
    )


@app.route("/reports/technical")
def view_technical_report():
    report_data = ReportGenerator.generate_full_technical_report()
    if request.args.get("format") == "raw":
        return Response(report_data["markdown"], mimetype="text/markdown")
    return render_template(
        "technical_report_view.html",
        active_page="reports",
        report_markdown=report_data["markdown"],
        generated_at=report_data["generated_at"]
    )


@app.route("/reports/download/proposal-pdf")
def download_proposal_pdf():
    pdf_path = BASE_DIR / "Proposed-structure-hackathon.pdf"
    if pdf_path.exists():
        return send_file(str(pdf_path), as_attachment=True, download_name="Proposed-structure-hackathon.pdf")
    flash("Proposal PDF not found. Recompiling...", "warning")
    from generate_proposal_pdf import generate_pdf
    generate_pdf()
    return send_file(str(pdf_path), as_attachment=True, download_name="Proposed-structure-hackathon.pdf")


# ------------------------------------------------------------------------------
# 10. Settings & Approved Scope Policy
# ------------------------------------------------------------------------------
@app.route("/settings")
def settings_page():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings = {r["key"]: r["value"] for r in cursor.fetchall()}
    conn.close()
    return render_template("settings.html", active_page="settings", settings=settings)


@app.route("/settings/save", methods=["POST"])
def save_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    for key in ["organization_name", "scan_interval_minutes", "socket_timeout_seconds", "allowed_ports"]:
        val = request.form.get(key)
        if val:
            cursor.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", (key, val, now_str))
    conn.commit()
    conn.close()
    flash("Settings updated successfully.", "success")
    return redirect(url_for("settings_page"))


if __name__ == "__main__":
    print("[*] Starting AIORI-3 PS-011 Attack-Surface Inventory & Change Monitor...")
    print("    URL: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
