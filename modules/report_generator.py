"""
Report Generator module for AIORI-3 PS-011.
Provides export functions:
  - CSV exports for Inventory, DNS, TLS, Ports, Changes, Findings.
  - Full Technical Markdown & Printable HTML report with False-Positive analysis.
"""

import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

from database import get_db_connection
from config import REPORTS_DIR


class ReportGenerator:
    @classmethod
    def export_csv(cls, table_name: str) -> str:
        """Generates CSV string content for the requested data category."""
        conn = get_db_connection()
        cursor = conn.cursor()

        output = io.StringIO()
        writer = csv.writer(output)

        if table_name == "assets":
            cursor.execute("SELECT id, name, asset_type, value, ip_address, is_approved, created_at FROM assets")
            writer.writerow(["ID", "Name", "Type", "Target Value", "IP Address", "Approved", "Created At"])
            for r in cursor.fetchall():
                writer.writerow([r["id"], r["name"], r["asset_type"], r["value"], r["ip_address"], "Yes" if r["is_approved"] else "No", r["created_at"]])

        elif table_name == "dns":
            cursor.execute("""
                SELECT d.id, d.domain, d.record_type, d.record_value, d.ttl, d.is_dangling_candidate, d.dangling_provider, d.observed_at
                FROM dns_observations d ORDER BY d.id DESC LIMIT 500
            """)
            writer.writerow(["ID", "Domain", "Record Type", "Record Value", "TTL", "Is Dangling Candidate", "Provider", "Observed At"])
            for r in cursor.fetchall():
                writer.writerow([r["id"], r["domain"], r["record_type"], r["record_value"], r["ttl"], "Yes" if r["is_dangling_candidate"] else "No", r["dangling_provider"] or "N/A", r["observed_at"]])

        elif table_name == "tls":
            cursor.execute("""
                SELECT t.id, t.domain, t.port, t.is_valid, t.is_expired, t.days_to_expiry, t.not_after, t.issuer, t.tls_version, t.cipher_suite
                FROM tls_observations t ORDER BY t.id DESC LIMIT 500
            """)
            writer.writerow(["ID", "Domain", "Port", "Valid", "Expired", "Days to Expiry", "Expiry Date", "Issuer", "TLS Version", "Cipher"])
            for r in cursor.fetchall():
                writer.writerow([r["id"], r["domain"], r["port"], "Yes" if r["is_valid"] else "No", "Yes" if r["is_expired"] else "No", r["days_to_expiry"], r["not_after"], r["issuer"], r["tls_version"], r["cipher_suite"]])

        elif table_name == "ports":
            cursor.execute("""
                SELECT p.id, p.host_ip, p.port, p.state, p.latency_ms, p.service_name, p.is_unexpected, p.server_header, p.observed_at
                FROM port_observations p ORDER BY p.id DESC LIMIT 500
            """)
            writer.writerow(["ID", "Host IP", "Port", "State", "Latency (ms)", "Service", "Unexpected Port", "Server Header", "Observed At"])
            for r in cursor.fetchall():
                writer.writerow([r["id"], r["host_ip"], r["port"], r["state"], r["latency_ms"], r["service_name"], "Yes" if r["is_unexpected"] else "No", r["server_header"] or "N/A", r["observed_at"]])

        elif table_name == "findings":
            cursor.execute("""
                SELECT f.id, f.category, f.severity, f.title, f.description, f.status, f.confidence, f.false_positive_risk, f.defensive_action, f.created_at
                FROM security_findings f ORDER BY f.id DESC
            """)
            writer.writerow(["ID", "Category", "Severity", "Title", "Description", "Status", "Confidence", "FP Risk", "Defensive Action", "Created At"])
            for r in cursor.fetchall():
                writer.writerow([r["id"], r["category"], r["severity"], r["title"], r["description"], r["status"], r["confidence"], r["false_positive_risk"], r["defensive_action"], r["created_at"]])

        elif table_name == "changes":
            cursor.execute("""
                SELECT c.id, c.change_type, c.severity, c.title, c.description, c.detected_at
                FROM change_events c ORDER BY c.id DESC
            """)
            writer.writerow(["ID", "Change Type", "Severity", "Title", "Description", "Detected At"])
            for r in cursor.fetchall():
                writer.writerow([r["id"], r["change_type"], r["severity"], r["title"], r["description"], r["detected_at"]])

        conn.close()
        return output.getvalue()

    @classmethod
    def generate_full_technical_report(cls) -> Dict[str, Any]:
        """Generates comprehensive technical report text for mentors and compliance audit."""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM assets WHERE asset_type = 'domain' AND is_approved = 1")
        dom_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM assets WHERE asset_type = 'host' AND is_approved = 1")
        host_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM security_findings WHERE status = 'OPEN'")
        open_findings = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM change_events")
        total_changes = cursor.fetchone()[0]

        cursor.execute("SELECT * FROM security_findings ORDER BY id DESC")
        findings = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM change_events ORDER BY id DESC LIMIT 50")
        changes = [dict(r) for r in cursor.fetchall()]

        conn.close()

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        md_content = f"""# AIORI-3 Cybersecurity Hackathon — Technical Report
## Project PS-011: Authorised Attack-Surface Inventory and Change Monitor
**Date Generated:** {now_str}  
**Classification:** Authorised Security Research / Lab Audit  
**Author:** AIORI-3 Project Team  

---

## 1. Executive Summary
This report documents the security posture, asset drift, and vulnerability observations identified by the **Authorised Attack-Surface Inventory and Change Monitor**. The system actively tracks a bounded portfolio of **{dom_count} lab domains** and **{host_count} lab hosts**.

- **Active Open Findings:** {open_findings}
- **Recorded Change Events:** {total_changes}
- **Strict Scope Boundaries:** Enforced (Limit 20 Domains / 10 Hosts)
- **Non-Exploitation Standard:** Enforced (Diagnostic non-intrusive probes only)

---

## 2. The 4 Documented Port and Service Checks
The monitoring system evaluates all in-scope endpoints across four documented inspection layers:
1. **Check 1: DNS Records & Dangling CNAME Candidate Detection:** Evaluates A, AAAA, CNAME, and MX records. Detects unallocated cloud provider destinations (AWS S3, Beanstalk, GitHub Pages, Azure, Heroku) without aggressive takeovers.
2. **Check 2: TLS Certificate Verification:** Analyzes peer certificates using X.509 cryptographic validation. Identifies expired certs, calculates days to expiry, and audits SANs.
3. **Check 3: Selected TCP Ports & Services:** Inspects only allowlisted ports with RFC 793 connect probes, banner grabbing, and HTTP header auditing.
4. **Check 4: Baseline Comparison & Change Detection:** Maintains a versioned golden baseline snapshot. Identifies newly opened ports, unapproved services, DNS drift, and manages findings lifecycle.

---

## 3. Seeded Issues Verification & False-Positive Analysis

| Category | Target Asset | Severity | Status | Confidence | False Positive Probability |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
        for f in findings:
            md_content += f"| `{f['category']}` | `{f['title'][:40]}` | **{f['severity']}** | `{f['status']}` | `{f['confidence']}` | `{f['false_positive_risk']}` |\n"

        md_content += """
---

## 4. False-Positive Analysis Rationales
1. **Multi-Tenant CDNs vs Orphaned Buckets:** CDN edge 404 responses (e.g. CloudFront) frequently occur when host headers are unmapped without meaning the resource is vulnerable to takeover. These are classified with **Confidence: LOW / FP Risk: HIGH**. Conversely, AWS S3 `NoSuchBucket` explicitly confirms namespace availability (**Confidence: HIGH**).
2. **Wildcard DNS Zones:** Catch-all resolvers are filtered to avoid reporting artificial subdomains.
3. **Firewall SYN-Proxies:** Port density metrics detect network sinkholes and port mirrors.

---

## 5. Security Findings Detail & Defensive Actions
"""
        for idx, f in enumerate(findings, 1):
            md_content += f"""
### Finding #{idx}: {f['title']}
- **Category:** `{f['category']}`
- **Severity:** `{f['severity']}` | **Status:** `{f['status']}`
- **Confidence Rating:** `{f['confidence']}` (FP Risk: `{f['false_positive_risk']}`)
- **Description:** {f['description']}
- **Recommended Defensive Action:** {f['defensive_action']}
- **Review Notes:** {f.get('review_notes') or 'None recorded'}
"""

        # Save to file
        report_file = REPORTS_DIR / "technical_report.md"
        report_file.write_text(md_content, encoding="utf-8")

        return {
            "markdown": md_content,
            "path": str(report_file),
            "generated_at": now_str,
            "findings_count": len(findings),
            "changes_count": len(changes)
        }
