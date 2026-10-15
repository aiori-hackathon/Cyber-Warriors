# PS-011: Authorised Attack-Surface Inventory and Change Monitor

[![Category: Cybersecurity](https://img.shields.io/badge/Category-Cybersecurity-red.svg)](https://owasp.org)
[![Hackathon: AIORI--3](https://img.shields.io/badge/Hackathon-AIORI--3-blue.svg)](https://github.com/aiori-hackathon)
[![Problem Statement: PS--011](https://img.shields.io/badge/Problem-PS--011-emerald.svg)](#)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![UI: Light Theme Navy Blue](https://img.shields.io/badge/UI-Navy%20%26%20White-navy.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#)

---

## 1. Project Objective

Organizations operating multi-cloud infrastructure frequently accumulate exposed digital assets over time: unmaintained test subdomains, expired TLS certificates, open service ports, and dangling DNS CNAME records pointing to decommissioned cloud instances.

This project delivers an **authorised attack-surface discovery and monitoring system** designed to track a defined lab portfolio of **up to 20 domains and 10 hosts**. The application:
- Catalogs public DNS records and flags potential dangling CNAME records for manual verification.
- Audits TLS certificates (validity dates, issuer, days to expiry, and expired state).
- Probes explicitly allowlisted TCP ports using standard, non-intrusive RFC 793 connect handshakes.
- Maintains a versioned golden baseline inventory and identifies asset/service drift.
- Categorizes security findings, manages finding lifecycles (Open, Acknowledged, Resolved, False Positive), and exports CSV datasets and technical reports.
- Enforces strict ethical scope boundaries: zero exploitation, zero brute-forcing, and rejection of out-of-scope targets.

---

## 2. Technology Stack

- **Backend & Logic:** Python 3.10+ (using standard library `ssl`, `socket`, `sqlite3`, `threading`)
- **Web Framework:** Flask 3.x
- **Database:** SQLite with parameterised queries and foreign key constraints
- **DNS Lookups:** `dnspython` with standard socket fallback
- **Frontend UI/UX:** HTML5, CSS3 (Light theme with Navy-Blue palette `#0f172a`, `#1e3a8a`, subtle shadows, responsive sidebar), Vanilla JavaScript
- **Data Visualizations:** Chart.js (Findings Severity Donut & Asset Distribution Bar charts)
- **Deployment:** 100% Local execution on Windows 10/11. No Linux, Docker, or external cloud dependencies required.

---

## 3. System Architecture

```
                               ┌────────────────────────────────────────────────────────┐
                               │           Approved Scope & Policy Enforcer             │
                               │      (modules/scope_manager.py: Max 20 Dom / 10 Host)  │
                               └───────────────────────────┬────────────────────────────┘
                                                           │ Verified In-Scope
                                                           ▼
                             ┌──────────────────────────────────────────────────────────┐
                             │               Multi-Layer Monitoring Checks              │
                             ├─────────────────────────────┬────────────────────────────┤
                             │ Check 1: DNS Records        │ Check 2: TLS Certificates  │
                             │ (modules/dns_checker.py)    │ (modules/tls_checker.py)   │
                             ├─────────────────────────────┼────────────────────────────┤
                             │ Check 3: Ports & Services   │ Check 4: Baseline Engine   │
                             │ (modules/port_checker.py)   │ (modules/change_detector)  │
                             └──────────────┬──────────────┴─────────────┬──────────────┘
                                            │                            │
                                            ▼                            ▼
                             ┌─────────────────────────────┐ ┌──────────────────────────┐
                             │      SQLite Database        │ │  Background Scheduler    │
                             │   (data/asm_database.sqlite)│ │  (modules/scheduler.py)  │
                             └──────────────┬──────────────┘ └──────────────────────────┘
                                            │
                                            ▼
                             ┌──────────────────────────────────────────────────────────┐
                             │       Flask Web Application & REST API (app.py)          │
                             ├─────────────────────────────┬────────────────────────────┤
                             │ Light-Theme Navy-Blue UI    │ Findings Triage & Reports  │
                             │ (Chart.js, Modals, Filters) │ (CSV & Markdown Exports)   │
                             └─────────────────────────────┴────────────────────────────┘
```

---

## 4. The 4 Documented Monitoring Checks

### Check 1: DNS Records & Dangling CNAME Candidates
- **Purpose:** Catalogs public DNS zone records (A, AAAA, CNAME, MX) and flags potential dangling CNAME records for manual verification.
- **Inputs:** Approved domain name, timeout (3.0s).
- **Outputs:** Record type, value, TTL, `is_dangling_candidate` (0/1), provider (e.g. AWS S3, GitHub Pages, Azure), reason.
- **Limitations & Safety:** Non-intrusive DNS queries. Does **not** claim a record is exploitable merely because destination fails to resolve. Handles timeouts and NXDOMAIN gracefully without crashing.

### Check 2: TLS Certificate Validity & Expiration
- **Purpose:** Evaluates transport layer cryptographic certificates on approved HTTPS endpoints using Server Name Indication (SNI).
- **Inputs:** Target domain or host IP, port (443), timeout.
- **Outputs:** `is_valid`, `is_expired`, `days_to_expiry`, `not_before`, `not_after`, issuer CA, subject, SANs, TLS version, cipher suite.
- **Error Handling:** Distinguishes an expired certificate (`is_expired = 1`) from other network failures (connection refused, timeout, handshake failure). Uses `CERT_NONE` so expired or self-signed certs can still be inspected.

### Check 3: Selected TCP Ports & Services
- **Purpose:** Inspects reachability, RTT latency, service banners, and HTTP applications on an explicitly allowlisted set of ports for approved hosts.
- **Inputs:** Host IP address, allowlisted ports list (e.g. `[22, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 8888, 9090]`).
- **Outputs:** State (`OPEN`, `CLOSED`, `FILTERED`), latency in ms, service name, raw banner snippet, HTTP title, Server header, `is_unexpected` (0/1).
- **Limitations & Safety:** Non-flooding RFC 793 connect handshake only. Never performs brute-force or exploitation. Flagged as unexpected if port is not in host's baseline approval matrix.

### Check 4: Baseline Comparison & Change Detection
- **Purpose:** Compares the observations of a completed scan against the active golden baseline inventory, recording deltas and generating actionable security findings.
- **Inputs:** `scan_run_id`, active `baseline_id`.
- **Outputs:** Change events (`NEW_UNEXPECTED_SERVICE`, `TLS_CERT_EXPIRED`, `DANGLING_DNS_DETECTED`, `NEW_OPEN_PORT`, `CLOSED_PORT`), Security findings with severity and false-positive risk.
- **Deduplication:** Prevents generating duplicate alerts for unchanged findings across consecutive scans.

---

## 5. Seeded-Issue Testing & Reproducible Test Cases

The application includes a built-in synthetic test harness (`modules/seeded_lab.py`) that demonstrates the detection of all mandated seeded vulnerabilities without creating external vulnerable infrastructure:

| Seeded Test Case | Target Asset | Expected Detection | Severity | Confidence & FP Risk |
| :--- | :--- | :--- | :--- | :--- |
| **1. Expired TLS Certificate** | `expired-tls.aiori.internal` | Validity ended 30 days ago in UTC | `CRITICAL` | Conf: **HIGH** / FP Risk: **LOW** |
| **2. Unexpected Open Service** | `10.0.1.15:8888` (Debug Console) | Unapproved port opened outside baseline | `HIGH` | Conf: **HIGH** / FP Risk: **LOW** |
| **3. Dangling DNS (AWS S3)** | `orphaned-bucket.aiori.internal` | CNAME target matches `NoSuchBucket` | `HIGH` | Conf: **HIGH** / FP Risk: **LOW** |
| **4. Dangling DNS (GitHub Pages)** | `blog.aiori.internal` | Target matches `There isn't a GitHub Pages site here` | `HIGH` | Conf: **HIGH** / FP Risk: **LOW** |
| **5. False-Positive Control** | `test-cdn.aiori.internal` | Multi-tenant CDN edge 404 (CloudFront) | `HIGH` | Conf: **LOW** / FP Risk: **HIGH** |

### Reproducing the Seeded Tests
- Via Web UI: Click **"Run Seeded Demo"** button on the top navigation bar.
- Via CLI: Run `python main.py demo` or execute the unit tests: `python -m unittest discover tests`.

---

## 6. Windows Installation & Setup Instructions

### Prerequisites
- Windows 10 or Windows 11
- Python 3.10 or higher installed (ensure "Add Python to PATH" was checked during install)

### Step 1: Open PowerShell / Command Prompt
Open PowerShell and navigate to the project directory:
```powershell
cd "C:\Users\DAKSH JAIN\.gemini\antigravity\scratch\attack-surface-monitor"
```

### Step 2: (Optional) Create & Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Run Automated Verification Tests
Verify all 14 unit tests pass cleanly:
```powershell
python -m unittest discover tests
```

### Step 5: Launch the Web Application
```powershell
python app.py
```
Open your web browser and navigate to:  
👉 **`http://127.0.0.1:5000`**

---

## 7. How to Use & Demonstrate to Mentors

### Mentor Demonstration Script (Step-by-Step)

1. **Overview & Scope Verification (Dashboard):**
   - Open `http://127.0.0.1:5000`.
   - Point out the **Navy-Blue and White light theme** design, metric cards (20 Domains / 10 Hosts), and Chart.js visualizations.
   - Show that the initial Golden Baseline is pre-loaded with clean observations (0 initial alerts).

2. **Triggering Seeded Drift Demonstration:**
   - Click the **"Run Seeded Demo"** button in the top header.
   - The system executes the simulated scan, passes it through Check 4 (Change Detector), and generates 5 actionable alerts.
   - Show the **Seeded-Issue Status Banner** confirming detection of:
     - Expired TLS Certificate (`expired-tls.aiori.internal`)
     - Unexpected Open Service (`10.0.1.15:8888`)
     - Dangling DNS CNAMEs (`AWS S3` & `GitHub Pages`)
     - False-Positive Control (`CloudFront` scored with Low Confidence / High FP Risk).

3. **Demonstrating The 4 Documented Checks:**
   - Navigate to **DNS Monitoring (`/dns`)**: Show cataloged records and flagged dangling CNAME candidates.
   - Navigate to **TLS Monitoring (`/tls`)**: Show certificate expiration countdowns, SANs, and expired state flags.
   - Navigate to **Port & Service Monitoring (`/ports`)**: Show reachability, latency, service banners, and unexpected port tags.
   - Navigate to **Change History (`/changes`)**: Show the delta between the current inventory and the golden baseline.

4. **Demonstrating Findings Triage:**
   - Navigate to **Security Findings (`/findings`)**: Filter by `OPEN` status.
   - Click **"Triage"** on any finding.
   - Update its review status to `ACKNOWLEDGED`, `RESOLVED`, or `FALSE_POSITIVE`, enter review notes, and save.

5. **Demonstrating Reports & Data Exports:**
   - Navigate to **Reports & Exports (`/reports`)**.
   - Download CSV exports for Assets, DNS, TLS, Ports, Findings, or Changes.
   - Click **"Download PDF"** to download the official `Proposed-structure-hackathon.pdf`.

6. **Resetting to Golden Baseline:**
   - Click **"Reset Baseline"** to demonstrate that the baseline comparison engine resets findings back to zero.

---

## 8. Pseudocode for the 4 Checks & Baseline Comparison

```python
FUNCTION RunContinuousMonitoringCycle(scopeConfig, isBaseline=False):
    # 1. Scope Enforcement (Max 20 Domains, 10 Hosts)
    domains = ScopeManager.GetApprovedDomains(limit=20)
    hosts   = ScopeManager.GetApprovedHosts(limit=10)

    scanRunId = Database.CreateScanRun(status="RUNNING")

    # 2. Check 1 (DNS) and Check 2 (TLS)
    FOR EACH domain IN domains:
        records = Check1_DNS(domain, recordTypes=["A", "AAAA", "CNAME", "MX"])
        FOR EACH rec IN records WHERE rec.Type == "CNAME":
            isDangling, provider, reason = EvaluateDanglingCandidate(rec.Value)
            IF isDangling: rec.FlagDangling(provider, reason)
        Database.SaveDNSObservations(scanRunId, domain, records)

        cert = Check2_TLS(domain, port=443)
        Database.SaveTLSObservation(scanRunId, domain, cert)

    # 3. Check 3: Selected Ports & Services
    FOR EACH host IN hosts:
        FOR EACH port IN scopeConfig.allowedPorts:
            isOpen, rtt = Check3_TCPConnect(host, port)
            IF isOpen:
                banner, service = GrabBanner(host, port)
                isUnexpected = (port NOT IN scopeConfig.baselineServices[host])
                Database.SavePortObservation(scanRunId, host, port, rtt, service, isUnexpected)

    # 4. Check 4: Baseline Comparison & Change Detection
    baseline = Database.GetActiveBaselineSnapshot()
    diff = Check4_CompareWithBaseline(baselineScanId=baseline.scanId, currentScanId=scanRunId)

    FOR EACH delta IN diff.changes:
        Database.RecordChangeEvent(scanRunId, delta)
        IF NOT Database.FindingAlreadyOpen(delta.target, delta.category):
            confidence, fpRisk = TriageFalsePositive(delta)
            Database.CreateSecurityFinding(scanRunId, delta, confidence, fpRisk)

    Database.CompleteScanRun(scanRunId)
    RETURN diff
```

---

## 9. Deliverables Compliance Checklist

- [x] **Deliverable 1: GitHub Collaboration & Ownership:** Ready for repository creation, adding `aiori-hackathon` as collaborator, and ownership transfer.
- [x] **Deliverable 2: Proposed Structure PDF:** Compiled and available at `Proposed-structure-hackathon.pdf`.
- [x] **Deliverable 3: Mentor Demonstration & Pseudocode:** Documented above and in `docs/MENTOR_DEMO_PSEUDOCODE.md`.
- [x] **Scope Enforcement:** Strict restriction to 20 lab domains and 10 hosts with server-side validation.
- [x] **The 4 Documented Checks:** Fully implemented in `modules/dns_checker.py`, `modules/tls_checker.py`, `modules/port_checker.py`, `modules/change_detector.py`.
- [x] **Seeded Issue Testing:** Fully verifiable via Web UI and automated tests.
- [x] **False-Positive Analysis:** Integrated confidence scoring and triage rationales.
- [x] **Light-Theme Dashboard:** Modern navy-blue and white palette with Chart.js charts and responsive navigation.

---

## 10. References & Standards
- **OWASP Web Security Testing Guide (WSTG):** [https://owasp.org/www-project-web-security-testing-guide/](https://owasp.org/www-project-web-security-testing-guide/)
- **RFC 793:** Transmission Control Protocol (TCP)
- **RFC 8446:** The Transport Layer Security (TLS) Protocol Version 1.3
- **RFC 1035:** Domain Names - Implementation and Specification
