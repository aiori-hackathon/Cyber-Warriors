# AIORI-3 PS-011: Authorised Attack-Surface Inventory and Change Monitor

[![Category: Cybersecurity](https://img.shields.io/badge/Category-Cybersecurity-red.svg)](https://owasp.org)
[![Hackathon: AIORI--3](https://img.shields.io/badge/Hackathon-AIORI--3-blue.svg)](https://github.com/aiori-hackathon)
[![Problem: PS--011](https://img.shields.io/badge/Problem-PS--011-emerald.svg)](#)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#)

> **Category:** Cybersecurity  
> **Problem Statement:** PS-011: Authorised Attack-Surface Inventory and Change Monitor  
> **AIORI-3 Hackathon Submission**

---

## 🎯 Executive Overview

Organizations operating multi-cloud infrastructure frequently accumulate exposed digital assets over time: unmaintained test subdomains, expired TLS certificates, open service ports, and dangling DNS CNAME records pointing to decommissioned cloud instances.

This project delivers a production-grade, authorized attack-surface discovery and monitoring system designed to monitor a lab portfolio of **up to 20 domains and 10 hosts**. The system catalogs DNS records, verifies TLS certificates, inspects open ports using **4 documented checks**, maintains baseline inventory, detects asset drift, flags seeded vulnerabilities, and applies a multi-factor **false-positive analysis engine** — all within strict written ethical boundaries without aggressive exploitation.

---

## 📋 Hackathon Deliverables Compliance Matrix

| Deliverable Mandated by AIORI-3 | Implementation / Location in Repository | Status |
| :--- | :--- | :--- |
| **1. GitHub Collaboration & Ownership** | See [GitHub Collaboration Guide](#-deliverable-1-github-collaboration-guide) below | ✅ Ready |
| **2. Proposed Structure PDF** | Generated at [`Proposed-structure-hackathon.pdf`](./Proposed-structure-hackathon.pdf) | ✅ Generated & Included |
| **3. Mentor Demonstration & Pseudocode** | Documented in [`docs/MENTOR_DEMO_PSEUDOCODE.md`](./docs/MENTOR_DEMO_PSEUDOCODE.md) | ✅ Complete |
| **Monitor 20 Domains & 10 Hosts** | Configured in [`config/scope.json`](./config/scope.json) & enforced by [`core/scope_guard.py`](./core/scope_guard.py) | ✅ Verified |
| **The 4 Documented Checks** | Implemented in [`checks/service_inspector.py`](./checks/service_inspector.py) | ✅ Verified |
| **Scheduled Inventory Comparisons** | Engine in [`core/diff_engine.py`](./core/diff_engine.py) & [`scheduler/monitor.py`](./scheduler/monitor.py) | ✅ Verified |
| **Detect Seeded Expired Certificates** | Verified on `expired-tls.aiori.internal` (`CRITICAL`) | ✅ Verified |
| **Detect Seeded Unexpected Services** | Verified on `10.0.1.15:8888` (`HIGH`) | ✅ Verified |
| **Detect Seeded Dangling DNS** | Verified on `AWS S3` & `GitHub Pages` CNAMEs (`HIGH`) | ✅ Verified |
| **Report False Positives** | Scored by [`analysis/false_positive.py`](./analysis/false_positive.py) (e.g. CloudFront CDN) | ✅ Verified |
| **Strict Scope & No Exploitation** | Safe passive/active diagnostic probes; zero hostile takeovers | ✅ Compliant |

---

## 🏗️ System Architecture

```
attack-surface-monitor/
├── Proposed-structure-hackathon.pdf  # Deliverable 2: Official Proposal PDF
├── main.py                           # Unified CLI entry point
├── requirements.txt                  # Python dependencies
├── config/
│   └── scope.json                    # Written, organiser-approved target scope (20 dom, 10 hosts)
├── core/
│   ├── models.py                     # Dataclasses (Assets, DNS, TLS, Ports, Diff, Alerts)
│   ├── scope_guard.py                # Strict boundary enforcement & policy check
│   ├── storage.py                    # Baseline snapshot persistence (JSON + SQLite DB)
│   └── diff_engine.py                # Change detection comparing current scan vs baseline
├── checks/
│   ├── service_inspector.py          # THE 4 DOCUMENTED CHECKS (TCP, Banner, TLS, HTTP)
│   ├── dns_inspector.py              # DNS record cataloging & Dangling CNAME detection
│   └── tls_inspector.py              # X.509 certificate parsing & expiry calculation
├── analysis/
│   ├── false_positive.py             # Confidence scoring (High/Med/Low) & triage notes
│   └── alerts.py                     # Actionable alert formatting (Terminal & Markdown)
├── scheduler/
│   └── monitor.py                    # Scheduled continuous monitoring daemon
├── lab_simulator/
│   ├── mock_targets.py               # Seeded issue harness (Expired cert, rogue port, dangling DNS)
│   └── test_scenarios.py             # Automated unit tests for 100% verification
├── ui/
│   ├── app.py                        # Flask Web Dashboard
│   └── templates/
│       └── dashboard.html            # Dark-mode Cybersecurity UI
├── docs/
│   ├── MENTOR_DEMO_PSEUDOCODE.md     # Deliverable 3: Mentor Guide & Pseudocode Snippet
│   ├── 4_DOCUMENTED_CHECKS.md        # Technical deep-dive into the 4 service checks
│   └── PROPOSED_STRUCTURE.md         # Proposal text and architectural specification
└── generate_proposal_pdf.py          # ReportLab script generating Deliverable 2 PDF
```

---

## 🔍 The 4 Documented Port & Service Checks

Every open port is analyzed across 4 distinct protocol layers:

1. **Check 1: TCP Port State & Latency Probe (RFC 793)**  
   *Methodology:* Full non-blocking 3-way handshake (`socket.connect_ex`). Measures latency in milliseconds and classifies state (`OPEN`, `CLOSED`, `FILTERED`).
2. **Check 2: Service Banner Grab & Protocol Fingerprint**  
   *Methodology:* Non-blocking read and safe gentle probes (`\r\n\r\n`). Regex pattern matching identifies daemons: SSH, SMTP, FTP, Redis, MySQL, HTTP.
3. **Check 3: TLS/SSL Handshake & Negotiation Probe (RFC 8446)**  
   *Methodology:* SNI-enabled TLS handshake. Evaluates protocol versions (TLSv1.2/1.3), cipher suites, and parses peer X.509 certificates to calculate days-to-expiry and identify expired certs.
4. **Check 4: Application-Layer HTTP/HTTPS Inspection (RFC 9110)**  
   *Methodology:* Authorized safe HTTP GET probe. Analyzes HTTP status code, HTML `<title>`, server disclosure headers (`Server`, `X-Powered-By`), and security headers (HSTS, CSP, X-Frame-Options).

*For exhaustive technical details, see [`docs/4_DOCUMENTED_CHECKS.md`](./docs/4_DOCUMENTED_CHECKS.md).*

---

## ⚡ Quick Start

### 1. Installation
Clone the repository and install dependencies:
```bash
cd attack-surface-monitor
pip install -r requirements.txt
```

### 2. Run the Mentor Demonstration (Deliverable 3)
Execute the complete end-to-end prototype demonstration with seeded vulnerabilities:
```bash
python main.py demo
```
This single command:
1. Initializes the golden baseline inventory across 20 domains and 10 hosts (0 alerts).
2. Simulates attack surface drift and detects:
   - **CRITICAL:** Expired TLS Certificate (`expired-tls.aiori.internal`)
   - **HIGH:** Unexpected Service Port 8888 (`10.0.1.15:8888` - Rogue Debug Console)
   - **HIGH:** Dangling DNS CNAMEs (`AWS S3 NoSuchBucket` & `GitHub Pages 404`)
   - **CONTROL (High FP Risk / Low Confidence):** Multi-tenant CDN edge 404 (`CloudFront`)
3. Dispatches actionable alerts and generates [`reports/latest_alert_report.md`](./reports/latest_alert_report.md).

### 3. Launch Interactive Cyber Web Dashboard
```bash
python main.py web --port 5000
```
Open your browser at **`http://127.0.0.1:5000`** to view:
- Seeded issue detection status indicators
- Active alerts with false-positive confidence badges
- The 4 Documented Checks explorer
- Real-time inventory table of domains, DNS records, hosts, and open ports
- One-click scan re-triggering and baseline reset

### 4. Run Automated Verification Test Suite
```bash
python -m unittest lab_simulator/test_scenarios.py
```

### 5. Re-compile Proposal PDF (Deliverable 2)
```bash
python main.py report
```
Generates `Proposed-structure-hackathon.pdf`.

---

## 🛡️ Deliverable 1: GitHub Collaboration Guide

Per AIORI-3 Hackathon Deliverable #1 guidelines:
1. **Repository Name:** Name your private GitHub repository according to your team name (e.g. `team-alpha-aiori-ps011`).
2. **Set as Private:** Ensure the repository visibility is set to **Private**.
3. **Add Collaborator:**
   - Go to your repository on GitHub → **Settings** → **Collaborators** → **Add people**.
   - Invite: **`https://github.com/aiori-hackathon`** (`aiori-hackathon`).
4. **Transfer Ownership:**
   - Once the collaboration request has been accepted by all teammates and `aiori-hackathon`:
   - Go to **Settings** → **General** → scroll to the bottom to **Danger Zone** → **Transfer ownership**.
   - Transfer repository ownership to: **`aiori-hackathon`**.

---

## 🔒 Scope & Ethical Guardrails

- **Strict Scope Enforcement:** Only targets listed in [`config/scope.json`](./config/scope.json) can be scanned. Scanning out-of-scope targets is rejected with `ScopeViolationError`.
- **Non-Exploitation Standard:** In strict compliance with hackathon rules, this tool does **not** perform exploitation, brute-forcing, or unauthorized takeovers. Probes are non-intrusive and diagnostic.
- **Dangling Record Integrity:** Dangling DNS records are classified as *potential candidates* with explicit verification criteria, recognizing that not every dangling record is vulnerable to takeover.

---

## 📚 References & Standards
- **OWASP Web Security Testing Guide (WSTG):** [https://owasp.org/www-project-web-security-testing-guide/](https://owasp.org/www-project-web-security-testing-guide/) (WSTG-INFO-04 to 08: Subdomain Enumeration, Service Discovery, DNS & TLS Analysis)
- **RFC 793:** Transmission Control Protocol (TCP)
- **RFC 8446:** The Transport Layer Security (TLS) Protocol Version 1.3
- **RFC 1035:** Domain Names - Implementation and Specification
