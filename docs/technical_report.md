# AIORI-3 Technical Report: PS-011 Authorised Attack-Surface Inventory and Change Monitor

**Project Name:** Cyber Warriors — Attack Surface Monitor (ASM Sentinel)  
**Problem Statement:** PS-011: Authorised Attack-Surface Inventory and Change Monitor  
**Category:** Cybersecurity  
**Hackathon:** AIORI-3 (Advanced Internet Operations Research in India)  
**Author Team:** Cyber Warriors  
**GitHub Repository:** `https://github.com/dakshhpvt-sudo/Cyber-Warriors`  
**Document Status:** Complete Draft & Reference for Official Template Submission  

> **Note on Submission Template:** This report contains all technical disclosures, data schemas, architectures, test results, and ethical boundaries required by the PS-011 problem statement. If the hackathon organizers require the separate `Proposed-structure-hackathon.pdf` format, the compiled PDF file [`Proposed-structure-hackathon.pdf`](../Proposed-structure-hackathon.pdf) in this repository fulfills that specific deliverable.

---

## 1. Executive Summary

Modern enterprise networks span multiple cloud providers (AWS, Azure, GCP, GitHub), SaaS platforms, and internal infrastructure. Over time, digital assets inadvertently accumulate: forgotten staging subdomains, expired TLS certificates, developer debug ports left open, and abandoned DNS CNAME records pointing to decommissioned cloud buckets or instances. These hygiene gaps represent low-complexity, high-impact attack vectors.

**Cyber Warriors** has designed and implemented a production-grade, authorized attack-surface discovery and monitoring system for PS-011. The application operates strictly within an organizer-approved lab scope of **up to 20 domains and 10 hosts**, executing four modular inspection checks:
1. Public DNS record cataloging & dangling CNAME candidate detection.
2. TLS/HTTPS certificate validity and expiration analysis.
3. Selected TCP port reachability, service banner identification, and HTTP application auditing.
4. Versioned golden baseline comparison and security findings lifecycle management.

The entire solution runs locally on Windows 10/11 without requiring Linux, Docker, or external cloud infrastructure. It includes automated tests, false-positive triage logic, CSV/Markdown export capabilities, and an interactive light-themed web dashboard with a Navy-Blue color palette.

---

## 2. Problem Statement & Objectives

### 2.1 The Challenge (PS-011)
Organizations operating multi-cloud infrastructure accumulate exposed digital assets:
- **Unmaintained subdomains & dangling CNAMEs:** Records pointing to released cloud resources (e.g. decommissioned AWS S3 buckets, deleted GitHub Pages sites, or expired Heroku apps).
- **Expired TLS certificates:** Causing browser trust failures, user warnings, and service outages.
- **Rogue & unexpected open service ports:** Internal developer servers or debug interfaces exposed to untrusted networks.
- **Asset drift:** Uncontrolled modifications occurring between security audits.

### 2.2 Core Objectives
- Enforce strict server-side scope boundaries: **limit of up to 20 lab domains and 10 hosts**.
- Implement **four documented monitoring checks** that evaluate endpoints safely.
- Maintain an active **baseline inventory** and compute change deltas on every scan.
- Detect seeded test vulnerabilities:
  - Expired TLS certificate (`expired-tls.aiori.internal`).
  - Unexpected open service port (`10.0.1.15:8888` - Rogue Debug Console).
  - Potential dangling DNS CNAME records (`AWS S3 NoSuchBucket` & `GitHub Pages 404`).
- Apply a **false-positive analysis framework** with confidence scoring, recognizing that not every unreachable destination or CDN 404 is exploitable.
- Strictly adhere to ethical standards: **no exploitation, no brute-forcing, no unauthorized takeovers**.

---

## 3. System Architecture & Workflow

```
                               ┌────────────────────────────────────────────────────────┐
                               │           Approved Scope & Policy Enforcer             │
                               │      (modules/scope_manager.py: Max 20 Dom / 10 Host)  │
                               └───────────────────────────┬────────────────────────────┘
                                                           │ Target Validated In-Scope
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

### Architectural Flow:
1. **Scope Validation:** Prior to any lookup or connect attempt, `ScopeManager` verifies that the domain or IP exists in the database with `is_approved = 1`. Any out-of-scope input raises `ScopeViolationError`.
2. **Observation Capture:** Checks 1, 2, and 3 run non-intrusive queries against approved assets and record timestamped observations into SQLite.
3. **Delta Comparison:** Check 4 compares current observations against the active baseline snapshot, recording `change_events`.
4. **Findings & Triage:** Significant changes generate `security_findings` populated with severity ratings, confidence assessments, false-positive risk evaluations, and defensive recommendations.
5. **Presentation & Export:** The Flask frontend displays observations in real-time tables with Chart.js analytics, providing CSV and Markdown export capabilities.

---

## 4. Technologies Used

| Layer | Technology | Justification & Role in Project |
| :--- | :--- | :--- |
| **Backend Language** | Python 3.10+ | Clean standard library network stack (`socket`, `ssl`, `sqlite3`, `threading`). |
| **Web Framework** | Flask 3.x | Lightweight, beginner-friendly web server; no complex ORM overhead. |
| **Database** | SQLite 3 | Zero-configuration local database with foreign keys, parameterised queries, and ACID reliability. |
| **DNS Resolution** | `dnspython` | Standard asynchronous DNS record querying (A, AAAA, CNAME, MX) with fallback. |
| **Cryptography** | `cryptography.x509` | Robust cryptographic parsing of X.509 DER certificates (validity dates, issuer, SANs). |
| **Frontend UI/UX** | HTML5, CSS3, JS | Light theme with navy-blue palette (`#0f172a`, `#1e3a8a`, `#2563eb`), subtle shadows, clean cards. |
| **Data Visualization** | Chart.js | Visual severity donut charts and asset inventory distribution bar charts. |
| **PDF Generation** | ReportLab | Compiles formal hackathon proposal PDF (`Proposed-structure-hackathon.pdf`). |

---

## 5. Implemented Features & The 4 Documented Checks

### Check 1: DNS Records & Dangling CNAME Candidate Detection
- **Purpose:** Catalogs public DNS zone records (A, AAAA, CNAME, MX) for approved lab domains and flags potential dangling CNAME records for manual verification.
- **Inputs:** Approved domain string, query timeout (default 3.0 seconds).
- **Outputs:** Record type, value, TTL, `is_dangling_candidate` (0/1), provider string, reason.
- **Dangling CNAME Logic:**
  - Evaluates CNAME destinations against 9 known cloud providers (AWS S3, Elastic Beanstalk, GitHub Pages, Azure App Service, Heroku, Shopify, Fastly, Pantheon).
  - Checks if the destination fails to resolve (`NXDOMAIN`).
  - Probes for unlinked cloud provider error signatures (e.g. `NoSuchBucket`, `There isn't a GitHub Pages site here`, `404 Web Site not found`).
- **Ethical Limitation:** Explicitly flags records as *candidates requiring verification*; does not claim exploitability or attempt subdomain takeovers.

### Check 2: TLS Certificate Validity & Expiration
- **Purpose:** Inspects transport layer certificates on HTTPS endpoints via Server Name Indication (SNI).
- **Inputs:** Approved domain or host IP, port 443, socket timeout.
- **Outputs:** `is_valid`, `is_expired`, `days_to_expiry`, `not_before`, `not_after`, issuer CA, subject Common Name, Subject Alternative Names (`sans`), TLS version, cipher suite.
- **Error Handling:** Distinguishes an expired certificate from connection timeouts or refused connections. Uses `CERT_NONE` verification mode strictly for inventory cataloging so untrusted or expired certificates can still be parsed.

### Check 3: Selected TCP Ports & Services
- **Purpose:** Probes reachability and identifies daemon banners on explicitly allowlisted ports for approved lab hosts.
- **Inputs:** Approved host IP, documented ports allowlist (`[22, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 8888, 9090]`).
- **Outputs:** State (`OPEN`, `CLOSED`, `FILTERED`), latency (ms), service name, raw banner snippet, HTTP `<title>`, Server header, `is_unexpected` (0/1).
- **Limitations & Safety:** Uses RFC 793 connect handshakes. Flags newly reachable ports outside the host baseline as unexpected. Never executes brute-force or exploitation attempts.

### Check 4: Baseline Comparison & Change Detection
- **Purpose:** Compares the observations of a completed scan against the active golden baseline inventory snapshot.
- **Inputs:** Current `scan_run_id`, active `baseline_id`.
- **Outputs:** `change_events` and deduplicated `security_findings`.
- **Deduplication:** Verifies whether an identical unresolved finding already exists for the asset before inserting, preventing alert fatigue.
- **Triage Lifecycle:** Supports updating finding status to `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, or `FALSE_POSITIVE` with reviewer audit notes.

---

## 6. Seeded Issue Testing & Actual Test Results

The application includes a built-in synthetic test harness (`modules/seeded_lab.py`) that simulates multi-cloud asset drift safely:

| Seeded Test Case | Target Asset | Detection Mechanism | Actual Severity | Real Test Result |
| :--- | :--- | :--- | :--- | :--- |
| **1. Expired TLS Certificate** | `expired-tls.aiori.internal` | X.509 validity ended 30 days ago in UTC | `CRITICAL` | **PASSED** (Detected 30 days expired) |
| **2. Unexpected Open Service** | `10.0.1.15:8888` | Unapproved port opened outside host baseline | `HIGH` | **PASSED** (Flagged Werkzeug debug server) |
| **3. Dangling DNS (AWS S3)** | `orphaned-bucket.aiori.internal` | CNAME target matches `NoSuchBucket` | `HIGH` | **PASSED** (Flagged S3 unlinked bucket) |
| **4. Dangling DNS (GitHub Pages)** | `blog.aiori.internal` | CNAME target matches `There isn't a GitHub Pages site here` | `HIGH` | **PASSED** (Flagged orphan GitHub Pages CNAME) |
| **5. False-Positive Control** | `test-cdn.aiori.internal` | Multi-tenant CDN edge 404 (`CloudFront`) | `HIGH` | **PASSED** (Scored Low Confidence / High FP Risk) |

### Automated Unit Test Results
Running `python -m unittest discover tests` executes 14 unit tests across all project modules:
```text
C:\Users\DAKSH JAIN\Desktop\Cyber Warriors> python -m unittest discover tests
..............
----------------------------------------------------------------------
Ran 14 tests in 1.707s

OK
```
- `tests/test_scope.py`: Verifies domain/host syntax validation, capacity bounds, and rejection of out-of-scope targets.
- `tests/test_dns.py`: Verifies Check 1 DNS parsing and dangling CNAME signature matching.
- `tests/test_tls.py`: Verifies Check 2 X.509 validity parsing, expiration calculation, and SAN extraction.
- `tests/test_ports.py`: Verifies Check 3 TCP port reachability and unexpected service detection.
- `tests/test_changes.py`: Verifies Check 4 baseline comparison, change generation, and finding triage updates.

---

## 7. False-Positive Analysis & Limitations

### 7.1 False-Positive Mitigation Strategies
In enterprise attack-surface management, false positives cause significant alert fatigue. The project applies four specific triage filters:
1. **Multi-Tenant CDN vs. Dedicated Bucket:** Edge CDNs (e.g., AWS CloudFront, Fastly) return HTTP 404 when an unknown Host header is received, even if the distribution is properly owned. The engine scores CDN 404s with **Confidence: LOW / False-Positive Risk: HIGH**, whereas AWS S3 `NoSuchBucket` XML returns **Confidence: HIGH**.
2. **Wildcard DNS Protection:** The engine flags that catch-all zones must be verified against non-existent randomized hostnames before alerting.
3. **Firewall SYN-Proxy Filtering:** Port density metrics evaluate if a host responds on all ports indiscriminately (e.g. firewall port reflector).
4. **SNI Enforcement:** Enforces Server Name Indication on all TLS handshakes to avoid false expired cert alerts from fallback default certificates.

### 7.2 Known Limitations
- **Private Lab TLDs:** In offline local environments, internal test domains (e.g., `*.aiori.internal`) resolve via the synthetic test harness or local `hosts` file rather than public root DNS servers.
- **Passive Fingerprinting:** Service banners are captured using non-intrusive greetings. If a daemon remains completely silent and does not speak HTTP, it is classified by its well-known port mapping.

---

## 8. Pseudocode for Prototype Demonstration

```python
FUNCTION RunContinuousMonitoringCycle(scopeConfig, isBaseline=False):
    # 1. Enforce Organiser-Approved Boundaries (Max 20 Domains, 10 Hosts)
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

## 9. Conclusion & Future Roadmap

The **Cyber Warriors Attack-Surface Monitor** provides an authorized, reliable, and beginner-understandable security monitoring platform tailored to hackathon guidelines. It proves that continuous asset discovery and baseline change detection can be accomplished with standard Python networking primitives, robust SQLite persistence, and an intuitive light-theme web dashboard.

### Planned Enhancements:
- **Webhook Alert Dispatchers:** Native integration with Slack and Microsoft Teams for immediate security notifications.
- **Automated Certificate Renewal Hooks:** Integrating ACME/Let's Encrypt automated verification triggers.
- **Passive CT Log Ingestion:** Querying public Certificate Transparency logs for automatic subdomain discovery within approved parent zones.

---

## 10. References
1. **OWASP Web Security Testing Guide (WSTG):** [https://owasp.org/www-project-web-security-testing-guide/](https://owasp.org/www-project-web-security-testing-guide/) (WSTG-INFO-04 to 08: Subdomain Enumeration, Service Discovery, DNS & TLS Analysis).
2. **RFC 793:** Transmission Control Protocol (TCP) Specification.
3. **RFC 8446:** The Transport Layer Security (TLS) Protocol Version 1.3.
4. **RFC 1035:** Domain Names — Implementation and Specification.
