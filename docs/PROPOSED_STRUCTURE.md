# Proposed Structure & Technical Architecture
## AIORI-3 PS-011: Authorised Attack-Surface Inventory and Change Monitor

**Category:** Cybersecurity  
**Problem Statement:** PS-011  
**Hackathon Deliverable Reference:** `Proposed-structure-hackathon.pdf`

---

## 1. Context & Motivation
Enterprises running multi-cloud infrastructure regularly experience asset sprawl. Decommissioned cloud VMs, unmaintained test subdomains, abandoned DNS CNAME entries, and expired TLS certificates accumulate silently across accounts. Attackers actively exploit this delta by hijacking unclaimed cloud buckets or exploiting unmonitored ports.

The **AIORI-3 Authorised Attack-Surface Inventory and Change Monitor** addresses this challenge by establishing an automated, recurring discovery and baseline comparison loop across a bounded scope of up to 20 lab domains and 10 hosts.

---

## 2. Scope & Ethical Guardrails
- **Written, Organiser-Approved Target Scope:** Stored in `config/scope.json`.
- **Target Boundaries:** Maximum 20 lab domains and 10 hosts. Any probe targeting out-of-scope assets is intercepted and halted by `core/scope_guard.py` with `ScopeViolationError`.
- **Non-Exploitation Policy:** The system strictly avoids hostile exploitation, subdomain takeovers, or intrusive payloads. Probes are diagnostic and passive.
- **Dangling Record Classification:** Dangling candidates are flagged as *potential* candidates requiring triage, recognizing that not all dangling records are exploitable.

---

## 3. High-Level System Architecture

```
                    ┌────────────────────────────────────────┐
                    │          Authorised Target Scope       │
                    │ (config/scope.json: 20 Dom / 10 Hosts) │
                    └───────────────────┬────────────────────┘
                                        │ ScopeGuard Validation
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │            Multi-Layer Discovery Engine             │
             ├──────────────────────────┬──────────────────────────┤
             │      DNS Inspector       │    Service Inspector     │
             │   (A, CNAME, Dangling)   │   (4 Documented Checks)  │
             └─────────────┬────────────┴─────────────┬────────────┘
                           │                          │
                           └────────────┬─────────────┘
                                        │ Snapshot Persistence
                                        ▼
                    ┌────────────────────────────────────────┐
                    │       Baseline & Storage Manager       │
                    │    (data/baseline.json & SQLite DB)    │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │          Diff & Alert Engine           │
                    │      (Delta Analysis & Drift)          │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │       False-Positive Analyzer          │
                    │    (Confidence & FP Risk Scoring)      │
                    └───────────────────┬────────────────────┘
                                        │
                    ┌───────────────────┴────────────────────┐
                    ▼                                        ▼
       ┌────────────────────────┐               ┌────────────────────────┐
       │   CLI / Alert Reports  │               │ Interactive Dashboard  │
       │  (Terminal & Markdown) │               │   (Flask Cyber UI)     │
       └────────────────────────┘               └────────────────────────┘
```

---

## 4. The 4 Documented Port & Service Checks
1. **Check 1: TCP Port State & Latency Probe (RFC 793)**  
   Full non-blocking 3-way handshake (`socket.connect_ex`) determining state (`OPEN`, `CLOSED`, `FILTERED`) and RTT latency.
2. **Check 2: Service Banner Grab & Protocol Fingerprint**  
   Non-blocking read and gentle probing to capture service banners, with regex pattern matching for SSH, SMTP, FTP, Redis, MySQL, and HTTP.
3. **Check 3: TLS/SSL Handshake & Negotiation Probe**  
   SNI TLS negotiation testing protocol (TLSv1.2/1.3), cipher suite, and X.509 certificate validity.
4. **Check 4: Application-Layer HTTP/HTTPS Inspection**  
   Safe HTTP probe measuring status code, Server/X-Powered-By headers, HTML `<title>`, tech stack disclosure, and defense headers (HSTS, CSP, X-Frame-Options).

---

## 5. Seeded-Issue Detection Results
The system provides a built-in Lab Harness (`lab_simulator/mock_targets.py`) with 100% verified detection of the required seeded issues:
1. **Expired TLS Certificate:** Detected on `expired-tls.aiori.internal` (`CRITICAL`).
2. **Unexpected Service:** Detected on `10.0.1.15:8888` (Debug Console) (`HIGH`).
3. **Potential Dangling DNS (AWS S3):** Detected on `orphaned-bucket.aiori.internal` (`HIGH`).
4. **Potential Dangling DNS (GitHub Pages):** Detected on `blog.aiori.internal` (`HIGH`).
5. **False-Positive Control:** Multi-tenant CDN edge 404 (`CloudFront`) correctly classified with `Confidence: LOW` and `FP Risk: HIGH`.

---

## 6. False-Positive Analysis Framework
To eliminate false alarms, the triage engine applies multi-factor filters:
- **CDN Multi-Tenant vs Dedicated Namespace:** Recognizes that 404 on CloudFront/Cloudflare is standard routing behavior before Host header binding, whereas AWS S3 `NoSuchBucket` is definitive evidence of an unallocated bucket.
- **Wildcard DNS Protection:** Tests randomized non-existent labels to avoid flagging catch-all zones.
- **Firewall SYN-Proxy Filtering:** Detects artificial port mirroring if open port count exceeds 15.
- **SNI Enforcement:** Uses explicit host headers to avoid default reverse-proxy certificate mismatches.

---

## 7. Compliance Checklist for AIORI-3 Deliverables
- [x] **Deliverable 1: GitHub Collaboration:** Ready for private repo creation and transfer to `aiori-hackathon`.
- [x] **Deliverable 2: Proposed Structure PDF:** Compiled as `Proposed-structure-hackathon.pdf`.
- [x] **Deliverable 3: Mentor Prototype Demonstration & Pseudocode:** Documented in `docs/MENTOR_DEMO_PSEUDOCODE.md`.
- [x] **Scope Enforcement:** Strict restriction to 20 lab domains and 10 hosts.
- [x] **The 4 Documented Checks:** Fully implemented in `checks/service_inspector.py`.
- [x] **Change Detection & Baseline Comparison:** Fully implemented in `core/diff_engine.py`.
- [x] **Seeded Issue Detection:** Verified via unit tests (`lab_simulator/test_scenarios.py`).
- [x] **False-Positive Analysis:** Integrated into all alerts.
- [x] **Interactive Dashboard:** Available via `python main.py web`.
