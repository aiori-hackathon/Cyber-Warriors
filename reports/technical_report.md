# AIORI-3 Cybersecurity Hackathon — Technical Report
## Project PS-011: Authorised Attack-Surface Inventory and Change Monitor
**Date Generated:** 2026-10-15 05:22:53 UTC  
**Classification:** Authorised Security Research / Lab Audit  
**Author:** AIORI-3 Project Team  

---

## 1. Executive Summary
This report documents the security posture, asset drift, and vulnerability observations identified by the **Authorised Attack-Surface Inventory and Change Monitor**. The system actively tracks a bounded portfolio of **20 lab domains** and **10 lab hosts**.

- **Active Open Findings:** 0
- **Recorded Change Events:** 0
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
| `UNEXPECTED_SERVICE` | `Test Finding` | **HIGH** | `FALSE_POSITIVE` | `HIGH` | `LOW` |

---

## 4. False-Positive Analysis Rationales
1. **Multi-Tenant CDNs vs Orphaned Buckets:** CDN edge 404 responses (e.g. CloudFront) frequently occur when host headers are unmapped without meaning the resource is vulnerable to takeover. These are classified with **Confidence: LOW / FP Risk: HIGH**. Conversely, AWS S3 `NoSuchBucket` explicitly confirms namespace availability (**Confidence: HIGH**).
2. **Wildcard DNS Zones:** Catch-all resolvers are filtered to avoid reporting artificial subdomains.
3. **Firewall SYN-Proxies:** Port density metrics detect network sinkholes and port mirrors.

---

## 5. Security Findings Detail & Defensive Actions

### Finding #1: Test Finding
- **Category:** `UNEXPECTED_SERVICE`
- **Severity:** `HIGH` | **Status:** `FALSE_POSITIVE`
- **Confidence Rating:** `HIGH` (FP Risk: `LOW`)
- **Description:** Test Desc
- **Recommended Defensive Action:** Action
- **Review Notes:** Verified CDN edge
