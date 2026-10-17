# AIORI-3 Cybersecurity Hackathon â€” Technical Report
## Project PS-011: Authorised Attack-Surface Inventory and Change Monitor
**Date Generated:** 2026-10-17 14:47:37 UTC<br>
**Classification:** Authorised Security Research / Lab Audit<br>
**Author:** AIORI-3 Project Team  

---

## 1. Executive Summary
This report documents the security posture, asset drift, and vulnerability observations identified by the **Authorised Attack-Surface Inventory and Change Monitor**. The system actively tracks a bounded portfolio of **20 lab domains** and **10 lab hosts**.

- **Open Findings in Demonstration Dataset:** 7 (seeded test scenarios; not independently verified external vulnerabilities)
- **Triage Breakdown:** 0 Acknowledged | 0 False Positive | 0 Resolved
- **Recorded Change Events:** 10
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

Demonstration-data note: The findings listed in this section represent seeded test scenarios used to demonstrate the monitoring and triage workflow. They must not be interpreted as independently verified vulnerabilities on real external systems. Potential dangling DNS indicators require manual verification, and all results should be interpreted within the authorised lab scope.

| Category | Target Asset | Severity | Status | Confidence | False Positive Probability | Investigator Notes / FP Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `POTENTIAL_DANGLING_DNS` | `Potential Dangling DNS Record Point` | **HIGH** | `OPEN` | `LOW` | `HIGH` | Manual investigator review not recorded |
| `POTENTIAL_DANGLING_DNS` | `Potential Dangling DNS Record Point` | **HIGH** | `OPEN` | `HIGH` | `LOW` | Manual investigator review not recorded |
| `POTENTIAL_DANGLING_DNS` | `Potential Dangling DNS Record Point` | **HIGH** | `OPEN` | `HIGH` | `LOW` | Manual investigator review not recorded |
| `EXPIRED_CERTIFICATE` | `Critical: Expired TLS Certificate o` | **CRITICAL** | `OPEN` | `HIGH` | `LOW` | Manual investigator review not recorded |
| `UNEXPECTED_SERVICE` | `Unexpected Open Service Detected on` | **HIGH** | `OPEN` | `HIGH` | `LOW` | Manual investigator review not recorded |
| `UNEXPECTED_SERVICE` | `Unexpected Open Service Detected on` | **HIGH** | `OPEN` | `HIGH` | `LOW` | Manual investigator review not recorded |
| `UNEXPECTED_SERVICE` | `Unexpected Open Service Detected on` | **HIGH** | `OPEN` | `HIGH` | `LOW` | Manual investigator review not recorded |

---

## 4. False-Positive Analysis Rationales
1. **Multi-Tenant CDNs vs Orphaned Buckets:** CDN edge 404 responses (e.g. CloudFront) frequently occur when host headers are unmapped without meaning the resource is vulnerable to takeover. These are classified with **Confidence: LOW / FP Risk: HIGH**. Conversely, AWS S3 `NoSuchBucket` explicitly confirms namespace availability (**Confidence: HIGH**).
2. **Wildcard DNS Zones:** Catch-all resolvers are filtered to avoid reporting artificial subdomains.
3. **Firewall SYN-Proxies:** Port density metrics detect network sinkholes and port mirrors.

---

## 5. Security Findings Detail & Defensive Actions

### Finding #1: Potential Dangling DNS Record Pointing to AWS CloudFront (test-cdn.aiori.internal)
- **Category:** `POTENTIAL_DANGLING_DNS`
- **Severity:** `HIGH` | **Status:** `OPEN`
- **Confidence Rating:** `LOW` (FP Risk: `HIGH`)
- **Description:** Domain 'test-cdn.aiori.internal' possesses a CNAME pointing to 'd123456789.cloudfront.net' (AWS CloudFront). Detection indicator: Target returned HTTP 404 (Multi-tenant edge distribution). Bounded verification only: no exploitability claimed.
- **Recommended Defensive Action:** Verify whether the AWS CloudFront resource was deleted. Remove orphan CNAME from authoritative DNS zone or reclaim asset.
- **Review Notes:** Manual investigator review not recorded

### Finding #2: Potential Dangling DNS Record Pointing to GitHub Pages (blog.aiori.internal)
- **Category:** `POTENTIAL_DANGLING_DNS`
- **Severity:** `HIGH` | **Status:** `OPEN`
- **Confidence Rating:** `HIGH` (FP Risk: `LOW`)
- **Description:** Domain 'blog.aiori.internal' possesses a CNAME pointing to 'aiori-legacy-blog.github.io' (GitHub Pages). Detection indicator: Target matches GitHub Pages unlinked signature: There isnt a GitHub Pages site here with HTTP 404. Bounded verification only: no exploitability claimed.
- **Recommended Defensive Action:** Verify whether the GitHub Pages resource was deleted. Remove orphan CNAME from authoritative DNS zone or reclaim asset.
- **Review Notes:** Manual investigator review not recorded

### Finding #3: Potential Dangling DNS Record Pointing to AWS S3 (orphaned-bucket.aiori.internal)
- **Category:** `POTENTIAL_DANGLING_DNS`
- **Severity:** `HIGH` | **Status:** `OPEN`
- **Confidence Rating:** `HIGH` (FP Risk: `LOW`)
- **Description:** Domain 'orphaned-bucket.aiori.internal' possesses a CNAME pointing to 'aiori-decommissioned-assets.s3.amazonaws.com' (AWS S3). Detection indicator: Target matches AWS S3 unlinked signature: NoSuchBucket with HTTP 404. Bounded verification only: no exploitability claimed.
- **Recommended Defensive Action:** Verify whether the AWS S3 resource was deleted. Remove orphan CNAME from authoritative DNS zone or reclaim asset.
- **Review Notes:** Manual investigator review not recorded

### Finding #4: Critical: Expired TLS Certificate on expired-tls.aiori.internal
- **Category:** `EXPIRED_CERTIFICATE`
- **Severity:** `CRITICAL` | **Status:** `OPEN`
- **Confidence Rating:** `HIGH` (FP Risk: `LOW`)
- **Description:** Domain 'expired-tls.aiori.internal' presents an expired TLS certificate issued by 'AIORI Lab Internal CA'. Expired on 2026-09-17T14:46:22.576456+00:00.
- **Recommended Defensive Action:** Immediately renew certificate with authoritative CA and deploy to load balancer or web server.
- **Review Notes:** Manual investigator review not recorded

### Finding #5: Unexpected Open Service Detected on 10.0.1.15:88 (Kerberos)
- **Category:** `UNEXPECTED_SERVICE`
- **Severity:** `HIGH` | **Status:** `OPEN`
- **Confidence Rating:** `HIGH` (FP Risk: `LOW`)
- **Description:** Host '10.0.1.15' has newly opened port 88 (Kerberos). This service was not present in the baseline inventory.
- **Recommended Defensive Action:** Inspect process listening on 10.0.1.15:88. If unauthorized, shut down service and block port at firewall.
- **Review Notes:** Manual investigator review not recorded

### Finding #6: Unexpected Open Service Detected on 10.0.1.15:9090 (Prometheus-Metrics)
- **Category:** `UNEXPECTED_SERVICE`
- **Severity:** `HIGH` | **Status:** `OPEN`
- **Confidence Rating:** `HIGH` (FP Risk: `LOW`)
- **Description:** Host '10.0.1.15' has newly opened port 9090 (Prometheus-Metrics). This service was not present in the baseline inventory.
- **Recommended Defensive Action:** Inspect process listening on 10.0.1.15:9090. If unauthorized, shut down service and block port at firewall.
- **Review Notes:** Manual investigator review not recorded

### Finding #7: Unexpected Open Service Detected on 10.0.1.15:8888 (HTTP-Dev-Console)
- **Category:** `UNEXPECTED_SERVICE`
- **Severity:** `HIGH` | **Status:** `OPEN`
- **Confidence Rating:** `HIGH` (FP Risk: `LOW`)
- **Description:** Host '10.0.1.15' has newly opened port 8888 (HTTP-Dev-Console). This service was not present in the baseline inventory.
- **Recommended Defensive Action:** Inspect process listening on 10.0.1.15:8888. If unauthorized, shut down service and block port at firewall.
- **Review Notes:** Manual investigator review not recorded

