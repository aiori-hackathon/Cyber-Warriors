# AIORI-3 Attack-Surface Inventory & Change Report
**Problem Statement:** PS-011: Authorised Attack-Surface Inventory and Change Monitor  
**Generated:** 2026-10-15T04:11:20.460592+00:00  
**Baseline Ref:** `snapshot_baseline_golden` | **Current Scan:** `scan_simulated_20261015_041120`  

---
## 1. Executive Summary
The continuous attack-surface monitoring scan completed with **5 actionable alerts** identified.

| Severity | Count | Primary Impact |
| :--- | :--- | :--- |
| 🔴 **CRITICAL** | 1 | Service Outages / Severe Trust Degradation (Expired TLS) |
| 🟠 **HIGH** | 4 | Exposure of Unauthorized Services / Potential Dangling DNS Takeover Risks |
| 🟡 **MEDIUM** | 0 | Unclassified Inventory Changes & Approaching Expirations |
| 🔵 **LOW** | 0 | Informational Disclosures / Missing Hardening Headers |
| 🟢 **INFO** | 0 | Normal Baseline Asset Deprecations |

---
## 2. Seeded Issues & Drift Verification Matrix

| Category | Detected Target | Verification Details & False Positive Triage | Action Required |
| :--- | :--- | :--- | :--- |
| `HIGH` **POTENTIAL_DANGLING_DNS** | `test-cdn.aiori.internal` | Multi-tenant edge CDN (AWS CloudFront) detected. 404/403 or routing errors frequently occur when the distribution does not recognize the Host header without meaning the backend is takeover-ready. (Confidence: **LOW**) | Immediately remove the orphan CNAME record from DNS zone files if the cloud resource is retired, or re-claim the resource in the AWS CloudFront account. Validate Alternate Domain Names (CNAMEs) configured in CDN distribution before flagging as critical. |
| `HIGH` **POTENTIAL_DANGLING_DNS** | `orphaned-bucket.aiori.internal` | Explicit S3 'NoSuchBucket' XML returned. Confirms bucket namespace is currently unregistered in AWS region. (Confidence: **HIGH**) | Immediately remove the orphan CNAME record from DNS zone files if the cloud resource is retired, or re-claim the resource in the AWS S3 account. Check AWS CloudTrail for bucket deletion logs; confirm bucket name is retired. |
| `CRITICAL` **EXPIRED_CERTIFICATE** | `expired-tls.aiori.internal` | Certificate validity timestamp expired 30 days ago. Cryptographically verified against UTC clock. (Confidence: **HIGH**) | Immediately renew certificate with authorized CA and redeploy to web server. |
| `HIGH` **POTENTIAL_DANGLING_DNS** | `blog.aiori.internal` | GitHub Pages official error banner observed. Domain CNAME exists but no repository has configured this CNAME in repo settings. (Confidence: **HIGH**) | Immediately remove the orphan CNAME record from DNS zone files if the cloud resource is retired, or re-claim the resource in the GitHub Pages account. Review cloud configuration and authoritative DNS records. |
| `HIGH` **UNEXPECTED_SERVICE** | `10.0.1.15:8888` | Active application response verified on port 8888. Confirmed running listener. (Confidence: **HIGH**) | Investigate process listening on 10.0.1.15:8888. If unauthorized, terminate service and close port at host firewall/security group. Perform local `netstat -tulpn` or `lsof -i :8888` on host 10.0.1.15 to inspect listening PID. |

---
## 3. Detailed Alerts and Technical Remediation

### Alert 1: Potential Dangling DNS Record Pointing to AWS CloudFront
- **Target:** `test-cdn.aiori.internal`
- **Category:** `POTENTIAL_DANGLING_DNS`
- **Severity:** **HIGH**
- **Confidence Assessment:** **LOW** (False Positive Probability: **HIGH**)
- **Description:** Domain 'test-cdn.aiori.internal' possesses a CNAME record pointing to 'd123456789.cloudfront.net' (AWS CloudFront). Inspection indicator: Target returned HTTP 404 (Multi-tenant edge distribution).
- **Technical Triage Notes:** Multi-tenant edge CDN (AWS CloudFront) detected. 404/403 or routing errors frequently occur when the distribution does not recognize the Host header without meaning the backend is takeover-ready.
- **Remediation Steps:** Immediately remove the orphan CNAME record from DNS zone files if the cloud resource is retired, or re-claim the resource in the AWS CloudFront account. Validate Alternate Domain Names (CNAMEs) configured in CDN distribution before flagging as critical.

### Alert 2: Potential Dangling DNS Record Pointing to AWS S3
- **Target:** `orphaned-bucket.aiori.internal`
- **Category:** `POTENTIAL_DANGLING_DNS`
- **Severity:** **HIGH**
- **Confidence Assessment:** **HIGH** (False Positive Probability: **LOW**)
- **Description:** Domain 'orphaned-bucket.aiori.internal' possesses a CNAME record pointing to 'aiori-decommissioned-assets.s3.amazonaws.com' (AWS S3). Inspection indicator: Target matches AWS S3 unlinked signature: 'NoSuchBucket' with HTTP 404.
- **Technical Triage Notes:** Explicit S3 'NoSuchBucket' XML returned. Confirms bucket namespace is currently unregistered in AWS region.
- **Remediation Steps:** Immediately remove the orphan CNAME record from DNS zone files if the cloud resource is retired, or re-claim the resource in the AWS S3 account. Check AWS CloudTrail for bucket deletion logs; confirm bucket name is retired.

### Alert 3: Critical: Expired TLS Certificate Detected
- **Target:** `expired-tls.aiori.internal`
- **Category:** `EXPIRED_CERTIFICATE`
- **Severity:** **CRITICAL**
- **Confidence Assessment:** **HIGH** (False Positive Probability: **LOW**)
- **Description:** Target 'expired-tls.aiori.internal' is presenting an expired TLS certificate issued by 'AIORI Lab Internal CA'. Validity ended on 2026-09-15T04:11:20.410205+00:00 (30 days ago). Users visiting this service will receive severe security trust warnings.
- **Technical Triage Notes:** Certificate validity timestamp expired 30 days ago. Cryptographically verified against UTC clock.
- **Remediation Steps:** Immediately renew certificate with authorized CA and redeploy to web server.

### Alert 4: Potential Dangling DNS Record Pointing to GitHub Pages
- **Target:** `blog.aiori.internal`
- **Category:** `POTENTIAL_DANGLING_DNS`
- **Severity:** **HIGH**
- **Confidence Assessment:** **HIGH** (False Positive Probability: **LOW**)
- **Description:** Domain 'blog.aiori.internal' possesses a CNAME record pointing to 'aiori-legacy-blog.github.io' (GitHub Pages). Inspection indicator: Target matches GitHub Pages unlinked signature: 'There isn't a GitHub Pages site here' with HTTP 404.
- **Technical Triage Notes:** GitHub Pages official error banner observed. Domain CNAME exists but no repository has configured this CNAME in repo settings.
- **Remediation Steps:** Immediately remove the orphan CNAME record from DNS zone files if the cloud resource is retired, or re-claim the resource in the GitHub Pages account. Review cloud configuration and authoritative DNS records.

### Alert 5: Unexpected Open Service: Port 8888 (HTTP-Dev-Console)
- **Target:** `10.0.1.15:8888`
- **Category:** `UNEXPECTED_SERVICE`
- **Severity:** **HIGH**
- **Confidence Assessment:** **HIGH** (False Positive Probability: **LOW**)
- **Description:** Host '10.0.1.15' has newly opened port 8888 (HTTP-Dev-Console). This port was not present in the baseline inventory or approved service matrix.
- **Technical Triage Notes:** Active application response verified on port 8888. Confirmed running listener.
- **Remediation Steps:** Investigate process listening on 10.0.1.15:8888. If unauthorized, terminate service and close port at host firewall/security group. Perform local `netstat -tulpn` or `lsof -i :8888` on host 10.0.1.15 to inspect listening PID.

---
## 4. Compliance & Ethical Guardrails
- **Authorised Scope Enforced:** All scans strictly confined to written organiser-approved target assets.
- **Non-Exploitation Standard:** No hostile subdomain takeovers or intrusive exploits were attempted.
- **False-Positive Mitigation:** Multi-factor verification applied before flagging any asset.
