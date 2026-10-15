# AIORI-3 PS-011: Prototype Demonstration & Mentor Pseudocode Snippet

**Category:** Cybersecurity  
**Problem Statement:** PS-011: Authorised Attack-Surface Inventory and Change Monitor  
**Deliverable:** Prototype Demonstration with a Pseudocode Snippet to the Mentor  

---

## 1. Mentor Demonstration Overview

This document serves as the official briefing guide for the hackathon mentor demonstration. It outlines:
1. **Live vs. Simulated Lab Demonstration Workflow**
2. **The Core Pseudocode Snippet** powering discovery, diff comparison, and triage
3. **The 4 Documented Checks** interface and technical specifications
4. **Seeded-Issue Detections** (Expired TLS, Unexpected Service, Dangling CNAMEs)
5. **False-Positive Analysis** and Confidence Scoring engine

---

## 2. Pseudocode Snippet (Core Inspection & Drift Detection)

```python
"""
ALGORITHM: Authorised Attack-Surface Discovery and Change Monitor (AIORI-3 PS-011)
INPUTS:
  - ScopeConfig: Approved target list (Max 20 Domains, 10 Hosts, Allowed Ports)
  - BaselineStorage: Persistent golden inventory reference
OUTPUTS:
  - Actionable Delta Alerts with False-Positive Confidence Ratings
"""

FUNCTION RunAttackSurfaceMonitorCycle(scopeConfig, isBaseline=False):
    # -------------------------------------------------------------
    # STEP 1: Strict Scope Enforcement & Boundary Validation
    # -------------------------------------------------------------
    ASSERT scopeConfig.enforce_strict_scope == True
    domains = ScopeGuard.FilterApprovedDomains(scopeConfig.approved_domains, max_limit=20)
    hosts   = ScopeGuard.FilterApprovedHosts(scopeConfig.approved_hosts, max_limit=10)

    snapshot = NewInventorySnapshot(timestamp=CURRENT_TIME_UTC())

    # -------------------------------------------------------------
    # STEP 2: DNS & TLS Asset Cataloging
    # -------------------------------------------------------------
    FOR EACH domain IN domains:
        # Catalog public DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA)
        dnsRecords = DNSInspector.QueryAllRecordTypes(domain)

        # Inspect for Potential Dangling DNS on CNAME records
        FOR EACH record IN dnsRecords WHERE record.type == "CNAME":
            isDangling, provider, reason = DNSInspector.EvaluateDanglingCandidate(
                cnameTarget = record.value,
                originalDomain = domain,
                knownProviders = [AWS_S3, Beanstalk, GitHubPages, Azure, Heroku]
            )
            IF isDangling:
                record.is_dangling_candidate = True
                record.dangling_provider = provider
                record.dangling_reason = reason
                snapshot.AddDanglingCandidate(domain, record)

        # TLS Certificate Verification
        tlsCert = TLSInspector.HandshakeAndExtractCert(domain, port=443)
        IF tlsCert.present:
            tlsCert.is_expired = (CURRENT_TIME_UTC() > tlsCert.not_after_utc)
            tlsCert.days_remaining = (tlsCert.not_after_utc - CURRENT_TIME_UTC()).days
            snapshot.AddDomainCertificate(domain, tlsCert)

        snapshot.AddDomain(domain, dnsRecords)

    # -------------------------------------------------------------
    # STEP 3: Multi-Layer Service Inspection (The 4 Documented Checks)
    # -------------------------------------------------------------
    FOR EACH host IN hosts:
        FOR EACH port IN scopeConfig.ports_to_inspect:
            
            # [CHECK 1]: TCP Port State & Connection Probe (RFC 793)
            isOpen, latency_ms = Check1_TCPConnect(host, port, timeout=3.0)
            IF NOT isOpen:
                CONTINUE # Port is CLOSED or FILTERED

            # [CHECK 2]: Service Banner Grab & Protocol Fingerprint
            rawBanner, serviceProtocol = Check2_BannerGrab(host, port)

            # [CHECK 3]: TLS/SSL Handshake & Negotiation Probe
            hasTLS, tlsVersion, cipherSuite, peerCert = Check3_TLSNegotiation(host, port, host)

            # [CHECK 4]: Application-Layer HTTP/HTTPS Inspection
            httpStatus, serverHeader, htmlTitle, techStack = Check4_HTTPInspection(host, port, hasTLS)

            # Evaluate Unexpected Service against Approved Matrix
            isUnexpected = (port NOT IN scopeConfig.baseline_approved_services[host])

            snapshot.AddServiceResult(
                host=host, port=port, state="OPEN", latency=latency_ms,
                service=serviceProtocol, banner=rawBanner, has_tls=hasTLS,
                is_unexpected=isUnexpected, http_status=httpStatus,
                tech_stack=techStack, certificate=peerCert
            )

    # -------------------------------------------------------------
    # STEP 4: Scheduled Inventory Comparison & Delta Generation
    # -------------------------------------------------------------
    baseline = BaselineStorage.LoadBaseline()
    IF baseline IS NULL OR isBaseline == True:
        BaselineStorage.SaveBaseline(snapshot)
        baseline = snapshot

    diff = DiffEngine.ComputeDelta(baselineInventory=baseline, currentInventory=snapshot)

    # -------------------------------------------------------------
    # STEP 5: False-Positive Analysis & Confidence Scoring
    # -------------------------------------------------------------
    FOR EACH alert IN diff.alerts:
        IF alert.category == POTENTIAL_DANGLING_DNS:
            alert.confidence, alert.fp_risk, alert.triage_notes = FalsePositiveAnalyzer.TriageDangling(
                provider = alert.evidence.provider,
                targetResolves = alert.evidence.resolves,
                httpSignature = alert.evidence.signature
            )
        ELSE IF alert.category == UNEXPECTED_SERVICE:
            alert.confidence, alert.fp_risk, alert.triage_notes = FalsePositiveAnalyzer.TriageService(
                port = alert.evidence.port,
                hasBanner = (alert.evidence.banner IS NOT NULL),
                totalOpenPortsOnHost = LENGTH(snapshot.GetHostOpenPorts(alert.evidence.host))
            )
        ELSE IF alert.category == EXPIRED_CERTIFICATE:
            alert.confidence = HIGH
            alert.fp_risk = LOW
            alert.triage_notes = "Cryptographically verified against authoritative UTC clock."

        # Dispatch actionable alert to console, database, and report
        AlertManager.Dispatch(alert)

    BaselineStorage.SaveCurrentScan(snapshot)
    RETURN diff
```

---

## 3. How to Demonstrate to Mentors

### Quick Demo Command (Terminal / CLI)
Run the following in the project root:
```bash
python main.py demo
```
**Mentor Observations:**
1. Step 1 establishes the clean initial baseline with 0 alerts across 20 domains and 10 hosts.
2. Step 2 simulates attack surface drift and detects all seeded issues:
   - **CRITICAL:** Expired TLS Certificate (`expired-tls.aiori.internal`)
   - **HIGH:** Unexpected Service (`10.0.1.15:8888` - Rogue Debug Console)
   - **HIGH:** Dangling DNS CNAMEs (`AWS S3 NoSuchBucket` & `GitHub Pages 404`)
   - **CONTROL (Low Confidence / High FP Risk):** Multi-tenant CDN edge 404 (`CloudFront`) properly filtered so teams don't waste time on false alarms!

### Interactive Web Dashboard Demonstration
Launch the visual dashboard:
```bash
python main.py web --port 5000
```
Open browser at: `http://127.0.0.1:5000`
- Live interactive dashboard showing real-time inventory, seeded issue verification cards, alert triage table, and 4 documented checks breakdown.

### Run Automated Unit Test Verification
```bash
python -m unittest lab_simulator/test_scenarios.py
```
Outputs: `Ran 4 tests ... OK` verifying scope enforcement, seeded issue detection, false-positive triage, and checks interfaces.
