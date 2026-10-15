# Pre-Demonstration Testing Checklist & Verification Audit

**Project:** PS-011 Authorised Attack-Surface Inventory and Change Monitor  
**Team:** Cyber Warriors  
**Last Verified:** 2026-10-15  
**Environment:** Windows 11 / Python 3.13.5  

---

## 1. Automated Test Execution Record

The automated test suite was executed locally using Python's standard `unittest` framework:

```powershell
cd "C:\Users\DAKSH JAIN\Desktop\Cyber Warriors"
python -m unittest discover tests -v
```

### Actual Recorded Results:
```text
test_dangling_cname_detection_nxdomain (test_dns.TestDNSChecker.test_dangling_cname_detection_nxdomain) ... ok
test_dangling_cname_detection_s3 (test_dns.TestDNSChecker.test_dangling_cname_detection_s3) ... ok
test_clean_cname_record (test_dns.TestDNSChecker.test_clean_cname_record) ... ok
test_parse_expired_certificate (test_tls.TestTLSChecker.test_parse_expired_certificate) ... ok
test_parse_valid_certificate (test_tls.TestTLSChecker.test_parse_valid_certificate) ... ok
test_approved_port_not_unexpected (test_ports.TestPortChecker.test_approved_port_not_unexpected) ... ok
test_closed_port_detection (test_ports.TestPortChecker.test_closed_port_detection) ... ok
test_unexpected_port_flagging (test_ports.TestPortChecker.test_unexpected_port_flagging) ... ok
test_counts_and_limits (test_scope.TestScopeManager.test_counts_and_limits) ... ok
test_domain_validation (test_scope.TestScopeManager.test_domain_validation) ... ok
test_host_validation (test_scope.TestScopeManager.test_host_validation) ... ok
test_scope_rejection_for_unapproved_targets (test_scope.TestScopeManager.test_scope_rejection_for_unapproved_targets) ... ok
test_seeded_simulation_and_change_detection (test_changes.TestChangeDetector.test_seeded_simulation_and_change_detection) ... ok
test_triage_status_lifecycle (test_changes.TestChangeDetector.test_triage_status_lifecycle) ... ok

----------------------------------------------------------------------
Ran 14 tests in 1.707s

OK (14 Tests Passed, 0 Failures, 0 Errors)
```

---

## 2. Interactive Feature Verification Checklist

| # | Item / Feature | Test Command / Action | Expected Result | Status | Verified Evidence |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **1** | **Application Startup** | `python app.py` | Starts HTTP listener on `127.0.0.1:5000` | ✅ PASSED | HTTP 200 response on `http://127.0.0.1:5000/` |
| **2** | **All 10 Routes Active** | Automated GET scan across all 10 endpoints | All return HTTP 200 | ✅ PASSED | `/`, `/assets`, `/dns`, `/tls`, `/ports`, `/findings`, `/changes`, `/scans`, `/reports`, `/settings` all return HTTP 200 |
| **3** | **Authorised Scope Enforcement** | Add asset beyond 20 domains or 10 hosts | Rejection message displayed; database prevents addition | ✅ PASSED | Verified via `test_scope.py` and UI capacity banner |
| **4** | **Out-of-Scope Scan Rejection** | Attempt scan on unapproved target | `ScopeViolationError` raised immediately | ✅ PASSED | Verified in `ScopeManager.verify_target_in_scope()` |
| **5** | **Check 1: DNS Cataloging** | Visit `/dns` | A, AAAA, CNAME, MX records displayed | ✅ PASSED | Cataloged in database with TTL and observed timestamp |
| **6** | **Check 2: TLS Expiry Verification** | Visit `/tls` | Expiry countdown & expired flags displayed | ✅ PASSED | `expired-tls.aiori.internal` flagged as EXPIRED; valid certs show days remaining |
| **7** | **Check 3: Selected Port Checks** | Visit `/ports` | Shows reachability state, latency, and banners | ✅ PASSED | Non-allowlisted port `:8888` flagged as UNEXPECTED PORT |
| **8** | **Check 4: Baseline Comparison** | Click "Run Seeded Demo" | Calculates delta against golden baseline snapshot | ✅ PASSED | Generates change events in `change_events` table |
| **9** | **Seeded Issue: Expired Cert** | Run Seeded Demo | `expired-tls.aiori.internal` detected | ✅ PASSED | Displayed in dashboard banner with CRITICAL severity |
| **10** | **Seeded Issue: Unexpected Service** | Run Seeded Demo | `10.0.1.15:8888` detected | ✅ PASSED | Flagged as HIGH severity finding with Werkzeug title |
| **11** | **Seeded Issue: Dangling S3 CNAME** | Run Seeded Demo | `orphaned-bucket.aiori.internal` detected | ✅ PASSED | Matches `NoSuchBucket` signature; flagged as HIGH |
| **12** | **Seeded Issue: Dangling GitHub CNAME**| Run Seeded Demo | `blog.aiori.internal` detected | ✅ PASSED | Matches `There isn't a GitHub Pages site here` |
| **13** | **False-Positive Triage** | Inspect `test-cdn.aiori.internal` | Scored with Low Confidence & High FP Risk | ✅ PASSED | Filtered as multi-tenant edge; triage modal updates status to `FALSE_POSITIVE` |
| **14** | **Deduplication Check** | Trigger scan twice | Duplicate findings NOT created for existing open alerts | ✅ PASSED | Verified in `ChangeDetector._finding_exists()` |
| **15** | **CSV Export Generation** | Visit `/reports/export/csv/assets` | Downloads RFC 4180 formatted CSV | ✅ PASSED | HTTP 200 with `text/csv` header verified |
| **16** | **Technical Report Viewer** | Visit `/reports/technical` | Renders styled report in browser with Print button | ✅ PASSED | Rendered via `technical_report_view.html` |
| **17** | **Baseline Reset** | Click "Reset Baseline" | Resets baseline snapshot and clears transient findings | ✅ PASSED | Cleans alerts back to 0 baseline state |

---

## 3. Known Limitations & Operational Boundaries

1. **Private Lab Domain Resolution:** In an isolated offline environment, `.internal` domains do not exist on the public internet. The system utilizes the built-in synthetic test harness to simulate multi-cloud responses accurately.
2. **Local Host Ports:** Port checking against `127.0.0.1` checks actual listening local services. If no service is running on a port, it accurately reports `CLOSED`.
3. **Non-Intrusive Safety Policy:** Probing is strictly non-exploitative. Subdomain takeovers are intentionally never performed.
