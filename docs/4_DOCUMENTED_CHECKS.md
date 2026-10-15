# Technical Specification: The 4 Documented Port & Service Checks

**AIORI-3 PS-011 Mandate:** *"Check selected ports using 4 documented checks."*  
**Implementation File:** `checks/service_inspector.py`

---

## Architecture Overview

Traditional port scanners rely solely on raw TCP connect probes, often generating excessive noise, false positives, or uninformative results. The **AIORI-3 Attack-Surface Monitor** implements a multi-layer inspection pipeline where every open port is subjected to **four sequentially executed, documented checks**:

```
[Target Port]
     │
     ▼
┌────────────────────────────────────────────────────────┐
│ CHECK 1: TCP Port State & Latency Probe (RFC 793)      │ ──> Is port OPEN/CLOSED/FILTERED?
└────────────────────────────────────────────────────────┘
     │ (If OPEN)
     ▼
┌────────────────────────────────────────────────────────┐
│ CHECK 2: Service Banner Grab & Protocol Fingerprint     │ ──> What daemon/version is greeting?
└────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────┐
│ CHECK 3: TLS/SSL Handshake & Negotiation Probe         │ ──> Does it speak TLS? Is cert valid?
└────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────┐
│ CHECK 4: Application-Layer HTTP/HTTPS Inspection       │ ──> Title, Server, Tech stack, Headers
└────────────────────────────────────────────────────────┘
```

---

## Detailed Check Specifications

### Check 1: TCP Port State & Latency Probe
- **Target Layer:** Transport Layer (OSI Layer 4) / RFC 793
- **Objective:** Determine socket availability and baseline network reachability without exploiting network stacks.
- **Methodology:**
  1. Instantiates non-blocking TCP socket (`AF_INET`, `SOCK_STREAM`).
  2. Applies configurable socket timeout (default: 3.0s).
  3. Records high-resolution timestamp prior to calling `connect_ex((host, port))`.
  4. Returns `OPEN` if return code is `0`; records round-trip latency in milliseconds (`latency_ms`).
  5. Catches timeout and connection errors, classifying port as `CLOSED` or `FILTERED`.
- **Safety Standard:** Clean socket shutdown (`s.close()`) prevents connection starvation on lab hosts.

---

### Check 2: Service Banner Grab & Protocol Fingerprint
- **Target Layer:** Session & Presentation Layer (OSI Layers 5–6)
- **Objective:** Ascertain daemon identity, software release, and protocol class before sending heavy application payloads.
- **Methodology:**
  1. Connects to open socket and executes non-blocking read (`recv(1024)`).
  2. If daemon remains silent after 1.5 seconds, transmits gentle probe sequence (`\r\n\r\n`).
  3. Decodes byte stream safely with replacement characters to avoid malformed payload crashes.
  4. Applies regex pattern matching against documented signatures:
     - **SSH:** `^SSH-[\d.]+-(\S+)`
     - **SMTP:** `^220.*SMTP|ESMTP`
     - **FTP:** `^220.*FTP`
     - **Redis:** `^-ERR unknown command` or `+PONG`
     - **MySQL:** Protocol version byte sequence / error greeting
     - **HTTP:** `^HTTP/[\d.]+`
- **Output:** Raw truncated banner string and normalized `identified_service` label.

---

### Check 3: TLS/SSL Handshake & Negotiation Probe
- **Target Layer:** Cryptographic Transport (OSI Layer 6) / RFC 8446
- **Objective:** Evaluate transport layer cryptographic hygiene, negotiate cipher suites, and extract X.509 certificate metadata.
- **Methodology:**
  1. Creates standard SSL client context (`ssl.create_default_context()`).
  2. Disables hostname rejection mode (`CERT_NONE`) strictly for inventory cataloging (so expired or self-signed certs can still be inspected and alerted upon!).
  3. Wraps socket with Server Name Indication (`server_hostname=sni_target`).
  4. Extracts negotiated protocol (`TLSv1.2`, `TLSv1.3`), cipher suite name, and bit strength.
  5. Retrieves raw binary DER certificate (`getpeercert(binary_form=True)`).
  6. Delegates certificate to `TLSInspector.parse_der_certificate` using cryptographic X.509 parsers:
     - Calculates `days_to_expiry` relative to UTC clock.
     - Flags `is_expired` if `current_time > not_after`.
     - Extracts Subject Alternative Names (`SANs`) list and CA Issuer.

---

### Check 4: Application-Layer HTTP/HTTPS Inspection
- **Target Layer:** Application Layer (OSI Layer 7) / RFC 9110
- **Objective:** Characterize exposed web applications, detect unexpected developer admin consoles or rogue debug services, and verify defensive headers.
- **Methodology:**
  1. Dispatches authorized HTTP GET request with designated user agent:
     `AIORI-ASM-Monitor/1.0 (Authorised Security Research; +https://github.com/aiori-hackathon)`
  2. Inspects HTTP response status code (e.g. 200, 301, 401, 403, 404, 500).
  3. Parses initial 8 KB of response body for HTML `<title>...</title>` tags to capture human-readable page name.
  4. Evaluates `Server` and `X-Powered-By` headers to identify web servers (Nginx, Apache, Werkzeug, Express).
  5. Audits security hardening headers:
     - `Strict-Transport-Security` (HSTS)
     - `Content-Security-Policy` (CSP)
     - `X-Frame-Options`
     - `X-Content-Type-Options`
- **Outcome:** Populates `PortScanResult` with complete web footprint for baseline change comparison.
