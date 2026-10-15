# AIORI-3 PS-011: 5-Minute Mentor Demonstration Script

**Project:** Authorised Attack-Surface Inventory and Change Monitor  
**Team:** Cyber Warriors  
**Target Duration:** ~5 Minutes  
**Audience:** Hackathon Mentors and Evaluators  

---

## Preparation Before Starting the Demo

1. Open PowerShell on Windows and navigate to your project folder:
   ```powershell
   cd "C:\Users\DAKSH JAIN\Desktop\Cyber Warriors"
   ```
2. Start the application:
   ```powershell
   python app.py
   ```
3. Open your browser at: **`http://127.0.0.1:5000`**
4. Optional: Click the **"Reset Baseline"** button on the dashboard once before the mentor arrives so the screen starts with a clean baseline state.

---

## Step-by-Step Presentation Script

---

### Step 1: Introduction to the Problem (~30 Seconds)

- **What to do:** Stand in front of your screen showing the web browser open at `http://127.0.0.1:5000`.
- **What to say:**
  > *"Hello mentors, we are team Cyber Warriors presenting problem statement **PS-011: Authorised Attack-Surface Inventory and Change Monitor**.*  
  > *Organizations managing multi-cloud infrastructure often suffer from asset sprawl — abandoned test subdomains, expired TLS certificates, developer debug ports left open, and dangling DNS CNAME records pointing to decommissioned cloud instances.*  
  > *Our goal was to build a reliable, beginner-friendly system in pure Python that tracks approved domains and hosts, maintains a baseline inventory, detects drift, and flags vulnerabilities without aggressive exploitation."*

---

### Step 2: Opening the Dashboard (~30 Seconds)

- **What to click:** Point to the main dashboard screen (`http://127.0.0.1:5000`).
- **What to say:**
  > *"Here is our web dashboard. We designed it with a clean light theme using a navy-blue palette specifically for clear visibility.*  
  > *At the top, we see our key operational metrics: 20 monitored domains, 10 monitored hosts, open ports, and the last scan status.*  
  > *We also have two Chart.js visualizers showing findings by severity and asset distribution.*  
  > *Notice that we strictly enforce the hackathon limit of up to 20 lab domains and 10 hosts directly at the database and application levels."*

---

### Step 3: Showing the Authorised Asset Inventory (~45 Seconds)

- **What to click:** In the left sidebar, click **"Asset Inventory"** (`/assets`).
- **What to say:**
  > *"On the Asset Inventory page, we manage our approved lab scope.*  
  > *All 20 domains and 10 hosts are pre-enrolled with their mapped IP addresses and approval status.*  
  > *Our backend strictly validates every target before any scan occurs. If an unauthorized target like `google.com` or an arbitrary IP is entered, our server-side Scope Guard immediately rejects the scan with a `ScopeViolationError`.*  
  > *We can also toggle targets in and out of scope, or add new lab assets up to the 20/10 limit."*

---

### Step 4: Demonstrating the DNS, TLS, and Selected-Port Checks (~1 Minute)

- **What to click:**
  1. Click **"DNS Monitoring"** (`/dns`) in the sidebar.
  2. Next, click **"TLS Certificate Monitoring"** (`/tls`) in the sidebar.
  3. Next, click **"Port & Service Monitoring"** (`/ports`) in the sidebar.
- **What to say:**
  > *"Next, let's look at the first three documented monitoring checks:*  
  > - *Under **DNS Monitoring (Check 1)**, the system catalogs public A, AAAA, CNAME, and MX records using `dnspython`. It inspects CNAME destinations against cloud provider patterns like AWS S3 and GitHub Pages to identify potential dangling records.*  
  > - *Under **TLS Certificate Monitoring (Check 2)**, we perform SNI handshakes to inspect X.509 certificates. We calculate the exact days remaining until expiry, extract Subject Alternative Names, and cleanly distinguish an expired certificate from a network timeout.*  
  > - *Under **Port & Service Monitoring (Check 3)**, we restrict port probes to an approved allowlist. We measure connection latency in milliseconds, capture service greeting banners, and run safe HTTP header inspections to detect web applications."*

---

### Step 5: Showing Baseline Comparison & Detected Drift (~45 Seconds)

- **What to click:** In the top header bar, click the blue **"Run Seeded Demo"** button. Wait 2 seconds for the scan to complete and page to reload.
- **What to say:**
  > *"Now let's demonstrate **Check 4: Baseline Comparison and Change Detection**.*  
  > *I just clicked 'Run Seeded Demo'. The system took our newly observed scan and automatically compared it against the active Golden Baseline.*  
  > *Notice that the system instantly identified drift: new unexpected services, certificate expiration transitions, and orphan CNAME records.*  
  > *If we go to **Change History** in the sidebar, we can see the exact audit log of every detected change with its timestamp, affected asset, and evidence."*

---

### Step 6: Demonstrating Seeded Test Issues & False-Positive Review (~1 Minute)

- **What to click:**
  1. Return to **"Overview"** (`/`) to show the **Seeded-Issue Status Banner**.
  2. Click **"Security Findings"** (`/findings`) in the sidebar.
  3. On the finding for `test-cdn.aiori.internal`, click the **"Triage"** button.
  4. Select **`FALSE_POSITIVE`**, type: `"Verified multi-tenant CloudFront edge distribution; not vulnerable."` and click **"Save Triage Decision"**.
- **What to say:**
  > *"The hackathon required us to detect specific seeded vulnerabilities:*  
  > 1. *Here is our **Expired TLS Certificate** on `expired-tls.aiori.internal`, flagged as CRITICAL.*  
  > 2. *Here is our **Unexpected Service** on host `10.0.1.15:8888`, flagged as HIGH because an unapproved Werkzeug debug console was opened.*  
  > 3. *Here are our **Dangling DNS Records** on `orphaned-bucket.aiori.internal` pointing to an unallocated AWS S3 bucket, and `blog.aiori.internal` pointing to an unlinked GitHub Pages site.*  
  > *Crucially, we also implemented **False-Positive Analysis**:*  
  > *For `test-cdn.aiori.internal`, the destination returns HTTP 404, but our engine recognizes it as a shared CDN edge rather than an orphaned resource. It scores it with Low Confidence and High False-Positive Risk.*  
  > *I just used our triage modal to mark it as a reviewed `FALSE_POSITIVE` with audit notes, removing it from our active alert queue."*

---

### Step 7: Showing Reports & Output (~30 Seconds)

- **What to click:** In the sidebar, click **"Reports & Exports"** (`/reports`).
- **What to say:**
  > *"Finally, in the Reports section, we provide structured data exports:*  
  > - *We can export any dataset — assets, DNS, TLS, ports, findings, and changes — as structured CSV files with one click.*  
  > - *We can view our full **Technical Report** rendered directly in the browser with print-to-PDF formatting.*  
  > - *And we have our compiled hackathon proposal PDF, `Proposed-structure-hackathon.pdf`, ready for submission."*

---

### Step 8: Conclusion (~15 Seconds)

- **What to say:**
  > *"In summary, Cyber Warriors built a fully functional, Windows-native attack-surface monitor that respects strict scope boundaries, implements the four documented checks, detects seeded vulnerabilities, and manages finding lifecycles without any offensive exploitation.*  
  > *Thank you, and we welcome your questions!"*

---

## Quick Q&A Cheat Sheet for Mentors

- **Q: Why are internal domain names like `.internal` used in the lab?**  
  *Answer:* PS-011 specifies a lab portfolio of domains and hosts. `.internal` represents multi-cloud private DNS zones. Our built-in synthetic lab harness simulates DNS and network responses safely and offline without scanning random public websites.
- **Q: How do you prevent duplicate alerts on consecutive scans?**  
  *Answer:* Check 4 queries the `security_findings` table before inserting. If an identical finding for the same target and category is already in `OPEN` status, it avoids generating duplicate notifications.
- **Q: How do you enforce the 20 domains and 10 hosts limit?**  
  *Answer:* `ScopeManager` validates counts in SQLite on every asset insertion, and `verify_target_in_scope()` checks that any target being scanned is explicitly marked as approved in the database.
