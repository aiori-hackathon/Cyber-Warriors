"""
Generates the hackathon deliverable 'Proposed-structure-hackathon.pdf'
Mandated by AIORI-3 Hackathon Deliverable #2.
"""

from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


def generate_pdf(output_path: Path = None) -> Path:
    if output_path is None:
        output_path = Path(__file__).resolve().parent / "Proposed-structure-hackathon.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        alignment=1, # Center
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0284c7'),
        alignment=1,
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=12,
        spaceAfter=6
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=8,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#334155'),
        spaceAfter=5
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=body_style,
        leftIndent=15,
        bulletIndent=5,
        spaceAfter=3
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#0f172a'),
        backColor=colors.HexColor('#f1f5f9'),
        borderPadding=4,
        spaceAfter=5
    )

    story = []

    # Title Banner
    story.append(Paragraph("AIORI-3 HACKATHON TECHNICAL PROPOSAL", subtitle_style))
    story.append(Paragraph("PS-011: Authorised Attack-Surface Inventory and Change Monitor", title_style))
    story.append(Paragraph("<b>Category:</b> Cybersecurity | <b>Track:</b> Internet Operations &amp; Attack Surface Management", ParagraphStyle('Meta', parent=body_style, alignment=1, textColor=colors.HexColor('#64748b'))))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=10))

    # Section 1
    story.append(Paragraph("1. Executive Summary &amp; Problem Overview", h1_style))
    story.append(Paragraph(
        "Modern cloud environments rapidly expand, leading to accumulated exposed digital assets: unmaintained test subdomains, "
        "expired TLS certificates, rogue open service ports, and dangling DNS CNAME records pointing to decommissioned multi-cloud instances. "
        "Such hygiene oversights expose organisations to security degradation, subdomain takeovers, and unintended service exposures. "
        "This project implements an <b>Authorised Attack-Surface Inventory and Change Monitor</b> designed for up to 20 lab domains and 10 hosts, "
        "providing automated continuous discovery, baseline drift detection, strict scope enforcement, and actionable alerts without aggressive exploitation.",
        body_style
    ))

    # Section 2
    story.append(Paragraph("2. System Architecture &amp; Component Design", h1_style))
    arch_data = [
        [Paragraph("<b>Component</b>", body_style), Paragraph("<b>Key Responsibilities</b>", body_style), Paragraph("<b>Security &amp; Operational Controls</b>", body_style)],
        [
            Paragraph("<b>Scope Guard</b><br/>(core/scope_guard.py)", body_style),
            Paragraph("Enforces strict boundary checking on domains and IPs. Hard limit of 20 domains / 10 hosts.", body_style),
            Paragraph("Rejects out-of-scope targets with ScopeViolationError. Enforces non-exploitation safety policy.", body_style)
        ],
        [
            Paragraph("<b>4 Documented Checks</b><br/>(checks/service_inspector.py)", body_style),
            Paragraph("Modular multi-layer port &amp; service inspection across TCP, Banners, TLS, and Application HTTP.", body_style),
            Paragraph("Non-flooding, standard RFC handshakes, passive banner listening, and SNI TLS negotiation.", body_style)
        ],
        [
            Paragraph("<b>DNS &amp; Dangling Engine</b><br/>(checks/dns_inspector.py)", body_style),
            Paragraph("Catalogs A, AAAA, CNAME, MX, TXT, NS, SOA records. Analyzes CNAMEs against 9 cloud providers.", body_style),
            Paragraph("Tests NXDOMAIN and unlinked cloud signatures (AWS S3, GitHub, Azure, Heroku) without hostile takeovers.", body_style)
        ],
        [
            Paragraph("<b>Diff &amp; Baseline Engine</b><br/>(core/diff_engine.py)", body_style),
            Paragraph("Computes delta between current scan and golden baseline snapshot. Flags asset, port, cert drift.", body_style),
            Paragraph("Categorizes severity (Critical/High/Medium/Low/Info). Triggers alerts for unexpected services.", body_style)
        ],
        [
            Paragraph("<b>False-Positive Analyzer</b><br/>(analysis/false_positive.py)", body_style),
            Paragraph("Scores confidence (High/Med/Low) and FP risk against CDNs, wildcard DNS, and SYN-proxies.", body_style),
            Paragraph("Provides human-readable technical triage rationales and precise verification steps.", body_style)
        ]
    ]
    t_arch = Table(arch_data, colWidths=[1.8*inch, 2.7*inch, 2.7*inch])
    t_arch.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_arch)
    story.append(Spacer(1, 8))

    # Section 3
    story.append(Paragraph("3. The 4 Documented Port &amp; Service Checks", h1_style))
    checks_data = [
        [Paragraph("<b>Check Designation</b>", body_style), Paragraph("<b>Protocol Layer &amp; Target</b>", body_style), Paragraph("<b>Inspection Methodology &amp; Outputs</b>", body_style)],
        [
            Paragraph("<b>Check 1: TCP Port State &amp; Latency</b>", body_style),
            Paragraph("Transport (L4) / RFC 793", body_style),
            Paragraph("Performs standard TCP 3-way handshake with configurable timeout. Outputs state (OPEN/CLOSED/FILTERED) and RTT latency in milliseconds.", body_style)
        ],
        [
            Paragraph("<b>Check 2: Service Banner Grab</b>", body_style),
            Paragraph("Session / Presentation (L5-L6)", body_style),
            Paragraph("Passively reads service greeting (up to 1024 bytes); sends gentle probe if quiet. Regex fingerprinting for SSH, SMTP, FTP, Redis, MySQL.", body_style)
        ],
        [
            Paragraph("<b>Check 3: TLS/SSL Handshake</b>", body_style),
            Paragraph("Cryptographic Transport (L6)", body_style),
            Paragraph("Initiates SNI ClientHello. Negotiates TLSv1.2/1.3 and cipher suite. Parses DER X.509 cert: computes days-to-expiry, issuer, SANs, and expired state.", body_style)
        ],
        [
            Paragraph("<b>Check 4: HTTP/HTTPS Inspection</b>", body_style),
            Paragraph("Application (L7) / RFC 9110", body_style),
            Paragraph("Transmits authorized GET probe. Analyzes HTTP status, Server/X-Powered-By headers, HTML &lt;title&gt;, and defense headers (HSTS, CSP, X-Frame-Options).", body_style)
        ]
    ]
    t_checks = Table(checks_data, colWidths=[2.0*inch, 2.0*inch, 3.2*inch])
    t_checks.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_checks)
    story.append(Spacer(1, 8))

    # Page Break for clean multi-page presentation
    story.append(PageBreak())

    # Section 4
    story.append(Paragraph("4. Seeded-Issue Detection Results &amp; Verification", h1_style))
    story.append(Paragraph(
        "To satisfy the hackathon evaluation mandate, the system includes a built-in Lab Harness with verified detections:",
        body_style
    ))
    seeded_data = [
        [Paragraph("<b>Seeded Vulnerability</b>", body_style), Paragraph("<b>Test Asset</b>", body_style), Paragraph("<b>Detection Mechanism &amp; Severity</b>", body_style), Paragraph("<b>FP Risk &amp; Confidence</b>", body_style)],
        [
            Paragraph("<b>Expired TLS Certificate</b>", body_style),
            Paragraph("<code>expired-tls.aiori.internal</code>", body_style),
            Paragraph("<b>CRITICAL:</b> Cryptographic comparison of <code>not_after_utc</code> against current UTC clock. Detected expired 30 days ago.", body_style),
            Paragraph("Confidence: <b>HIGH</b><br/>FP Risk: <b>LOW</b>", body_style)
        ],
        [
            Paragraph("<b>Unexpected Open Service</b>", body_style),
            Paragraph("<code>10.0.1.15:8888</code>", body_style),
            Paragraph("<b>HIGH:</b> Baseline policy comparison flags unapproved port. Checks 2 &amp; 4 confirm active Werkzeug debug HTTP server.", body_style),
            Paragraph("Confidence: <b>HIGH</b><br/>FP Risk: <b>LOW</b>", body_style)
        ],
        [
            Paragraph("<b>Dangling DNS (AWS S3)</b>", body_style),
            Paragraph("<code>orphaned-bucket.aiori.internal</code>", body_style),
            Paragraph("<b>HIGH:</b> CNAME target points to S3. Non-intrusive probe detects XML signature: <code>NoSuchBucket</code> with HTTP 404.", body_style),
            Paragraph("Confidence: <b>HIGH</b><br/>FP Risk: <b>LOW</b>", body_style)
        ],
        [
            Paragraph("<b>Dangling DNS (GitHub)</b>", body_style),
            Paragraph("<code>blog.aiori.internal</code>", body_style),
            Paragraph("<b>HIGH:</b> CNAME target points to <code>*.github.io</code>. Probe confirms <code>There isn't a GitHub Pages site here</code>.", body_style),
            Paragraph("Confidence: <b>HIGH</b><br/>FP Risk: <b>LOW</b>", body_style)
        ],
        [
            Paragraph("<b>False-Positive Control</b>", body_style),
            Paragraph("<code>test-cdn.aiori.internal</code>", body_style),
            Paragraph("<b>CONTROL:</b> CNAME points to CloudFront edge returning 404. Filter recognizes multi-tenant CDN routing behavior.", body_style),
            Paragraph("Confidence: <b>LOW</b><br/>FP Risk: <b>HIGH</b>", body_style)
        ]
    ]
    t_seed = Table(seeded_data, colWidths=[1.8*inch, 1.8*inch, 2.4*inch, 1.2*inch])
    t_seed.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_seed)
    story.append(Spacer(1, 8))

    # Section 5
    story.append(Paragraph("5. False-Positive Analysis &amp; Confidence Framework", h1_style))
    story.append(Paragraph(
        "A central requirement of AIORI-3 PS-011 is reporting false positives and acknowledging that not all dangling records or open ports are exploitable. "
        "Our engine applies multi-factor triage filters:",
        body_style
    ))
    story.append(Paragraph("&bull; <b>Multi-Tenant CDN vs Orphaned Resource:</b> Distinguishes between dedicated storage buckets (S3) where 404 NoSuchBucket indicates true orphaned namespaces, versus shared CDN edges (CloudFront/Cloudflare) where 404 is standard when host routing is unconfigured.", bullet_style))
    story.append(Paragraph("&bull; <b>Wildcard DNS Filtering:</b> Compares resolutions against random non-existent test labels (e.g. <code>random_test_xyz.domain</code>) to prevent false alerts on catch-all zones.", bullet_style))
    story.append(Paragraph("&bull; <b>Firewall SYN-Proxy Sinkholes:</b> Evaluates total open port density. If &gt;15 ports open indiscriminately, marks alerts as Low Confidence / High FP Risk (honeypot or port reflector).", bullet_style))
    story.append(Paragraph("&bull; <b>SNI Isolation:</b> Enforces SNI in all TLS handshakes to avoid false expired cert alerts from fallback default certificates on reverse proxies.", bullet_style))
    story.append(Spacer(1, 6))

    # Section 6
    story.append(Paragraph("6. Prototype Demonstration with Pseudocode Snippet (Mentor Demonstration)", h1_style))
    story.append(Paragraph(
        "The following structured pseudocode represents the operational core of the change detection and inspection engine:",
        body_style
    ))
    pseudo_code = """FUNCTION RunAttackSurfaceMonitorCycle(scopeConfig, isBaseline):
    # 1. Enforce Organiser-Approved Boundaries
    domains = ScopeGuard.FilterDomains(scopeConfig.domains, maxLimit=20)
    hosts = ScopeGuard.FilterHosts(scopeConfig.hosts, maxLimit=10)

    # 2. Multi-Layer Discovery
    snapshot = NewInventorySnapshot(timestamp=NOW_UTC())
    FOR EACH domain IN domains:
        dnsRecords = DNSInspector.CatalogRecords(domain, [A, AAAA, CNAME, MX, TXT])
        FOR EACH record IN dnsRecords WHERE record.Type == CNAME:
            isDangling, provider, reason = DNSInspector.CheckDanglingCNAME(record.Target)
            IF isDangling: record.FlagAsDanglingCandidate(provider, reason)
        tlsCert = TLSInspector.Probe(domain, port=443)
        snapshot.AddDomain(domain, dnsRecords, tlsCert)

    FOR EACH host IN hosts:
        FOR EACH port IN scopeConfig.approvedPorts:
            # The 4 Documented Checks
            pState, rtt = Check1_TCPConnect(host, port)
            IF pState == OPEN:
                banner, service = Check2_BannerGrab(host, port)
                hasTLS, tlsVer, cipher, cert = Check3_TLSNegotiation(host, port)
                httpData = Check4_HTTPInspection(host, port, hasTLS)
                isUnexpected = (port NOT IN scopeConfig.baselineServices[host])
                snapshot.AddService(host, port, service, isUnexpected, cert, httpData)

    # 3. Baseline Delta & False-Positive Triage
    baseline = Storage.LoadBaseline()
    diff = DiffEngine.Compare(baseline, snapshot)
    FOR EACH alert IN diff.Alerts:
        alert.Confidence, alert.FPRisk, alert.Triage = FalsePositiveAnalyzer.Evaluate(alert)
        AlertManager.Dispatch(alert)

    Storage.SaveSnapshot(snapshot, markBaseline=isBaseline)
    RETURN diff"""
    story.append(Paragraph(pseudo_code.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style))

    # Section 7
    story.append(Paragraph("7. Ethical Scope Guardrails &amp; References", h1_style))
    story.append(Paragraph(
        "<b>Strict Scope Enforcement:</b> All probes are constrained to written, organiser-approved targets. "
        "<b>No Exploitation:</b> Probes are purely diagnostic and passive; no takeover claims or payload deliveries are made.<br/>"
        "<b>References:</b> [1] OWASP Web Security Testing Guide (WSTG-INFO-04 to 08); [2] RFC 793 (TCP); [3] RFC 8446 (TLS 1.3); [4] RFC 1035 (DNS).",
        body_style
    ))

    doc.build(story)
    return output_path
