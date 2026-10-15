"""
Alert formatting and reporting module for Authorised Attack-Surface Inventory and Change Monitor.
Generates terminal, JSON, and Markdown reports adhering to AIORI-3 PS-011 guidelines.
"""

from typing import List, Dict, Any
from pathlib import Path
from colorama import Fore, Style, init

from core.models import Alert, Severity, InventoryDiff

init(autoreset=True)


class AlertManager:
    SEVERITY_COLORS = {
        Severity.CRITICAL: Fore.RED + Style.BRIGHT,
        Severity.HIGH: Fore.LIGHTRED_EX,
        Severity.MEDIUM: Fore.YELLOW,
        Severity.LOW: Fore.CYAN,
        Severity.INFO: Fore.GREEN
    }

    @classmethod
    def print_terminal_summary(cls, diff: InventoryDiff):
        """Displays formatted delta and alerts summary to terminal."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*78}")
        print(f" AIORI-3 PS-011 ATTACK-SURFACE CHANGE & ALERT MONITOR")
        print(f"{'='*78}{Style.RESET_ALL}")
        print(f"Timestamp        : {diff.timestamp}")
        print(f"Baseline Snapshot: {diff.baseline_id}")
        print(f"Current Scan     : {diff.current_id}")
        print(f"Total Alerts     : {len(diff.alerts)}")
        print(f"{'-'*78}")
        
        # Summary counts
        counts = {sev: 0 for sev in Severity}
        for a in diff.alerts:
            counts[a.severity] = counts.get(a.severity, 0) + 1
            
        print(
            f"Severity Breakdown: "
            f"{Fore.RED}[CRITICAL: {counts[Severity.CRITICAL]}]{Style.RESET_ALL} "
            f"{Fore.LIGHTRED_EX}[HIGH: {counts[Severity.HIGH]}]{Style.RESET_ALL} "
            f"{Fore.YELLOW}[MEDIUM: {counts[Severity.MEDIUM]}]{Style.RESET_ALL} "
            f"{Fore.CYAN}[LOW: {counts[Severity.LOW]}]{Style.RESET_ALL} "
            f"{Fore.GREEN}[INFO: {counts[Severity.INFO]}]{Style.RESET_ALL}"
        )
        print(f"{'-'*78}\n")

        if not diff.alerts:
            print(f"{Fore.GREEN}[+] No new security drift, unexpected services, or dangling records detected.{Style.RESET_ALL}\n")
            return

        for idx, alert in enumerate(diff.alerts, 1):
            color = cls.SEVERITY_COLORS.get(alert.severity, Fore.WHITE)
            print(f"{color}[ALERT #{idx}] [{alert.severity.value}] {alert.title}{Style.RESET_ALL}")
            print(f"  Target           : {alert.target}")
            print(f"  Category         : {alert.category.value if hasattr(alert.category, 'value') else alert.category}")
            print(f"  Confidence       : {alert.confidence.value if hasattr(alert.confidence, 'value') else alert.confidence} (FP Risk: {alert.false_positive_risk})")
            print(f"  Description      : {alert.description}")
            if alert.triage_notes:
                print(f"  Triage Rationale : {Fore.WHITE}{alert.triage_notes}{Style.RESET_ALL}")
            if alert.remediation_recommendation:
                print(f"  Remediation      : {Fore.LIGHTBLUE_EX}{alert.remediation_recommendation}{Style.RESET_ALL}")
            print()

    @classmethod
    def generate_markdown_report(cls, diff: InventoryDiff, output_path: Path) -> Path:
        """Generates an executive Markdown alert and change report."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        counts = {sev: 0 for sev in Severity}
        for a in diff.alerts:
            counts[a.severity] = counts.get(a.severity, 0) + 1

        md = [
            "# AIORI-3 Attack-Surface Inventory & Change Report",
            f"**Problem Statement:** PS-011: Authorised Attack-Surface Inventory and Change Monitor  ",
            f"**Generated:** {diff.timestamp}  ",
            f"**Baseline Ref:** `{diff.baseline_id}` | **Current Scan:** `{diff.current_id}`  \n",
            "---",
            "## 1. Executive Summary",
            f"The continuous attack-surface monitoring scan completed with **{len(diff.alerts)} actionable alerts** identified.",
            "",
            "| Severity | Count | Primary Impact |",
            "| :--- | :--- | :--- |",
            f"| 🔴 **CRITICAL** | {counts[Severity.CRITICAL]} | Service Outages / Severe Trust Degradation (Expired TLS) |",
            f"| 🟠 **HIGH** | {counts[Severity.HIGH]} | Exposure of Unauthorized Services / Potential Dangling DNS Takeover Risks |",
            f"| 🟡 **MEDIUM** | {counts[Severity.MEDIUM]} | Unclassified Inventory Changes & Approaching Expirations |",
            f"| 🔵 **LOW** | {counts[Severity.LOW]} | Informational Disclosures / Missing Hardening Headers |",
            f"| 🟢 **INFO** | {counts[Severity.INFO]} | Normal Baseline Asset Deprecations |",
            "",
            "---",
            "## 2. Seeded Issues & Drift Verification Matrix",
            "",
            "| Category | Detected Target | Verification Details & False Positive Triage | Action Required |",
            "| :--- | :--- | :--- | :--- |"
        ]

        for a in diff.alerts:
            cat_str = a.category.value if hasattr(a.category, 'value') else str(a.category)
            sev_badge = f"`{a.severity.value}`"
            notes = a.triage_notes.replace("|", "/")
            remed = a.remediation_recommendation.replace("|", "/")
            md.append(f"| {sev_badge} **{cat_str}** | `{a.target}` | {notes} (Confidence: **{a.confidence.value}**) | {remed} |")

        md.extend([
            "",
            "---",
            "## 3. Detailed Alerts and Technical Remediation",
            ""
        ])

        for idx, a in enumerate(diff.alerts, 1):
            md.extend([
                f"### Alert {idx}: {a.title}",
                f"- **Target:** `{a.target}`",
                f"- **Category:** `{a.category.value if hasattr(a.category, 'value') else a.category}`",
                f"- **Severity:** **{a.severity.value}**",
                f"- **Confidence Assessment:** **{a.confidence.value}** (False Positive Probability: **{a.false_positive_risk}**)",
                f"- **Description:** {a.description}",
                f"- **Technical Triage Notes:** {a.triage_notes}",
                f"- **Remediation Steps:** {a.remediation_recommendation}",
                ""
            ])

        md.extend([
            "---",
            "## 4. Compliance & Ethical Guardrails",
            "- **Authorised Scope Enforced:** All scans strictly confined to written organiser-approved target assets.",
            "- **Non-Exploitation Standard:** No hostile subdomain takeovers or intrusive exploits were attempted.",
            "- **False-Positive Mitigation:** Multi-factor verification applied before flagging any asset.",
            ""
        ])

        output_path.write_text("\n".join(md), encoding="utf-8")
        return output_path
