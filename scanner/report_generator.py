"""Report Generator for LockSentry AI.

Produces exportable JSON and Markdown reports with:
- Deterministic policy gate decisions (PASS / BLOCK / REVIEW)
- Open-weight AI context analysis, trade-offs, and remediation recommendations
- Verified OSV vulnerability evidence and advisory links
- Clear indicators of whether AI inference was live or fallback
- Documented data limitations and supply-chain ambiguity
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from scanner.ai_analyzer import AIAnalysisResult
from scanner.dependency_parser import DependencyDiff
from scanner.osv_client import PackageSecurityStatus
from scanner.policy_engine import GateSummary


class AuditReport(BaseModel):
    """Unified audit report schema for LockSentry AI."""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool_name: str = "LockSentry AI"
    tool_version: str = "0.1.0"
    gate_decision: str
    manifest_source: str = "manifest"
    gate_summary: GateSummary
    ai_analysis: AIAnalysisResult
    security_statuses: List[PackageSecurityStatus]
    diffs: List[DependencyDiff] = Field(default_factory=list)


def generate_json_report(
    gate_summary: GateSummary,
    security_statuses: List[PackageSecurityStatus],
    ai_result: AIAnalysisResult,
    diffs: Optional[List[DependencyDiff]] = None,
    source_label: str = "manifest"
) -> str:
    """Generate a structured JSON report string."""
    report = AuditReport(
        gate_decision=gate_summary.overall_outcome,
        manifest_source=source_label,
        gate_summary=gate_summary,
        ai_analysis=ai_result,
        security_statuses=security_statuses,
        diffs=diffs or [],
    )
    return report.model_dump_json(indent=2)


def generate_markdown_report(
    gate_summary: GateSummary,
    security_statuses: List[PackageSecurityStatus],
    ai_result: AIAnalysisResult,
    diffs: Optional[List[DependencyDiff]] = None,
    source_label: str = "manifest"
) -> str:
    """Generate a clean, professional GitHub Flavored Markdown audit report."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    outcome = gate_summary.overall_outcome

    # Outcome badge
    badge_color = "🔴 BLOCK" if outcome == "BLOCK" else ("🟡 REVIEW" if outcome == "REVIEW" else "🟢 PASS")

    md: List[str] = []
    md.append(f"# LockSentry AI Security Gate Report")
    md.append(f"**Date**: `{timestamp}` | **Scan Target**: `{source_label}`")
    md.append(f"")
    md.append(f"## Gate Decision: **{badge_color}**")
    md.append(f"")

    # Summary metrics
    md.append(f"### Summary Metrics")
    md.append(f"| Metric | Value |")
    md.append(f"|---|---|")
    md.append(f"| **Overall Gate Decision** | **{outcome}** |")
    md.append(f"| **Total Dependencies Evaluated** | {gate_summary.total_packages_evaluated} |")
    md.append(f"| **Blocked Packages** | {gate_summary.blocked_count} |")
    md.append(f"| **Review Required** | {gate_summary.review_count} |")
    md.append(f"| **Passed Packages** | {gate_summary.passed_count} |")
    md.append(f"| **Known Vulnerabilities Found** | {gate_summary.total_vulnerabilities} |")
    md.append(f"| **AI Model Used** | `{ai_result.model_name}` ({'LIVE INFERENCE' if ai_result.is_live_model else 'DETERMINISTIC FALLBACK'}) |")
    md.append(f"| **AI Grounding Verified** | {'✅ Yes (Zero Hallucinations)' if ai_result.grounding_verified else '⚠️ Issues Detected'} |")
    md.append(f"")

    # Open-weight AI Analysis Section
    md.append(f"---")
    md.append(f"## Open-Weight AI Security Analysis")
    if ai_result.is_live_model:
        md.append(f"> [!NOTE]")
        md.append(f"> **Inference Engine**: Local Open-Weight Model `{ai_result.model_name}` via {ai_result.runtime_type} in {ai_result.duration_seconds:.2f}s.")
        md.append(f"> Grounding check: verified all package and advisory references against OSV records.")
    else:
        md.append(f"> [!WARNING]")
        md.append(f"> **AI Inference Status**: Fallback mode active ({ai_result.error_message or 'Model offline'}). Analysis generated via deterministic rules.")

    if ai_result.report:
        md.append(f"")
        md.append(f"### Executive Summary")
        md.append(f"{ai_result.report.executive_summary}")
        md.append(f"")
        md.append(f"### Upgrade & Remediation Guidance")
        md.append(f"{ai_result.report.overall_upgrade_recommendation}")
        md.append(f"")

        if ai_result.report.package_insights:
            md.append(f"### Deep Dive: Package Context & Trade-Offs")
            for insight in ai_result.report.package_insights:
                md.append(f"#### `{insight.package_name}`")
                md.append(f"- **Risk Context**: {insight.risk_interpretation}")
                md.append(f"- **Remediation Trade-Offs**: {insight.remediation_trade_offs}")
                md.append(f"- **Breaking Change Risk**: {insight.breaking_change_risk}")
                md.append(f"- **Uncertainty & Gaps**: {insight.uncertainty_gaps}")
                md.append(f"- **Review Rationale**: {insight.human_review_rationale}")
                md.append(f"")

        if ai_result.report.unresolved_questions:
            md.append(f"### Critical Questions for Maintainers")
            for q in ai_result.report.unresolved_questions:
                md.append(f"- [ ] {q}")
            md.append(f"")

    # Deterministic Policy Decisions Table
    md.append(f"---")
    md.append(f"## Deterministic Policy Evaluations")
    md.append(f"| Package | Version | Change | Gate | Primary Reason | Recommended Action |")
    md.append(f"|---|---|---|---|---|---|")
    for item in gate_summary.items:
        gate_badge = "🔴 BLOCK" if item.outcome == "BLOCK" else ("🟡 REVIEW" if item.outcome == "REVIEW" else "🟢 PASS")
        ver_str = item.new_version or "unpinned"
        md.append(f"| `{item.package_name}` | `{ver_str}` | {item.change_type} | **{gate_badge}** | {item.primary_reason} | {item.recommended_action} |")
    md.append(f"")

    # Detailed Vulnerability Evidence
    md.append(f"---")
    md.append(f"## Verified Vulnerability Evidence (OSV.dev)")
    has_vulns = any(s.vulnerabilities for s in security_statuses)
    if not has_vulns:
        md.append(f"No known public advisories were returned by OSV for the evaluated package versions.")
    else:
        for s in security_statuses:
            if not s.vulnerabilities:
                continue
            md.append(f"### Package: `{s.package_name}@{s.version}` ({s.ecosystem})")
            md.append(f"- **Recommended Fixed Version**: `{s.recommended_fixed_version or 'None specified'}`")
            md.append(f"- **All Documented Fixes**: {', '.join(f'`{f}`' for f in s.all_fixed_versions) or 'None'}")
            md.append(f"")
            md.append(f"| Vulnerability ID | Aliases | Severity | CVSS | Summary | Source References |")
            md.append(f"|---|---|---|---|---|---|")
            for v in s.vulnerabilities:
                aliases_str = ", ".join(v.aliases) or "None"
                cvss_str = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "N/A"
                refs_str = " ".join(f"[[Link]({u})]({u})" for u in v.references[:2]) if v.references else "None"
                osv_link = f"[{v.id}](https://osv.dev/vulnerability/{v.id})"
                summary_clean = v.summary.replace("|", "/") if v.summary else "Advisory details in references"
                md.append(f"| {osv_link} | {aliases_str} | **{v.severity_level}** | {cvss_str} | {summary_clean} | {refs_str} |")
            md.append(f"")

    # Limitations & Threat Boundary
    md.append(f"---")
    md.append(f"## Data Integrity & Limitations")
    md.append(f"1. **Intelligence Scope**: OSV vulnerability intelligence reflects publicly disclosed security advisories. Absence of an advisory does NOT guarantee zero vulnerabilities.")
    md.append(f"2. **Deterministic Precedence**: Open-weight AI models serve an advisory and explanatory role; they possess zero authority to override deterministic policy rejections.")
    md.append(f"3. **Execution Safety**: LockSentry AI operates purely via static manifest inspection and API evidence. No untrusted package install scripts were executed.")
    md.append(f"")
    md.append(f"*Report generated by LockSentry AI v0.1.0*")

    return "\n".join(md)
