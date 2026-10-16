"""LockSentry AI - Streamlit Web Dashboard.

AI-Assisted Software Dependency Security Gate powered by local open-weight models (Gemma 2 2B)
and deterministic OSV vulnerability intelligence.
"""

from __future__ import annotations

import json
from pathlib import Path
import streamlit as st

from scanner.engine import LockSentryEngine, ScanResult
from scanner.policy_engine import PolicyRuleConfig

# Page configuration
st.set_page_config(
    page_title="LockSentry AI - Dependency Security Gate",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #475569;
        margin-bottom: 1.5rem;
    }
    .badge-block {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 0.35rem 0.8rem;
        border-radius: 6px;
        font-weight: 700;
        border: 1px solid #F87171;
        display: inline-block;
    }
    .badge-review {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 0.35rem 0.8rem;
        border-radius: 6px;
        font-weight: 700;
        border: 1px solid #FBBF24;
        display: inline-block;
    }
    .badge-pass {
        background-color: #DCFCE7;
        color: #166534;
        padding: 0.35rem 0.8rem;
        border-radius: 6px;
        font-weight: 700;
        border: 1px solid #4ADE80;
        display: inline-block;
    }
    .kpi-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
    }
    .kpi-num {
        font-size: 1.8rem;
        font-weight: 800;
    }
    .kpi-label {
        font-size: 0.85rem;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
</style>
""", unsafe_allow_html=True)


def load_sample_file(path_str: str) -> str:
    """Helper to read sample file from disk."""
    p = Path(path_str)
    if p.exists():
        return p.read_text(encoding="utf-8")
    return ""


def main():
    st.markdown('<div class="main-header">🛡️ LockSentry AI</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">AI-Assisted Software Dependency Security Gate | '
        'Verified OSV.dev Intelligence + Deterministic Policy Rules + Open-Weight AI Analysis</div>',
        unsafe_allow_html=True
    )

    # Sidebar: Engine Configuration & Runtime Health
    st.sidebar.title("⚙️ Security Gate Settings")

    # Runtime Health Check
    engine_temp = LockSentryEngine()
    health = engine_temp.ai_analyzer.check_runtime_health()

    with st.sidebar.expander("🤖 Open-Weight AI Runtime", expanded=True):
        if health.get("available"):
            st.success(f"Ollama Online ({health.get('url')})")
            models = health.get("models", [])
            st.write("**Installed Models:**")
            for m in models:
                st.markdown(f"- `{m}`")
            default_ix = 0
            for ix, m in enumerate(models):
                if "gemma2:2b" in m:
                    default_ix = ix
                    break
            selected_model = st.selectbox("Active Inference Model", models, index=default_ix)
        else:
            st.warning(f"Ollama Offline ({health.get('url')})")
            st.info("System will operate in Deterministic Fallback Mode (zero model hallucination risk).")
            selected_model = "gemma2:2b"

    enable_ai = st.sidebar.checkbox("Enable Open-Weight AI Analysis", value=True)

    with st.sidebar.expander("🛡️ Deterministic Policy Engine", expanded=False):
        block_crit = st.checkbox("Block on Critical Severity", value=True)
        block_high = st.checkbox("Block on High Severity", value=True)
        block_med = st.checkbox("Block on Medium Severity", value=True)
        block_down = st.checkbox("Block on Version Downgrade", value=True)
        review_unpinned = st.checkbox("Review on Unpinned / Range", value=True)
        review_major = st.checkbox("Review on Major SemVer Bump", value=True)
        cvss_thresh = st.slider("CVSS Block Threshold", min_value=0.0, max_value=10.0, value=7.0, step=0.5)

    policy_config = PolicyRuleConfig(
        block_on_critical=block_crit,
        block_on_high=block_high,
        block_on_medium=block_med,
        block_on_downgrade=block_down,
        review_on_unpinned=review_unpinned,
        review_on_major_bump=review_major,
        cvss_block_threshold=cvss_thresh,
    )

    # Input Mode Selection
    mode = st.radio(
        "Select Gate Workflow Mode:",
        ["Comparative Gate (Existing vs Proposed)", "Single Manifest Scan", "Try Preset Samples"],
        horizontal=True
    )

    old_content: str | None = None
    old_filename: str | None = None
    new_content: str | None = None
    new_filename: str | None = None

    if mode == "Comparative Gate (Existing vs Proposed)":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("1. Existing (Base) Manifest / Lockfile")
            old_file = st.file_uploader(
                "Upload Current requirements.txt or package-lock.json",
                type=["txt", "json"],
                key="old_uploader"
            )
            if old_file:
                old_content = old_file.getvalue().decode("utf-8", errors="replace")
                old_filename = old_file.name

        with col2:
            st.subheader("2. Proposed (Target) Manifest / Lockfile")
            new_file = st.file_uploader(
                "Upload Proposed requirements.txt or package-lock.json",
                type=["txt", "json"],
                key="new_uploader"
            )
            if new_file:
                new_content = new_file.getvalue().decode("utf-8", errors="replace")
                new_filename = new_file.name

    elif mode == "Single Manifest Scan":
        st.subheader("Upload Dependency File to Inspect")
        new_file = st.file_uploader(
            "Upload requirements.txt or package-lock.json",
            type=["txt", "json"],
            key="single_uploader"
        )
        if new_file:
            new_content = new_file.getvalue().decode("utf-8", errors="replace")
            new_filename = new_file.name

    else:  # Preset Samples
        st.subheader("Select a Pre-configured Security Scenario")
        sample_choice = st.selectbox(
            "Choose Scenario:",
            [
                "Vulnerable Python Upgrade (requests 2.25.0 -> 2.33.1)",
                "Safe Python Dependencies (All Patched)",
                "Vulnerable npm Lockfile (lodash 4.17.15 & axios 0.21.1)",
                "Safe npm Lockfile (Patched)",
                "Unpinned Python Dependencies (Ambiguity / Supply Chain Risk)",
            ]
        )

        samples_dir = Path(__file__).parent / "samples"
        if sample_choice == "Vulnerable Python Upgrade (requests 2.25.0 -> 2.33.1)":
            old_content = (samples_dir / "vulnerable_requirements.txt").read_text(encoding="utf-8")
            old_filename = "vulnerable_requirements.txt"
            new_content = (samples_dir / "safe_requirements.txt").read_text(encoding="utf-8")
            new_filename = "safe_requirements.txt"
            st.info("Simulating upgrade PR from vulnerable base to safe fixed versions.")

        elif sample_choice == "Safe Python Dependencies (All Patched)":
            new_content = (samples_dir / "safe_requirements.txt").read_text(encoding="utf-8")
            new_filename = "safe_requirements.txt"

        elif sample_choice == "Vulnerable npm Lockfile (lodash 4.17.15 & axios 0.21.1)":
            new_content = (samples_dir / "vulnerable_package_lock.json").read_text(encoding="utf-8")
            new_filename = "package-lock.json"

        elif sample_choice == "Safe npm Lockfile (Patched)":
            new_content = (samples_dir / "safe_package_lock.json").read_text(encoding="utf-8")
            new_filename = "package-lock.json"

        elif sample_choice == "Unpinned Python Dependencies (Ambiguity / Supply Chain Risk)":
            new_content = (samples_dir / "unpinned_requirements.txt").read_text(encoding="utf-8")
            new_filename = "unpinned_requirements.txt"

    # Action Button
    run_btn = st.button("🚀 Run LockSentry Security Gate Analysis", type="primary", use_container_width=True)

    if run_btn:
        if not new_content:
            st.error("Please upload or select a valid target dependency file to analyze.")
            return

        with st.spinner("Inspecting dependencies, querying OSV database, and performing open-weight AI analysis..."):
            engine = LockSentryEngine(
                policy_config=policy_config,
                ai_model_name=selected_model,
            )
            result: ScanResult = engine.scan(
                new_manifest_content=new_content,
                new_filename=new_filename or "manifest.txt",
                old_manifest_content=old_content,
                old_filename=old_filename,
                enable_ai=enable_ai,
            )

        # Store in session state
        st.session_state["scan_result"] = result

    # Display Scan Result
    if "scan_result" in st.session_state:
        res: ScanResult = st.session_state["scan_result"]
        summary = res.gate_summary

        st.markdown("---")

        # Top Banner: Gate Outcome
        outcome_col, kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns([2.5, 1, 1, 1, 1, 1])

        with outcome_col:
            st.write("**OVERALL GATE DECISION:**")
            if summary.overall_outcome == "BLOCK":
                st.markdown(
                    '<span class="badge-block" style="font-size:1.6rem;">🔴 GATE BLOCKED</span>',
                    unsafe_allow_html=True
                )
                st.caption("Violated deterministic security policies. PR/build should be rejected.")
            elif summary.overall_outcome == "REVIEW":
                st.markdown(
                    '<span class="badge-review" style="font-size:1.6rem;">🟡 HUMAN REVIEW REQUIRED</span>',
                    unsafe_allow_html=True
                )
                st.caption("Unresolved ambiguities, unpinned versions, or major API upgrades detected.")
            else:
                st.markdown(
                    '<span class="badge-pass" style="font-size:1.6rem;">🟢 GATE PASSED</span>',
                    unsafe_allow_html=True
                )
                st.caption("All dependencies satisfy deterministic policies and OSV baseline.")

        with kpi1:
            st.metric("Total Evaluated", summary.total_packages_evaluated)
        with kpi2:
            st.metric("Blocked", summary.blocked_count)
        with kpi3:
            st.metric("Review Needed", summary.review_count)
        with kpi4:
            st.metric("Passed", summary.passed_count)
        with kpi5:
            st.metric("Known CVEs", summary.total_vulnerabilities)

        # Tabs for details
        tab_ai, tab_policy, tab_evidence, tab_diff, tab_export = st.tabs([
            "🤖 Open-Weight AI Insights",
            "🛡️ Deterministic Gate Decisions",
            "🔍 OSV Vulnerability Evidence",
            "📊 Version Diffs",
            "📥 Export Reports"
        ])

        # TAB 1: AI Analysis
        with tab_ai:
            ai = res.ai_result
            if ai.is_live_model:
                st.success(
                    f"**Live Model Inference Active**: Analyzed by `{ai.model_name}` ({ai.runtime_type}) "
                    f"in {ai.duration_seconds:.2f}s | Grounding Check: "
                    f"{'✅ Verified Grounded (No Hallucinations)' if ai.grounding_verified else '⚠️ Grounding Issues Detected'}"
                )
            else:
                st.warning(
                    f"**Deterministic Fallback Mode**: Model runtime unavailable ({ai.error_message or 'Offline'}). "
                    "Safety analysis generated deterministically without unverified AI output."
                )

            if ai.report:
                st.markdown("### 📋 Executive Supply-Chain Summary")
                st.info(ai.report.executive_summary)

                st.markdown("### 🛠️ Developer Remediation Guidance")
                st.markdown(ai.report.overall_upgrade_recommendation)

                if ai.report.package_insights:
                    st.markdown("### 🔍 Contextual Package Insights & Trade-Offs")
                    for p_insight in ai.report.package_insights:
                        with st.expander(f"📦 Package: `{p_insight.package_name}`", expanded=True):
                            st.markdown(f"- **Runtime Risk Context**: {p_insight.risk_interpretation}")
                            st.markdown(f"- **Remediation Trade-Offs**: {p_insight.remediation_trade_offs}")
                            st.markdown(f"- **Breaking Change Risk**: {p_insight.breaking_change_risk}")
                            st.markdown(f"- **Uncertainty & Gaps**: {p_insight.uncertainty_gaps}")
                            st.markdown(f"- **Why Review is Required**: {p_insight.human_review_rationale}")

                if ai.report.unresolved_questions:
                    st.markdown("### ❓ Maintainer Review Checklist")
                    for q in ai.report.unresolved_questions:
                        st.checkbox(q, value=False, key=f"chk_{q}")

        # TAB 2: Policy Decisions
        with tab_policy:
            st.markdown("### Deterministic Policy Rules & Outcomes")
            table_data = []
            for item in summary.items:
                badge = "🔴 BLOCK" if item.outcome == "BLOCK" else ("🟡 REVIEW" if item.outcome == "REVIEW" else "🟢 PASS")
                table_data.append({
                    "Package": item.package_name,
                    "Version": item.new_version or "unpinned",
                    "Change": item.change_type,
                    "Gate": badge,
                    "Primary Reason": item.primary_reason,
                    "Action": item.recommended_action,
                })
            st.dataframe(table_data, use_container_width=True)

        # TAB 3: Vulnerability Evidence
        with tab_evidence:
            st.markdown("### Verified OSV.dev Vulnerability Evidence")
            vulnerable_pkgs = [s for s in res.security_statuses if s.vulnerabilities]
            if not vulnerable_pkgs:
                st.success("No known public vulnerability advisories were returned by OSV for the evaluated packages.")
            else:
                for s in vulnerable_pkgs:
                    with st.expander(f"🚨 `{s.package_name}@{s.version}` — {len(s.vulnerabilities)} Advisories", expanded=True):
                        st.markdown(f"**Recommended Fixed Version**: `{s.recommended_fixed_version or 'None'}`")
                        st.markdown(f"**All Documented Fixes**: {', '.join(f'`{f}`' for f in s.all_fixed_versions) or 'None'}")
                        
                        vuln_table = []
                        for v in s.vulnerabilities:
                            vuln_table.append({
                                "Advisory ID": v.id,
                                "CVE Aliases": ", ".join(v.aliases) or "None",
                                "Severity": v.severity_level,
                                "CVSS": f"{v.cvss_score:.1f}" if v.cvss_score else "N/A",
                                "Summary": v.summary or "See advisory details",
                                "Reference URL": v.references[0] if v.references else f"https://osv.dev/vulnerability/{v.id}",
                            })
                        st.dataframe(vuln_table, use_container_width=True)

        # TAB 4: Version Diffs
        with tab_diff:
            st.markdown("### Dependency Version Comparison")
            if not res.diffs:
                st.info("No base manifest provided for comparison; operating in single manifest mode.")
            else:
                diff_table = []
                for d in res.diffs:
                    diff_table.append({
                        "Package": d.name,
                        "Ecosystem": d.ecosystem,
                        "Old Version": d.old_version or "None (New)",
                        "New Version": d.new_version or "None (Removed)",
                        "Change Type": d.change_type,
                        "Major Bump": "⚠️ Yes" if d.is_major_bump else "No",
                    })
                st.dataframe(diff_table, use_container_width=True)

        # TAB 5: Export Reports
        with tab_export:
            st.markdown("### Download Audit Artifacts")
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.download_button(
                    label="📄 Download Markdown Security Report (.md)",
                    data=res.markdown_report,
                    file_name="locksentry_report.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
            with col_d2:
                st.download_button(
                    label="📊 Download Structured JSON Audit (.json)",
                    data=res.json_report,
                    file_name="locksentry_report.json",
                    mime="application/json",
                    use_container_width=True,
                )

            st.markdown("### Markdown Report Preview")
            st.markdown(res.markdown_report)


if __name__ == "__main__":
    main()
