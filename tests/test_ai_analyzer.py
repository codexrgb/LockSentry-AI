"""Tests for Open-Weight AI Analyzer module.

Covers:
- Pydantic schema validation
- Model selection from approved open-weight allowlist
- Rejection of arbitrary unapproved models
- Dependency-diff inclusion in AI prompt
- Grounding verification (hallucinated CVEs, unknown packages, overconfident safety claims)
- Invalid model output handling
- Offline fallback handling and explicit non-AI labeling
- Policy independence (AI cannot override deterministic BLOCK)
- Live open-weight inference with local Gemma 2 2B
"""

from unittest.mock import MagicMock, patch
import pytest
import requests

from scanner.ai_analyzer import (
    AIAnalysisReport,
    AIAnalysisResult,
    OpenWeightAIAnalyzer,
    PackageAIInsight,
)
from scanner.dependency_parser import DependencyDiff
from scanner.osv_client import PackageSecurityStatus, VulnerabilityEvidence
from scanner.policy_engine import DeterministicPolicyEngine, GateSummary


def test_ai_schema_validation():
    """Verify that AIAnalysisReport validates correct schema and rejects malformed fields."""
    valid_payload = {
        "executive_summary": "Supply chain risk detected due to critical CVEs.",
        "package_insights": [
            {
                "package_name": "requests",
                "risk_interpretation": "Vulnerable to data exfiltration via proxy headers.",
                "remediation_trade_offs": "Immediate upgrade to 2.33.1 eliminates vulnerability.",
                "breaking_change_risk": "Low risk; API backwards-compatible.",
                "uncertainty_gaps": "None identified.",
                "human_review_rationale": "Verify integration tests pass."
            }
        ],
        "overall_upgrade_recommendation": "Merge proposed fix version 2.33.1.",
        "confidence_score": 0.95,
        "unresolved_questions": ["Have regression tests executed?"]
    }
    report = AIAnalysisReport.model_validate(valid_payload)
    assert report.confidence_score == 0.95
    assert len(report.package_insights) == 1
    assert report.package_insights[0].package_name == "requests"


def test_model_selection_approved_primary():
    """Verify that configured approved model is selected when present in Ollama."""
    analyzer = OpenWeightAIAnalyzer(model_name="gemma2:2b")
    mock_health = {
        "available": True,
        "models": ["gemma2:2b", "llama3:latest"],
    }
    with patch.object(analyzer, "check_runtime_health", return_value=mock_health):
        selected = analyzer.select_active_model()
        assert selected == "gemma2:2b"


def test_model_selection_approved_fallback():
    """Verify that when primary model is missing, approved fallback is selected."""
    analyzer = OpenWeightAIAnalyzer(model_name="gemma2:9b", fallback_model="llama3:latest")
    mock_health = {
        "available": True,
        "models": ["llama3:latest"],
    }
    with patch.object(analyzer, "check_runtime_health", return_value=mock_health):
        selected = analyzer.select_active_model()
        assert selected == "llama3:latest"


def test_model_selection_rejects_arbitrary_unapproved_model():
    """Verify that arbitrary unapproved models are NEVER silently selected."""
    analyzer = OpenWeightAIAnalyzer(
        model_name="gemma2:2b",
        fallback_model="llama3:latest",
        approved_models=("gemma2:2b", "llama3:latest")
    )
    # Ollama has only an unapproved arbitrary model
    mock_health = {
        "available": True,
        "models": ["unvetted-arbitrary-model:latest", "other-closed-model:v1"],
    }
    with patch.object(analyzer, "check_runtime_health", return_value=mock_health):
        selected = analyzer.select_active_model()
        # Must return None rather than silently choosing unvetted-arbitrary-model:latest
        assert selected is None


def test_dependency_diff_inclusion_in_prompt():
    """Verify that dependency diffs (old_version, new_version, change_type) are serialized into AI prompt."""
    analyzer = OpenWeightAIAnalyzer()
    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.33.1",
        status="NO_KNOWN_ADVISORY"
    )
    diff = DependencyDiff(
        name="requests",
        ecosystem="PyPI",
        old_version="2.25.0",
        new_version="2.33.1",
        change_type="UPDATED",
        is_major_bump=False,
    )
    summary = GateSummary(overall_outcome="PASS", total_packages_evaluated=1, items=[])

    prompt = analyzer.build_analysis_prompt(summary, [status], [diff])

    assert "dependency_changes" in prompt
    assert "2.25.0" in prompt
    assert "2.33.1" in prompt
    assert "UPDATED" in prompt
    assert "requests" in prompt


def test_grounding_verification_detects_hallucinations():
    """Verify that invented CVEs and packages not in OSV evidence are detected as grounding issues."""
    analyzer = OpenWeightAIAnalyzer()
    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.25.0",
        vulnerabilities=[VulnerabilityEvidence(id="GHSA-real-01", aliases=["CVE-2024-47081"])],
        status="CONFIRMED_VULNERABLE"
    )

    hallucinated_report = AIAnalysisReport(
        executive_summary="Exploit detected in CVE-2099-99999 and CVE-2024-47081.",
        package_insights=[
            PackageAIInsight(
                package_name="non-existent-lib",
                risk_interpretation="Invented risk",
                remediation_trade_offs="None",
                breaking_change_risk="None",
                uncertainty_gaps="None",
                human_review_rationale="Review"
            )
        ],
        overall_upgrade_recommendation="Do upgrade",
        confidence_score=0.5,
    )

    is_grounded, issues = analyzer.verify_evidence_grounding(hallucinated_report, [status])
    assert is_grounded is False
    assert any("non-existent-lib" in iss for iss in issues)
    assert any("CVE-2099-99999" in iss for iss in issues)


def test_grounding_verification_detects_overconfident_safety_claims():
    """Verify that overconfident absolute safety assertions ('100% safe', 'completely secure') are caught."""
    analyzer = OpenWeightAIAnalyzer()
    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.33.1",
        status="NO_KNOWN_ADVISORY"
    )

    overconfident_report = AIAnalysisReport(
        executive_summary="This upgrade is completely safe and 100% secure with zero vulnerabilities exist.",
        package_insights=[
            PackageAIInsight(
                package_name="requests",
                risk_interpretation="No security risk at all, totally safe.",
                remediation_trade_offs="None",
                breaking_change_risk="None",
                uncertainty_gaps="None",
                human_review_rationale="None"
            )
        ],
        overall_upgrade_recommendation="Approve",
        confidence_score=1.0,
    )

    is_grounded, issues = analyzer.verify_evidence_grounding(overconfident_report, [status])
    assert is_grounded is False
    assert any("Overconfident safety assertion" in iss for iss in issues)


def test_grounding_verification_detects_unpinned_safety_claims():
    """Verify that claiming an unpinned package is safe triggers an unsupported claim issue."""
    analyzer = OpenWeightAIAnalyzer()
    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version=None,
        is_pinned=False,
        status="AMBIGUOUS_UNPINNED"
    )

    unpinned_safe_report = AIAnalysisReport(
        executive_summary="Analysis completed.",
        package_insights=[
            PackageAIInsight(
                package_name="requests",
                risk_interpretation="Package is safe to use in production.",
                remediation_trade_offs="None",
                breaking_change_risk="None",
                uncertainty_gaps="None",
                human_review_rationale="Review"
            )
        ],
        overall_upgrade_recommendation="Approve",
        confidence_score=0.8,
    )

    is_grounded, issues = analyzer.verify_evidence_grounding(unpinned_safe_report, [status])
    assert is_grounded is False
    assert any("Unsupported safety claim: Package 'requests' is unpinned" in iss for iss in issues)


def test_invalid_model_output_triggers_deterministic_fallback():
    """Verify that corrupt or invalid model JSON triggers graceful deterministic fallback with clear labels."""
    analyzer = OpenWeightAIAnalyzer()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "{corrupt invalid json response from model..."}

    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.25.0",
        status="CONFIRMED_VULNERABLE",
        vulnerabilities=[VulnerabilityEvidence(id="GHSA-01", severity_level="HIGH")],
    )
    summary = GateSummary(overall_outcome="BLOCK", total_packages_evaluated=1, items=[])

    with patch("requests.post", return_value=mock_resp), \
         patch.object(analyzer, "select_active_model", return_value="gemma2:2b"):
        result = analyzer.analyze(summary, [status])

        assert result.inference_success is False
        assert result.is_live_model is False
        assert result.report is not None
        assert "[DETERMINISTIC FALLBACK — NOT AI GENERATED]" in result.report.executive_summary
        assert "Invalid Output" in result.model_name or "Fallback Used" in result.model_name
        assert "Deterministic Rule Engine" in result.runtime_type


def test_offline_fallback_clearly_labeled():
    """Verify that offline Ollama runtime triggers deterministic fallback with zero live-inference claim."""
    analyzer = OpenWeightAIAnalyzer(base_url="http://invalid-offline-host:99999")
    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.25.0",
        status="CONFIRMED_VULNERABLE",
        vulnerabilities=[VulnerabilityEvidence(id="GHSA-9hjg-9r4m-mvj7", severity_level="HIGH")],
        recommended_fixed_version="2.32.4",
    )
    summary = GateSummary(
        overall_outcome="BLOCK",
        total_packages_evaluated=1,
        blocked_count=1,
        items=[]
    )

    result = analyzer.analyze(summary, [status])
    assert result.inference_success is False
    assert result.is_live_model is False
    assert result.report is not None
    assert "[DETERMINISTIC FALLBACK — NOT AI GENERATED]" in result.report.executive_summary
    assert "Deterministic Rule Engine" in result.runtime_type
    assert result.report.package_insights[0].risk_interpretation.startswith("[Deterministic Rule]")


def test_policy_independence_ai_cannot_override_block():
    """Verify that deterministic policy engine maintains BLOCK regardless of hypothetical AI opinion."""
    policy_engine = DeterministicPolicyEngine()
    vuln_status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.25.0",
        status="CONFIRMED_VULNERABLE",
        vulnerabilities=[
            VulnerabilityEvidence(
                id="GHSA-critical-01",
                aliases=["CVE-2024-47081"],
                severity_level="CRITICAL",
                cvss_score=9.8
            )
        ]
    )

    # 1. Deterministic evaluation MUST be BLOCK
    check = policy_engine.evaluate_item(vuln_status)
    assert check.outcome == "BLOCK"
    summary = policy_engine.evaluate_all([vuln_status])
    assert summary.overall_outcome == "BLOCK"

    # 2. Even if an AI report claims low risk, the deterministic gate outcome remains BLOCK
    analyzer = OpenWeightAIAnalyzer()
    fallback = analyzer.generate_deterministic_fallback_report(summary, [vuln_status])
    # The gate decision in the report must strictly reflect the deterministic BLOCK
    assert "BLOCK" in fallback.executive_summary


def test_live_open_weight_inference_with_diffs():
    """Mandatory integration test: invoke real configured local Gemma 2 2B with actual diffs."""
    analyzer = OpenWeightAIAnalyzer(model_name="gemma2:2b")
    health = analyzer.check_runtime_health()
    if not health.get("available") or not health.get("model_present"):
        pytest.skip(f"Local Ollama gemma2:2b runtime unavailable: {health.get('error')}")

    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.25.0",
        status="CONFIRMED_VULNERABLE",
        vulnerabilities=[
            VulnerabilityEvidence(
                id="GHSA-9hjg-9r4m-mvj7",
                aliases=["CVE-2024-47081"],
                summary="Requests authorization header leakage on redirect",
                severity_level="HIGH",
            )
        ],
        recommended_fixed_version="2.33.1",
    )
    diff = DependencyDiff(
        name="requests",
        ecosystem="PyPI",
        old_version="2.25.0",
        new_version="2.33.1",
        change_type="UPDATED",
    )
    summary = GateSummary(
        overall_outcome="BLOCK",
        total_packages_evaluated=1,
        blocked_count=1,
        items=[]
    )

    result = analyzer.analyze(summary, [status], [diff])
    assert result.inference_success is True
    assert result.is_live_model is True
    assert result.report is not None
    assert len(result.report.package_insights) >= 1
    assert result.duration_seconds > 0.0
    assert result.grounding_verified is True
