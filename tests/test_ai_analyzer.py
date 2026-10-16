"""Tests for Open-Weight AI Analyzer module."""

from unittest.mock import MagicMock, patch
import pytest
from scanner.ai_analyzer import (
    AIAnalysisReport,
    OpenWeightAIAnalyzer,
    PackageAIInsight,
)
from scanner.osv_client import PackageSecurityStatus, VulnerabilityEvidence
from scanner.policy_engine import GateSummary


def test_ai_schema_validation():
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


def test_grounding_verification_detects_hallucinations():
    analyzer = OpenWeightAIAnalyzer()
    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.25.0",
        vulnerabilities=[VulnerabilityEvidence(id="GHSA-real-01", aliases=["CVE-2024-47081"])],
        status="CONFIRMED_VULNERABLE"
    )

    # Report mentions a hallucinated package "non-existent-lib" and hallucinated "CVE-2099-99999"
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

    is_grounded, issues = analyzer._verify_evidence_grounding(hallucinated_report, [status])
    assert is_grounded is False
    assert any("non-existent-lib" in iss for iss in issues)
    assert any("CVE-2099-99999" in iss for iss in issues)


def test_deterministic_fallback_when_runtime_offline():
    analyzer = OpenWeightAIAnalyzer(base_url="http://invalid-localhost:99999")
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
    assert "FALLBACK MODE" in result.report.executive_summary
    assert result.report.package_insights[0].package_name == "requests"


def test_live_open_weight_inference():
    """Mandatory integration test: invoke real configured open-weight model when Ollama is available."""
    analyzer = OpenWeightAIAnalyzer(model_name="gemma2:2b")
    health = analyzer.check_runtime_health()
    if not health.get("available"):
        pytest.skip(f"Local Ollama runtime offline: {health.get('error')}")

    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.25.0",
        status="CONFIRMED_VULNERABLE",
        vulnerabilities=[
            VulnerabilityEvidence(
                id="GHSA-9hjg-9r4m-mvj7",
                aliases=["CVE-2024-47081"],
                summary="Requests header leak vulnerability",
                severity_level="HIGH",
            )
        ],
        recommended_fixed_version="2.33.1",
    )
    summary = GateSummary(
        overall_outcome="BLOCK",
        total_packages_evaluated=1,
        blocked_count=1,
        items=[]
    )

    result = analyzer.analyze(summary, [status])
    assert result.inference_success is True
    assert result.is_live_model is True
    assert result.report is not None
    assert len(result.report.package_insights) >= 1
    assert result.duration_seconds > 0.0
