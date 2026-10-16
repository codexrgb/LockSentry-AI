"""Tests for Deterministic Security Policy Engine."""

import pytest
from scanner.dependency_parser import DependencyDiff
from scanner.osv_client import PackageSecurityStatus, VulnerabilityEvidence
from scanner.policy_engine import DeterministicPolicyEngine, PolicyRuleConfig


def test_policy_block_on_vulnerability():
    engine = DeterministicPolicyEngine()
    vuln = VulnerabilityEvidence(
        id="GHSA-test-01",
        aliases=["CVE-2024-99999"],
        summary="Remote code execution",
        severity_level="CRITICAL",
        cvss_score=9.8,
    )
    status = PackageSecurityStatus(
        package_name="test-pkg",
        ecosystem="PyPI",
        version="1.0.0",
        is_pinned=True,
        status="CONFIRMED_VULNERABLE",
        vulnerabilities=[vuln],
        recommended_fixed_version="1.0.1",
    )
    result = engine.evaluate_item(status)
    assert result.outcome == "BLOCK"
    assert "Critical vulnerability" in result.primary_reason or "CVSS score" in result.primary_reason
    assert result.highest_severity == "CRITICAL"


def test_policy_block_on_downgrade():
    engine = DeterministicPolicyEngine()
    status = PackageSecurityStatus(
        package_name="requests",
        ecosystem="PyPI",
        version="2.20.0",
        is_pinned=True,
        status="NO_KNOWN_ADVISORY",
    )
    diff = DependencyDiff(
        name="requests",
        ecosystem="PyPI",
        old_version="2.25.0",
        new_version="2.20.0",
        change_type="DOWNGRADED",
    )
    result = engine.evaluate_item(status, diff)
    assert result.outcome == "BLOCK"
    assert "downgrade detected" in result.primary_reason.lower()


def test_policy_review_on_unpinned():
    engine = DeterministicPolicyEngine()
    status = PackageSecurityStatus(
        package_name="flask",
        ecosystem="PyPI",
        version=None,
        is_pinned=False,
        status="AMBIGUOUS_UNPINNED",
        limitations_and_ambiguity=["Floating version specifier."],
    )
    result = engine.evaluate_item(status)
    assert result.outcome == "REVIEW"
    assert "not pinned" in result.primary_reason.lower()


def test_policy_review_on_major_bump():
    engine = DeterministicPolicyEngine()
    status = PackageSecurityStatus(
        package_name="pydantic",
        ecosystem="PyPI",
        version="2.0.0",
        is_pinned=True,
        status="NO_KNOWN_ADVISORY",
    )
    diff = DependencyDiff(
        name="pydantic",
        ecosystem="PyPI",
        old_version="1.10.0",
        new_version="2.0.0",
        change_type="UPDATED",
        is_major_bump=True,
    )
    result = engine.evaluate_item(status, diff)
    assert result.outcome == "REVIEW"
    assert "major version bump" in result.primary_reason.lower()


def test_policy_pass_on_clean_package():
    engine = DeterministicPolicyEngine()
    status = PackageSecurityStatus(
        package_name="clean-pkg",
        ecosystem="PyPI",
        version="1.0.0",
        is_pinned=True,
        status="NO_KNOWN_ADVISORY",
    )
    diff = DependencyDiff(
        name="clean-pkg",
        ecosystem="PyPI",
        old_version="0.9.0",
        new_version="1.0.0",
        change_type="UPDATED",
    )
    result = engine.evaluate_item(status, diff)
    assert result.outcome == "PASS"


def test_policy_evaluate_all_aggregate():
    engine = DeterministicPolicyEngine()
    s_pass = PackageSecurityStatus(
        package_name="pkg-a", ecosystem="PyPI", version="1.0.0", status="NO_KNOWN_ADVISORY"
    )
    s_review = PackageSecurityStatus(
        package_name="pkg-b", ecosystem="PyPI", version=None, is_pinned=False, status="AMBIGUOUS_UNPINNED"
    )
    s_block = PackageSecurityStatus(
        package_name="pkg-c",
        ecosystem="PyPI",
        version="1.0.0",
        status="CONFIRMED_VULNERABLE",
        vulnerabilities=[VulnerabilityEvidence(id="GHSA-1", severity_level="HIGH")],
    )

    # Mixed with block -> overall BLOCK
    summary1 = engine.evaluate_all([s_pass, s_review, s_block])
    assert summary1.overall_outcome == "BLOCK"
    assert summary1.blocked_count == 1
    assert summary1.review_count == 1
    assert summary1.passed_count == 1

    # Mixed pass and review -> overall REVIEW
    summary2 = engine.evaluate_all([s_pass, s_review])
    assert summary2.overall_outcome == "REVIEW"

    # Only pass -> overall PASS
    summary3 = engine.evaluate_all([s_pass])
    assert summary3.overall_outcome == "PASS"
