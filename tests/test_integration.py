"""End-to-end integration tests for LockSentry AI security gate."""

import json
from pathlib import Path
import pytest
from scanner.engine import LockSentryEngine

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def test_e2e_vulnerable_requirements_blocked():
    content = (SAMPLES_DIR / "vulnerable_requirements.txt").read_text(encoding="utf-8")
    engine = LockSentryEngine()
    result = engine.scan(
        new_manifest_content=content,
        new_filename="vulnerable_requirements.txt",
        enable_ai=False,  # baseline deterministic test
    )

    assert result.gate_summary.overall_outcome == "BLOCK"
    assert result.gate_summary.blocked_count >= 1
    assert result.gate_summary.total_vulnerabilities > 0
    assert "requests" in [item.package_name for item in result.gate_summary.items]
    assert len(result.json_report) > 100
    assert len(result.markdown_report) > 100


def test_e2e_safe_requirements_passed():
    content = (SAMPLES_DIR / "safe_requirements.txt").read_text(encoding="utf-8")
    engine = LockSentryEngine()
    result = engine.scan(
        new_manifest_content=content,
        new_filename="safe_requirements.txt",
        enable_ai=False,
    )

    assert result.gate_summary.overall_outcome == "PASS"
    assert result.gate_summary.blocked_count == 0
    assert result.gate_summary.review_count == 0
    assert result.gate_summary.passed_count == 3


def test_e2e_unpinned_requirements_review():
    content = (SAMPLES_DIR / "unpinned_requirements.txt").read_text(encoding="utf-8")
    engine = LockSentryEngine()
    result = engine.scan(
        new_manifest_content=content,
        new_filename="unpinned_requirements.txt",
        enable_ai=False,
    )

    assert result.gate_summary.overall_outcome == "REVIEW"
    assert result.gate_summary.review_count >= 1


def test_e2e_comparative_upgrade_workflow():
    old_content = (SAMPLES_DIR / "vulnerable_requirements.txt").read_text(encoding="utf-8")
    new_content = (SAMPLES_DIR / "safe_requirements.txt").read_text(encoding="utf-8")
    engine = LockSentryEngine()

    result = engine.scan(
        new_manifest_content=new_content,
        new_filename="safe_requirements.txt",
        old_manifest_content=old_content,
        old_filename="vulnerable_requirements.txt",
        enable_ai=False,
    )

    assert result.gate_summary.overall_outcome == "PASS"
    assert len(result.diffs) == 3
    diff_types = {d.name: d.change_type for d in result.diffs}
    assert diff_types["requests"] == "UPDATED"


def test_e2e_vulnerable_package_lock_blocked():
    content = (SAMPLES_DIR / "vulnerable_package_lock.json").read_text(encoding="utf-8")
    engine = LockSentryEngine()
    result = engine.scan(
        new_manifest_content=content,
        new_filename="package-lock.json",
        enable_ai=False,
    )

    assert result.gate_summary.overall_outcome == "BLOCK"
    assert any(item.package_name == "lodash" for item in result.gate_summary.items)


def test_e2e_report_integrity_and_export():
    content = (SAMPLES_DIR / "vulnerable_requirements.txt").read_text(encoding="utf-8")
    engine = LockSentryEngine()
    result = engine.scan(
        new_manifest_content=content,
        new_filename="vulnerable_requirements.txt",
        enable_ai=False,
    )

    parsed_json = json.loads(result.json_report)
    assert parsed_json["gate_decision"] == "BLOCK"
    assert "gate_summary" in parsed_json
    assert "BLOCK" in result.markdown_report
