"""Unified execution engine for LockSentry AI.

Coordinates:
1. Parsing manifests / lockfiles (requirements.txt, package-lock.json)
2. Computing existing vs proposed version diffs
3. Retrieving verified OSV vulnerability records
4. Enforcing deterministic security policies (PASS / BLOCK / REVIEW)
5. Running open-weight AI analysis with schema validation & grounding
6. Exporting audit reports
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field

from scanner.ai_analyzer import AIAnalysisResult, OpenWeightAIAnalyzer
from scanner.dependency_parser import (
    Dependency,
    DependencyDiff,
    compare_dependencies,
    parse_manifest_file,
)
from scanner.osv_client import OSVClient, PackageSecurityStatus
from scanner.policy_engine import (
    DeterministicPolicyEngine,
    GateSummary,
    PolicyRuleConfig,
)
from scanner.report_generator import generate_json_report, generate_markdown_report


class ScanResult(BaseModel):
    """Complete container for a LockSentry AI security gate execution."""
    gate_summary: GateSummary
    security_statuses: List[PackageSecurityStatus]
    diffs: List[DependencyDiff]
    ai_result: AIAnalysisResult
    json_report: str
    markdown_report: str
    source_label: str
    parsed_old_deps_count: int = 0
    parsed_new_deps_count: int = 0


class LockSentryEngine:
    """Core security gate runner for LockSentry AI."""

    def __init__(
        self,
        policy_config: Optional[PolicyRuleConfig] = None,
        osv_timeout: float = 10.0,
        ai_base_url: str = "http://localhost:11434",
        ai_model_name: str = "gemma2:2b",
    ):
        self.policy_engine = DeterministicPolicyEngine(policy_config)
        self.osv_client = OSVClient(timeout=osv_timeout)
        self.ai_analyzer = OpenWeightAIAnalyzer(base_url=ai_base_url, model_name=ai_model_name)

    def scan(
        self,
        new_manifest_content: str,
        new_filename: str,
        old_manifest_content: Optional[str] = None,
        old_filename: Optional[str] = None,
        enable_ai: bool = True,
    ) -> ScanResult:
        """Run complete security gate inspection."""
        # 1. Parse dependencies
        new_deps = parse_manifest_file(new_manifest_content, new_filename)
        old_deps = parse_manifest_file(old_manifest_content, old_filename) if old_manifest_content else []

        # 2. Compute diffs if comparative mode
        diffs = compare_dependencies(old_deps, new_deps) if old_manifest_content else []

        # 3. Query OSV for proposed dependencies
        # Gather queries (name, ecosystem, version)
        queries = [(d.name, d.ecosystem, d.version) for d in new_deps]
        security_statuses = self.osv_client.query_batch(queries)

        # 4. Evaluate Deterministic Security Policies
        gate_summary = self.policy_engine.evaluate_all(security_statuses, diffs)

        # 5. Open-Weight AI Analysis
        source_label = f"{new_filename}" if not old_filename else f"{old_filename} -> {new_filename}"
        if enable_ai:
            ai_result = self.ai_analyzer.analyze(gate_summary, security_statuses, diffs)
        else:
            # Deterministic baseline mode without AI
            fallback = self.ai_analyzer._generate_deterministic_fallback_report(gate_summary, security_statuses)
            ai_result = AIAnalysisResult(
                model_name="none (baseline mode)",
                runtime_type="None (deterministic rules only)",
                inference_success=False,
                is_live_model=False,
                duration_seconds=0.0,
                error_message="AI analysis disabled by configuration",
                report=fallback,
                grounding_verified=True,
                grounding_issues=[],
            )

        # 6. Generate Reports
        json_rep = generate_json_report(gate_summary, security_statuses, ai_result, diffs, source_label)
        md_rep = generate_markdown_report(gate_summary, security_statuses, ai_result, diffs, source_label)

        return ScanResult(
            gate_summary=gate_summary,
            security_statuses=security_statuses,
            diffs=diffs,
            ai_result=ai_result,
            json_report=json_rep,
            markdown_report=md_rep,
            source_label=source_label,
            parsed_old_deps_count=len(old_deps),
            parsed_new_deps_count=len(new_deps),
        )
