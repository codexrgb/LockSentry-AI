"""Open-weight AI Analyzer for LockSentry AI.

Interfaces with a local open-weight model runtime (e.g. Ollama with gemma2:2b or llama3:latest)
to analyze verified vulnerability records, interpret dependency change context,
compare remediation trade-offs, identify uncertainty gaps, and generate structured
evidence-grounded security explanations.

NON-NEGOTIABLE PRINCIPLE:
AI inference never overrides deterministic security policies.
If model inference fails or is offline, the system degrades gracefully with clear indications,
without skipping any security gate checks.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ValidationError
import requests

from scanner.dependency_parser import DependencyDiff
from scanner.osv_client import PackageSecurityStatus
from scanner.policy_engine import GateSummary, PolicyCheckResult

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "gemma2:2b"
FALLBACK_MODEL = "llama3:latest"


class PackageAIInsight(BaseModel):
    """Structured AI reasoning for an individual dependency."""
    package_name: str
    risk_interpretation: str = Field(..., description="Contextual evaluation of vulnerability severity in runtime context")
    remediation_trade_offs: str = Field(..., description="Trade-offs between remaining on current version vs jumping to recommended fix")
    breaking_change_risk: str = Field(..., description="Evaluation of API disruption or compatibility risks")
    uncertainty_gaps: str = Field(..., description="Missing data, unpinned ambiguities, or unverified assumptions")
    human_review_rationale: str = Field(..., description="Why human judgment or testing is needed before merging")


class AIAnalysisReport(BaseModel):
    """Validated structured output produced by the open-weight AI model."""
    executive_summary: str = Field(..., description="High-level security summary of proposed changes")
    package_insights: List[PackageAIInsight] = Field(default_factory=list)
    overall_upgrade_recommendation: str = Field(..., description="Pragmatic guidance for developers")
    confidence_score: float = Field(0.0, description="Self-assessed confidence score between 0.0 and 1.0 based on evidence completeness")
    unresolved_questions: List[str] = Field(default_factory=list, description="Explicit questions maintainers should resolve")


class AIAnalysisResult(BaseModel):
    """Complete container for AI analysis results including runtime metadata and grounding checks."""
    model_name: str
    runtime_type: str = "Ollama (local open-weight)"
    inference_success: bool = False
    is_live_model: bool = False
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    report: Optional[AIAnalysisReport] = None
    grounding_verified: bool = False
    grounding_issues: List[str] = Field(default_factory=list)
    raw_response: Optional[str] = None


class OpenWeightAIAnalyzer:
    """Client for performing structured security analysis using a local open-weight LLM."""

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        model_name: str = DEFAULT_MODEL,
        timeout: float = 60.0
    ):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.timeout = timeout

    def check_runtime_health(self) -> Dict[str, Any]:
        """Check if local Ollama runtime is reachable and query available open-weight models."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5.0)
            if resp.status_code == 200:
                models_data = resp.json().get("models", [])
                available_names = [m.get("name") for m in models_data if m.get("name")]
                return {
                    "available": True,
                    "models": available_names,
                    "configured_model": self.model_name,
                    "model_present": any(self.model_name in name for name in available_names),
                    "url": self.base_url,
                }
            return {
                "available": False,
                "error": f"Ollama returned HTTP {resp.status_code}",
                "url": self.base_url,
            }
        except Exception as exc:
            return {
                "available": False,
                "error": str(exc),
                "url": self.base_url,
            }

    def _select_active_model(self) -> str:
        """Verify model availability, falling back to an available open-weight model if configured is absent."""
        health = self.check_runtime_health()
        if not health.get("available"):
            return self.model_name

        available = health.get("models", [])
        # Check if requested model is installed
        for name in available:
            if self.model_name in name:
                return name

        # Fallback to secondary known model
        for name in available:
            if FALLBACK_MODEL in name:
                logger.info(f"Preferred model '{self.model_name}' not found; falling back to '{name}'")
                return name

        # If any model exists, use the first available open-weight model
        if available:
            return available[0]

        return self.model_name

    def _build_analysis_prompt(
        self,
        gate_summary: GateSummary,
        security_statuses: List[PackageSecurityStatus],
        diffs: Optional[List[DependencyDiff]] = None
    ) -> str:
        """Construct an evidence-grounded prompt containing verified OSV findings and diffs."""
        # Compile verified evidence into concise, factual prompt context
        evidence_lines = []
        for status in security_statuses:
            vuln_details = []
            for v in status.vulnerabilities[:3]:  # Limit top 3 to keep prompt tight
                vuln_details.append(
                    f"ID: {v.id} (Aliases: {', '.join(v.aliases) or 'None'}), Severity: {v.severity_level}, "
                    f"Summary: {v.summary or 'No summary'}"
                )

            evidence_lines.append({
                "package": status.package_name,
                "ecosystem": status.ecosystem,
                "version": status.version or "UNPINNED",
                "osv_status": status.status,
                "vulnerabilities": vuln_details,
                "recommended_fixed_version": status.recommended_fixed_version or "None documented",
                "ambiguities": status.limitations_and_ambiguity,
            })

        prompt_data = {
            "deterministic_gate_outcome": gate_summary.overall_outcome,
            "blocked_count": gate_summary.blocked_count,
            "review_count": gate_summary.review_count,
            "packages_evidence": evidence_lines,
        }

        prompt = f"""You are LockSentry AI, an expert open-weight security analyzer evaluating software supply chain dependency changes.
You MUST reason strictly based on the verified evidence provided below. Do NOT invent CVEs, fixed versions, or security scores.

VERIFIED SECURITY EVIDENCE:
{json.dumps(prompt_data, indent=2)}

TASK:
Analyze the dependency change context and generate a valid JSON object matching the exact schema below:
{{
  "executive_summary": "Concise summary explaining the key supply chain risks and policy outcome.",
  "package_insights": [
    {{
      "package_name": "exact name from evidence",
      "risk_interpretation": "Specific explanation of what these vulnerabilities mean and how severe they are.",
      "remediation_trade_offs": "Trade-offs between staying on the current version vs upgrading to the recommended fix.",
      "breaking_change_risk": "Risk of API breaking changes or major version incompatibility.",
      "uncertainty_gaps": "Any unpinned constraints, missing CVSS scores, or unverified safety gaps.",
      "human_review_rationale": "Clear reason why human security/engineering review is required."
    }}
  ],
  "overall_upgrade_recommendation": "Practical step-by-step guidance for developers on how to remediate safely.",
  "confidence_score": 0.85,
  "unresolved_questions": [
    "Specific technical question for the engineering team"
  ]
}}

CRITICAL RULES:
1. Return ONLY the valid JSON object. No markdown code fences, no conversational text before or after.
2. Ground all claims in the provided evidence.
3. Every package in package_insights must match a package in the evidence.
"""
        return prompt

    def _verify_evidence_grounding(
        self,
        report: AIAnalysisReport,
        security_statuses: List[PackageSecurityStatus]
    ) -> tuple[bool, List[str]]:
        """Verify that AI claims are strictly grounded in verified OSV evidence without hallucinations."""
        issues: List[str] = []
        known_pkgs = {s.package_name.lower() for s in security_statuses}

        # Check that reported packages actually exist in scanned input
        for insight in report.package_insights:
            if insight.package_name.lower() not in known_pkgs:
                issues.append(f"AI referenced package '{insight.package_name}' which is not in the verified scanned dependencies.")

        # Check for hallucinated CVE identifiers in text
        all_known_vuln_ids = set()
        for s in security_statuses:
            for v in s.vulnerabilities:
                all_known_vuln_ids.add(v.id.upper())
                for alias in v.aliases:
                    all_known_vuln_ids.add(alias.upper())

        combined_text = (
            report.executive_summary + " " +
            report.overall_upgrade_recommendation + " " +
            " ".join(i.risk_interpretation + " " + i.remediation_trade_offs for i in report.package_insights)
        ).upper()

        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
        found_cves = cve_pattern.findall(combined_text)
        for cve in found_cves:
            if cve not in all_known_vuln_ids:
                issues.append(f"AI mentioned CVE '{cve}' which was not in verified OSV evidence (potential hallucination).")

        return len(issues) == 0, issues

    def _generate_deterministic_fallback_report(
        self,
        gate_summary: GateSummary,
        security_statuses: List[PackageSecurityStatus]
    ) -> AIAnalysisReport:
        """Provide a rigorous rule-based explanation when the AI model runtime is offline or fails validation."""
        insights = []
        for s in security_statuses:
            if s.vulnerabilities:
                vuln_count = len(s.vulnerabilities)
                cves = [v.id for v in s.vulnerabilities[:2]]
                risk = f"Package has {vuln_count} confirmed advisory records in OSV ({', '.join(cves)}). Immediate remediation recommended."
                trade_off = f"Remaining on version {s.version} carries known exploit risk. Upgrading to {s.recommended_fixed_version or 'latest patched version'} mitigates vulnerability."
                breaking = "Review package release notes for breaking changes before deployment."
                review = f"Verify compatibility with target version {s.recommended_fixed_version or 'patch release'}."
            elif not s.is_pinned:
                risk = "Unpinned version constraint allows variable package resolution at build time."
                trade_off = "Floating version ranges may pull untested upstream updates."
                breaking = "Future dependency builds may break if an incompatible minor/major version is published."
                review = "Pin exact dependency version in manifest or generate a lockfile."
            else:
                risk = f"No known security advisories found in OSV database for version {s.version}."
                trade_off = "Package meets current deterministic security baseline."
                breaking = "No upgrade necessary at this time."
                review = "Standard peer review recommended."

            insights.append(
                PackageAIInsight(
                    package_name=s.package_name,
                    risk_interpretation=risk,
                    remediation_trade_offs=trade_off,
                    breaking_change_risk=breaking,
                    uncertainty_gaps="OSV records only known public vulnerabilities; zero-day exposure cannot be ruled out.",
                    human_review_rationale=review,
                )
            )

        summary = (
            f"Deterministic Security Assessment: Gate decision is {gate_summary.overall_outcome}. "
            f"Evaluated {gate_summary.total_packages_evaluated} dependencies ({gate_summary.blocked_count} blocked, "
            f"{gate_summary.review_count} requiring review, {gate_summary.passed_count} passed). "
            "[FALLBACK MODE: AI inference runtime unavailable; analysis generated via deterministic security engine]."
        )

        return AIAnalysisReport(
            executive_summary=summary,
            package_insights=insights,
            overall_upgrade_recommendation="Apply all documented fixed versions and run test suites before merging.",
            confidence_score=0.75,
            unresolved_questions=["Have automated integration tests passed with proposed dependency versions?"],
        )

    def analyze(
        self,
        gate_summary: GateSummary,
        security_statuses: List[PackageSecurityStatus],
        diffs: Optional[List[DependencyDiff]] = None
    ) -> AIAnalysisResult:
        """Perform end-to-end AI analysis using local open-weight model with strict validation and grounding checks."""
        start_t = time.perf_counter()
        active_model = self._select_active_model()
        prompt = self._build_analysis_prompt(gate_summary, security_statuses, diffs)

        payload = {
            "model": active_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2,  # Low temperature for factual, grounded responses
                "num_predict": 1024,
            }
        }

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            elapsed = time.perf_counter() - start_t

            if resp.status_code != 200:
                err_msg = f"Ollama HTTP {resp.status_code}: {resp.text[:200]}"
                logger.warning(f"AI inference error: {err_msg}")
                fallback = self._generate_deterministic_fallback_report(gate_summary, security_statuses)
                return AIAnalysisResult(
                    model_name=active_model,
                    runtime_type="Ollama (local open-weight)",
                    inference_success=False,
                    is_live_model=False,
                    duration_seconds=elapsed,
                    error_message=err_msg,
                    report=fallback,
                    grounding_verified=True,
                    grounding_issues=[],
                )

            data = resp.json()
            raw_text = data.get("response", "").strip()

            # Parse JSON
            # In case model wrapped response in markdown fences ```json ... ```
            cleaned_text = raw_text
            if "```json" in cleaned_text:
                cleaned_text = cleaned_text.split("```json", 1)[1].split("```", 1)[0].strip()
            elif "```" in cleaned_text:
                cleaned_text = cleaned_text.split("```", 1)[1].split("```", 1)[0].strip()

            parsed_json = json.loads(cleaned_text)
            validated_report = AIAnalysisReport.model_validate(parsed_json)

            # Grounding check
            is_grounded, grounding_issues = self._verify_evidence_grounding(validated_report, security_statuses)

            return AIAnalysisResult(
                model_name=active_model,
                runtime_type="Ollama (local open-weight)",
                inference_success=True,
                is_live_model=True,
                duration_seconds=elapsed,
                report=validated_report,
                grounding_verified=is_grounded,
                grounding_issues=grounding_issues,
                raw_response=raw_text,
            )

        except (requests.exceptions.RequestException, json.JSONDecodeError, ValidationError) as exc:
            elapsed = time.perf_counter() - start_t
            err_msg = f"AI inference/validation failed: {str(exc)}"
            logger.warning(err_msg)
            fallback = self._generate_deterministic_fallback_report(gate_summary, security_statuses)

            return AIAnalysisResult(
                model_name=active_model,
                runtime_type="Ollama (local open-weight)",
                inference_success=False,
                is_live_model=False,
                duration_seconds=elapsed,
                error_message=err_msg,
                report=fallback,
                grounding_verified=True,
                grounding_issues=[f"Inference failed or invalid schema: {str(exc)}"],
            )
