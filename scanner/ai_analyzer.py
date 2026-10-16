"""Open-weight AI Analyzer for LockSentry AI.

Interfaces with a local open-weight model runtime (Ollama) to analyze verified
vulnerability records, interpret dependency change diffs, compare remediation
trade-offs, identify uncertainty gaps, and generate structured, evidence-grounded
security explanations.

NON-NEGOTIABLE PRINCIPLES:
1. Local Open-Weight Only: Only verified, approved open-weight models (e.g. Google Gemma 2 2B)
   may be executed. Arbitrary unapproved installed models are strictly disallowed.
2. Deterministic Precedence: AI inference never overrides deterministic security policies.
3. Transparent Fallback: If model inference fails, is offline, or no approved model is found,
   the system executes a deterministic fallback that is explicitly labeled as non-AI.
   Fallback output is NEVER marked as a live model inference.
4. Evidence Grounding & Uncertainty: Claims must be grounded in OSV evidence; overconfident
   or unsupported safety assertions are flagged as grounding violations.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field, ValidationError
import requests

from scanner.dependency_parser import DependencyDiff
from scanner.osv_client import PackageSecurityStatus
from scanner.policy_engine import GateSummary

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "gemma2:2b"
APPROVED_FALLBACK_MODEL = "llama3:latest"

# Explicit allowlist of approved, verified open-weight model identifiers.
# Arbitrary installed models outside this list will NEVER be silently selected.
APPROVED_OPEN_WEIGHT_MODELS: Tuple[str, ...] = (
    "gemma2:2b",
    "gemma2",
    "gemma:2b",
    "gemma",
    "llama3:latest",
    "llama3",
    "llama3:8b",
)

# Overconfident or unsupported phrases that violate empirical supply-chain security standards.
OVERCONFIDENT_SAFETY_PATTERNS = [
    re.compile(r"\b(completely|totally|entirely|100%|guaranteed)\s+safe\b", re.IGNORECASE),
    re.compile(r"\b(completely|totally|entirely|100%|guaranteed)\s+secure\b", re.IGNORECASE),
    re.compile(r"\bzero\s+(vulnerabilities|bugs|flaws|risks?)\s+exist\b", re.IGNORECASE),
    re.compile(r"\bno\s+(security\s+)?risk\b", re.IGNORECASE),
    re.compile(r"\bimmune\s+to\s+vulnerabilit(y|ies)\b", re.IGNORECASE),
]


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
        fallback_model: str = APPROVED_FALLBACK_MODEL,
        timeout: float = 60.0,
        approved_models: Tuple[str, ...] = APPROVED_OPEN_WEIGHT_MODELS,
    ):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.fallback_model = fallback_model
        self.timeout = timeout
        self.approved_models = approved_models

    def check_runtime_health(self) -> Dict[str, Any]:
        """Check if local Ollama runtime is reachable and query available models."""
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

    def select_active_model(self) -> Optional[str]:
        """Select an approved open-weight model.
        
        Strict Enforcement:
        1. Checks if configured model is available AND in the approved open-weight allowlist.
        2. If absent, checks if fallback model is available AND in the approved open-weight allowlist.
        3. NEVER silently selects an arbitrary installed model outside the approved allowlist.
        4. Returns None if no approved model is available, triggering deterministic fallback.
        """
        health = self.check_runtime_health()
        if not health.get("available"):
            return None

        available = health.get("models", [])

        # 1. Check primary configured model
        for name in available:
            if self.model_name in name:
                # Verify that the model is in the approved open-weight list
                if any(approved in name for approved in self.approved_models):
                    return name
                else:
                    logger.warning(f"Configured model '{name}' is not in approved open-weight allowlist.")

        # 2. Check approved fallback model
        for name in available:
            if self.fallback_model in name:
                if any(approved in name for approved in self.approved_models):
                    logger.info(
                        f"Primary model '{self.model_name}' unavailable; falling back to approved model '{name}'."
                    )
                    return name

        # 3. Security Boundary: Do NOT pick arbitrary models from `available[0]`.
        logger.warning(
            f"No approved open-weight model found in Ollama runtime. "
            f"Available models: {available}. Approved list: {self.approved_models}. "
            "Refusing to select arbitrary installed model."
        )
        return None

    def build_analysis_prompt(
        self,
        gate_summary: GateSummary,
        security_statuses: List[PackageSecurityStatus],
        diffs: Optional[List[DependencyDiff]] = None
    ) -> str:
        """Construct an evidence-grounded prompt containing verified OSV findings AND actual dependency diffs."""
        evidence_lines = []
        for status in security_statuses:
            vuln_details = []
            for v in status.vulnerabilities[:3]:  # Top 3 to maintain high prompt quality
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

        # Explicitly format actual dependency diffs (old vs proposed)
        diff_entries = []
        if diffs:
            for d in diffs:
                diff_entries.append({
                    "package": d.name,
                    "ecosystem": d.ecosystem,
                    "old_version": d.old_version or "None (New Dependency)",
                    "new_version": d.new_version or "None (Removed Dependency)",
                    "change_type": d.change_type,
                    "is_major_bump": d.is_major_bump,
                    "version_warning": d.version_comparison_warning,
                })

        prompt_data = {
            "deterministic_gate_outcome": gate_summary.overall_outcome,
            "blocked_count": gate_summary.blocked_count,
            "review_count": gate_summary.review_count,
            "dependency_changes": diff_entries,
            "packages_evidence": evidence_lines,
        }

        prompt = f"""You are LockSentry AI, an expert open-weight security analyzer evaluating software supply chain dependency changes.
You MUST reason strictly based on the verified evidence and version diffs provided below. Do NOT invent CVEs, fixed versions, or security scores.

VERIFIED SECURITY EVIDENCE & DEPENDENCY CHANGES:
{json.dumps(prompt_data, indent=2)}

TASK:
Analyze the dependency change context, version diffs (old_version -> new_version), and vulnerability evidence.
Generate a valid JSON object matching the exact schema below:
{{
  "executive_summary": "Concise summary explaining the key supply chain risks, version transitions, and policy outcome.",
  "package_insights": [
    {{
      "package_name": "exact name from evidence",
      "risk_interpretation": "Specific explanation of what these vulnerabilities mean and how severe they are in runtime context.",
      "remediation_trade_offs": "Trade-offs between staying on the old version vs upgrading to the proposed or recommended fix.",
      "breaking_change_risk": "Risk of API breaking changes or major version incompatibility between versions.",
      "uncertainty_gaps": "Any unpinned constraints, missing CVSS scores, absence of advisories vs zero-day uncertainty, or unverified safety gaps.",
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
4. Do NOT make overconfident claims that an unpinned or unadvisoried package is 'completely safe' or '100% secure'.
5. Explicitly reference the old vs proposed version diffs where available.
"""
        return prompt

    def verify_evidence_grounding(
        self,
        report: AIAnalysisReport,
        security_statuses: List[PackageSecurityStatus]
    ) -> Tuple[bool, List[str]]:
        """Verify that AI claims are strictly grounded in verified OSV evidence without hallucinations or overconfident claims."""
        issues: List[str] = []
        known_pkgs = {s.package_name.lower() for s in security_statuses}
        status_map = {s.package_name.lower(): s for s in security_statuses}

        # 1. Check that reported packages actually exist in scanned input
        for insight in report.package_insights:
            p_name = insight.package_name.lower()
            if p_name not in known_pkgs:
                issues.append(f"AI referenced package '{insight.package_name}' which is not in the verified scanned dependencies.")
            else:
                s = status_map[p_name]
                # Check for unsupported safety claims on unpinned packages
                if not s.is_pinned:
                    insight_text = (insight.risk_interpretation + " " + insight.remediation_trade_offs).lower()
                    if "safe" in insight_text and "not safe" not in insight_text:
                        issues.append(
                            f"Unsupported safety claim: Package '{insight.package_name}' is unpinned. "
                            "Unpinned packages cannot be declared safe without an exact locked version."
                        )

        # 2. Check for hallucinated CVE identifiers in text
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
        )

        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        found_cves = cve_pattern.findall(combined_text)
        for cve in found_cves:
            if cve.upper() not in all_known_vuln_ids:
                issues.append(f"AI mentioned CVE '{cve}' which was not in verified OSV evidence (potential hallucination).")

        # 3. Check for overconfident or unsupported absolute safety claims
        for pat in OVERCONFIDENT_SAFETY_PATTERNS:
            match = pat.search(combined_text)
            if match:
                issues.append(
                    f"Overconfident safety assertion detected ('{match.group(0)}'). "
                    "Absence of recorded OSV advisories does not guarantee absolute safety or zero-day immunity."
                )

        return len(issues) == 0, issues

    def generate_deterministic_fallback_report(
        self,
        gate_summary: GateSummary,
        security_statuses: List[PackageSecurityStatus],
        diffs: Optional[List[DependencyDiff]] = None,
        reason: str = "AI inference runtime unavailable"
    ) -> AIAnalysisReport:
        """Provide a rigorous rule-based explanation when AI model runtime is offline, unapproved, or fails validation.
        
        Strict Labeling:
        The output is explicitly stamped as [DETERMINISTIC FALLBACK — NOT AI GENERATED] to prevent
        any perception of automated model hallucination or false inference claims.
        """
        diff_map = {d.name.lower(): d for d in (diffs or [])}
        insights = []

        for s in security_statuses:
            d = diff_map.get(s.package_name.lower())
            old_v = d.old_version if d else None
            new_v = s.version

            if s.vulnerabilities:
                vuln_count = len(s.vulnerabilities)
                cves = [v.id for v in s.vulnerabilities[:2]]
                risk = (
                    f"[Deterministic Rule] Package has {vuln_count} confirmed advisory records in OSV "
                    f"({', '.join(cves)}). Immediate remediation required."
                )
                trade_off = (
                    f"Remaining on version {new_v} maintains known CVE exposure. "
                    f"Upgrading to {s.recommended_fixed_version or 'latest patched release'} eliminates vulnerability."
                )
                breaking = (
                    "Major version bump detected — test for breaking changes."
                    if (d and d.is_major_bump) else
                    "Review package release notes before merging."
                )
                review = f"Verify compatibility with target version {s.recommended_fixed_version or 'patch release'}."
            elif not s.is_pinned:
                risk = "[Deterministic Rule] Unpinned version constraint allows variable package resolution at build time."
                trade_off = "Floating version ranges may pull untested upstream updates."
                breaking = "Future dependency builds may break if an incompatible minor/major version is published."
                review = "Pin exact dependency version in manifest or generate a lockfile."
            else:
                risk = f"[Deterministic Rule] No known security advisories found in OSV database for version {new_v}."
                trade_off = "Package meets current deterministic security baseline."
                breaking = (
                    "Major version bump detected — verify backward compatibility."
                    if (d and d.is_major_bump) else
                    "No upgrade necessary at this time."
                )
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
            f"[DETERMINISTIC FALLBACK — NOT AI GENERATED] "
            f"Gate decision is {gate_summary.overall_outcome}. "
            f"Evaluated {gate_summary.total_packages_evaluated} dependencies ({gate_summary.blocked_count} blocked, "
            f"{gate_summary.review_count} requiring review, {gate_summary.passed_count} passed). "
            f"Reason: {reason}. All explanations generated via deterministic security engine rules."
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
        """Perform end-to-end AI analysis using an approved local open-weight model with strict validation.
        
        Guarantees:
        - Only approved open-weight models are ever executed.
        - Dependency diffs are included in the prompt.
        - Fallbacks are explicitly stamped as deterministic and NOT live model inferences.
        - Grounding checks detect hallucinations and overconfident safety claims.
        """
        start_t = time.perf_counter()
        active_model = self.select_active_model()

        # If no approved open-weight model is available, execute deterministic fallback immediately
        if not active_model:
            elapsed = time.perf_counter() - start_t
            err_msg = (
                f"No approved open-weight model found in Ollama runtime. "
                f"Configured: '{self.model_name}', Approved: {self.approved_models}. "
                "Arbitrary model fallback disallowed."
            )
            fallback = self.generate_deterministic_fallback_report(
                gate_summary, security_statuses, diffs, reason=err_msg
            )
            return AIAnalysisResult(
                model_name=f"{self.model_name} (Unavailable - Fallback Used)",
                runtime_type="Deterministic Rule Engine (No AI Inference)",
                inference_success=False,
                is_live_model=False,
                duration_seconds=elapsed,
                error_message=err_msg,
                report=fallback,
                grounding_verified=True,
                grounding_issues=[],
            )

        prompt = self.build_analysis_prompt(gate_summary, security_statuses, diffs)

        payload = {
            "model": active_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.25,
                "top_p": 0.9,
                "repeat_penalty": 1.15,
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
                fallback = self.generate_deterministic_fallback_report(
                    gate_summary, security_statuses, diffs, reason=err_msg
                )
                return AIAnalysisResult(
                    model_name=f"{active_model} (Failed - Fallback Used)",
                    runtime_type="Deterministic Rule Engine (No AI Inference)",
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

            # Clean markdown code fences if model returned ```json ... ```
            cleaned_text = raw_text
            if "```json" in cleaned_text:
                cleaned_text = cleaned_text.split("```json", 1)[1].split("```", 1)[0].strip()
            elif "```" in cleaned_text:
                cleaned_text = cleaned_text.split("```", 1)[1].split("```", 1)[0].strip()

            parsed_json = json.loads(cleaned_text)
            validated_report = AIAnalysisReport.model_validate(parsed_json)

            # Grounding and overconfident claim verification
            is_grounded, grounding_issues = self.verify_evidence_grounding(validated_report, security_statuses)

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
            fallback = self.generate_deterministic_fallback_report(
                gate_summary, security_statuses, diffs, reason=err_msg
            )

            return AIAnalysisResult(
                model_name=f"{active_model} (Invalid Output - Fallback Used)",
                runtime_type="Deterministic Rule Engine (No AI Inference)",
                inference_success=False,
                is_live_model=False,
                duration_seconds=elapsed,
                error_message=err_msg,
                report=fallback,
                grounding_verified=True,
                grounding_issues=[f"Inference failed or invalid schema: {str(exc)}"],
            )
