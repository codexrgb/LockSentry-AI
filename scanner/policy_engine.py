"""Deterministic security policy engine for LockSentry AI.

Evaluates dependency changes strictly against configurable deterministic security rules.
Outcomes:
- PASS: All dependencies satisfy security conditions with documented evidence.
- BLOCK: Confirmed policy violation (e.g. known vulnerability, downgrade).
- REVIEW: Ambiguity, unpinned versions, major breaking bumps, or retrieval failures.

CRITICAL GUARANTEE:
AI inference NEVER overrides deterministic policy decisions.
Failed AI inference NEVER skips security policy evaluations.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from scanner.dependency_parser import DependencyDiff
from scanner.osv_client import PackageSecurityStatus, VulnerabilityEvidence


class PolicyRuleConfig(BaseModel):
    """Configurable thresholds for the deterministic policy engine."""
    block_on_critical: bool = True
    block_on_high: bool = True
    block_on_medium: bool = True
    block_on_low: bool = False
    block_on_downgrade: bool = True
    block_on_any_vulnerability: bool = True
    review_on_unpinned: bool = True
    review_on_osv_error: bool = True
    review_on_major_bump: bool = True
    cvss_block_threshold: float = 7.0


class PolicyCheckResult(BaseModel):
    """Result of policy evaluation for an individual dependency."""
    package_name: str
    ecosystem: str
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    change_type: str = "UNCHANGED"
    outcome: str = Field(..., description="PASS, BLOCK, or REVIEW")
    primary_reason: str
    policy_violations: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    vulnerabilities_found: int = 0
    highest_severity: str = "NONE"
    max_cvss: Optional[float] = None
    recommended_action: str = ""
    evidence_summary: str = ""


class GateSummary(BaseModel):
    """Aggregate decision across an entire manifest or diff."""
    overall_outcome: str = Field(..., description="PASS, BLOCK, or REVIEW")
    total_packages_evaluated: int = 0
    passed_count: int = 0
    blocked_count: int = 0
    review_count: int = 0
    total_vulnerabilities: int = 0
    block_reasons: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    items: List[PolicyCheckResult] = Field(default_factory=list)


class DeterministicPolicyEngine:
    """Engine that enforces strict security rules against package security status and diffs."""

    def __init__(self, config: Optional[PolicyRuleConfig] = None):
        self.config = config or PolicyRuleConfig()

    def evaluate_item(
        self,
        security_status: PackageSecurityStatus,
        diff: Optional[DependencyDiff] = None
    ) -> PolicyCheckResult:
        """Evaluate a single package status and optional diff against deterministic rules."""
        violations: List[str] = []
        review_notes: List[str] = []
        change_type = diff.change_type if diff else ("ADDED" if security_status.version else "UNCHANGED")
        old_ver = diff.old_version if diff else None
        new_ver = diff.new_version if diff else security_status.version

        # 1. Check for retrieval errors
        if security_status.status == "QUERY_ERROR":
            if self.config.review_on_osv_error:
                review_notes.append(
                    f"OSV intelligence lookup failed: {'; '.join(security_status.limitations_and_ambiguity)}. "
                    "Security cannot be determined offline."
                )

        # 2. Check for unpinned/ambiguous constraints
        if security_status.status in ("AMBIGUOUS_UNPINNED", "INSUFFICIENT_DATA"):
            if self.config.review_on_unpinned:
                review_notes.append(
                    f"Dependency '{security_status.package_name}' is not pinned to an exact version. "
                    "Dynamic resolution at install time introduces supply-chain risk."
                )

        # 3. Check for version downgrades
        if diff and diff.change_type == "DOWNGRADED" and self.config.block_on_downgrade:
            violations.append(
                f"Version downgrade detected ({old_ver} -> {new_ver}). "
                "Downgrading packages may re-introduce previously patched vulnerabilities."
            )

        # 4. Check for major breaking bumps
        if diff and diff.is_major_bump and self.config.review_on_major_bump:
            review_notes.append(
                f"Major version bump detected ({old_ver} -> {new_ver}). "
                "Potential breaking API changes require verification."
            )

        # 5. Evaluate vulnerabilities and severities (only for confirmed vulnerable versions)
        highest_sev = "NONE"
        max_cvss: Optional[float] = None
        severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1, "NONE": 0}

        if security_status.status == "CONFIRMED_VULNERABLE":
            for vuln in security_status.vulnerabilities:
                s_level = vuln.severity_level.upper()
                if severity_rank.get(s_level, 0) > severity_rank.get(highest_sev, 0):
                    highest_sev = s_level

                if vuln.cvss_score is not None:
                    if max_cvss is None or vuln.cvss_score > max_cvss:
                        max_cvss = vuln.cvss_score

                # Check CVSS threshold
                if vuln.cvss_score is not None and vuln.cvss_score >= self.config.cvss_block_threshold:
                    violations.append(
                        f"Vulnerability {vuln.id} has CVSS score {vuln.cvss_score} exceeding threshold {self.config.cvss_block_threshold}."
                    )

                # Check Severity Level
                if s_level == "CRITICAL" and self.config.block_on_critical:
                    violations.append(f"Critical vulnerability {vuln.id} ({', '.join(vuln.aliases) or 'No CVE alias'}) detected.")
                elif s_level == "HIGH" and self.config.block_on_high:
                    violations.append(f"High severity vulnerability {vuln.id} ({', '.join(vuln.aliases) or 'No CVE alias'}) detected.")
                elif s_level == "MEDIUM" and self.config.block_on_medium:
                    violations.append(f"Medium severity vulnerability {vuln.id} detected.")
                elif s_level == "LOW" and self.config.block_on_low:
                    violations.append(f"Low severity vulnerability {vuln.id} detected.")

            if self.config.block_on_any_vulnerability and not violations and security_status.vulnerabilities:
                violations.append(
                    f"Found {len(security_status.vulnerabilities)} confirmed vulnerability advisories in OSV for version {new_ver}."
                )

        # Determine Outcome
        if violations:
            outcome = "BLOCK"
            primary_reason = violations[0]
            action = f"Reject package change. Upgrade to fixed version {security_status.recommended_fixed_version or 'documented safe release'}."
        elif review_notes:
            outcome = "REVIEW"
            primary_reason = review_notes[0]
            action = "Perform manual supply-chain review or pin exact version in lockfile before approving."
        else:
            outcome = "PASS"
            primary_reason = "No policy violations or known advisories detected in queried database."
            action = "Approve change; dependency meets current deterministic security baseline."

        # Evidence summary
        evidence_text = (
            f"Ecosystem: {security_status.ecosystem} | Version: {new_ver or 'unpinned'} | "
            f"Vulnerabilities: {len(security_status.vulnerabilities)} | Highest Sev: {highest_sev}"
        )
        if security_status.recommended_fixed_version:
            evidence_text += f" | Safe Target: {security_status.recommended_fixed_version}"

        return PolicyCheckResult(
            package_name=security_status.package_name,
            ecosystem=security_status.ecosystem,
            old_version=old_ver,
            new_version=new_ver,
            change_type=change_type,
            outcome=outcome,
            primary_reason=primary_reason,
            policy_violations=violations,
            review_reasons=review_notes,
            vulnerabilities_found=len(security_status.vulnerabilities),
            highest_severity=highest_sev,
            max_cvss=max_cvss,
            recommended_action=action,
            evidence_summary=evidence_text,
        )

    def evaluate_all(
        self,
        security_statuses: List[PackageSecurityStatus],
        diffs: Optional[List[DependencyDiff]] = None
    ) -> GateSummary:
        """Evaluate an entire set of package security statuses and generate a gate decision."""
        diff_map: Dict[tuple[str, str], DependencyDiff] = {}
        if diffs:
            for d in diffs:
                diff_map[(d.ecosystem.lower(), d.name.lower())] = d

        items: List[PolicyCheckResult] = []
        block_reasons: List[str] = []
        review_reasons: List[str] = []
        passed_cnt = 0
        blocked_cnt = 0
        review_cnt = 0
        total_vulns = 0

        for status in security_statuses:
            diff = diff_map.get((status.ecosystem.lower(), status.package_name.lower()))
            res = self.evaluate_item(status, diff)
            items.append(res)
            total_vulns += res.vulnerabilities_found

            if res.outcome == "BLOCK":
                blocked_cnt += 1
                block_reasons.append(f"{res.package_name}@{res.new_version}: {res.primary_reason}")
            elif res.outcome == "REVIEW":
                review_cnt += 1
                review_reasons.append(f"{res.package_name}: {res.primary_reason}")
            else:
                passed_cnt += 1

        if blocked_cnt > 0:
            overall = "BLOCK"
        elif review_cnt > 0:
            overall = "REVIEW"
        else:
            overall = "PASS"

        return GateSummary(
            overall_outcome=overall,
            total_packages_evaluated=len(items),
            passed_count=passed_cnt,
            blocked_count=blocked_cnt,
            review_count=review_cnt,
            total_vulnerabilities=total_vulns,
            block_reasons=block_reasons,
            review_reasons=review_reasons,
            items=items,
        )
