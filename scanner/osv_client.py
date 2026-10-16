"""OSV.dev client for LockSentry AI.

Interfaces with the official Google OSV API:
- https://api.osv.dev/v1/query
- https://api.osv.dev/v1/querybatch

Preserves verified vulnerability evidence, affected version ranges, documented fixed versions,
and source advisory references without fabrication.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field
import requests

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
DEFAULT_TIMEOUT_SECONDS = 10.0


class VulnerabilityEvidence(BaseModel):
    """Verified vulnerability record from OSV."""
    id: str = Field(..., description="Primary advisory ID (e.g. GHSA-xxx, PYSEC-xxx, OSV-xxx)")
    aliases: List[str] = Field(default_factory=list, description="Associated CVEs or tracking IDs")
    summary: str = Field("", description="One-line advisory summary")
    details: str = Field("", description="Detailed vulnerability description")
    severity_level: str = Field("UNKNOWN", description="CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN")
    cvss_score: Optional[float] = Field(None, description="Numeric CVSS score if present in advisory")
    affected_ranges: List[str] = Field(default_factory=list, description="Human-readable affected ranges")
    fixed_versions: List[str] = Field(default_factory=list, description="Documented fixed versions")
    references: List[str] = Field(default_factory=list, description="Advisory URLs and source references")
    database_specific: Dict[str, Any] = Field(default_factory=dict, description="Database-specific metadata")


class PackageSecurityStatus(BaseModel):
    """Aggregated security posture and evidence for a specific dependency."""
    package_name: str
    ecosystem: str
    version: Optional[str] = None
    is_pinned: bool = True
    status: str = Field(
        ...,
        description="CONFIRMED_VULNERABLE, NO_KNOWN_ADVISORY, AMBIGUOUS_UNPINNED, INSUFFICIENT_DATA, or QUERY_ERROR"
    )
    vulnerabilities: List[VulnerabilityEvidence] = Field(default_factory=list)
    recommended_fixed_version: Optional[str] = None
    all_fixed_versions: List[str] = Field(default_factory=list)
    limitations_and_ambiguity: List[str] = Field(default_factory=list)
    query_duration_ms: float = 0.0


def _parse_severity(vuln_dict: Dict[str, Any]) -> tuple[str, Optional[float]]:
    """Extract severity category and CVSS score from OSV record."""
    # Check OSV severity array
    severities = vuln_dict.get("severity", [])
    cvss_score = None
    level = "UNKNOWN"

    for s in severities:
        score_str = s.get("score")
        if score_str and isinstance(score_str, str) and score_str.startswith("CVSS:"):
            # CVSS vector string; check database_specific for calculated numeric score
            pass

    db_specific = vuln_dict.get("database_specific", {})
    if isinstance(db_specific, dict):
        raw_sev = db_specific.get("severity")
        if raw_sev and isinstance(raw_sev, str):
            level = raw_sev.upper()
        raw_score = db_specific.get("cvss_score") or db_specific.get("score")
        if raw_score:
            try:
                cvss_score = float(raw_score)
            except (ValueError, TypeError):
                pass

    # Fallback to GitHub / ecosystem severity strings in details
    if level == "UNKNOWN":
        text_to_check = (vuln_dict.get("summary", "") + " " + vuln_dict.get("details", "")).lower()
        if "critical severity" in text_to_check or "severity: critical" in text_to_check:
            level = "CRITICAL"
        elif "high severity" in text_to_check or "severity: high" in text_to_check:
            level = "HIGH"
        elif "medium severity" in text_to_check or "severity: medium" in text_to_check:
            level = "MEDIUM"
        elif "low severity" in text_to_check or "severity: low" in text_to_check:
            level = "LOW"

    return level, cvss_score


def _extract_affected_ranges_and_fixes(vuln_dict: Dict[str, Any], pkg_name: str) -> tuple[List[str], List[str]]:
    """Extract affected version boundaries and fixed versions from OSV record."""
    ranges_summary: List[str] = []
    fixed_versions: List[str] = []

    for affected in vuln_dict.get("affected", []):
        aff_pkg = affected.get("package", {}).get("name", "").lower()
        # Ensure we only extract fixes relevant to this package
        if aff_pkg and aff_pkg != pkg_name.lower():
            continue

        for r in affected.get("ranges", []):
            range_type = r.get("type", "ECOSYSTEM")
            events = r.get("events", [])
            intro = None
            fixed = None
            for event in events:
                if "introduced" in event:
                    intro = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
                    if fixed not in fixed_versions:
                        fixed_versions.append(fixed)

            range_desc = f"{range_type}: introduced {intro or '0'}"
            if fixed:
                range_desc += f", fixed {fixed}"
            ranges_summary.append(range_desc)

    return ranges_summary, fixed_versions


def _find_recommended_fix(current_ver: Optional[str], all_fixed: List[str]) -> Optional[str]:
    """Determine the safest recommended upgrade version from documented fixed versions."""
    if not all_fixed:
        return None
    if not current_ver:
        return all_fixed[-1]

    valid_fixed_versions: List[Version] = []
    current_parsed = None
    try:
        current_parsed = Version(current_ver)
    except InvalidVersion:
        current_parsed = None

    if current_parsed:
        for fv in all_fixed:
            try:
                v = Version(fv)
                if v > current_parsed:
                    valid_fixed_versions.append(v)
            except InvalidVersion:
                continue

        if valid_fixed_versions:
            # Recommend the lowest version that fixes the issue to minimize breaking change risk
            valid_fixed_versions.sort()
            return str(valid_fixed_versions[0])

    # Fallback to string sort or latest
    return all_fixed[-1]


class OSVClient:
    """Client for querying OSV vulnerability database with batching and error handling."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT_SECONDS, session: Optional[requests.Session] = None):
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "LockSentry-AI/0.1.0 (Dependency Security Gate)",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def query_package(self, name: str, ecosystem: str, version: Optional[str] = None) -> PackageSecurityStatus:
        """Query OSV for a single package and version."""
        start_t = time.perf_counter()
        is_pinned = bool(version)
        query_payload: Dict[str, Any] = {
            "package": {
                "name": name,
                "ecosystem": ecosystem
            }
        }
        if version:
            query_payload["version"] = version

        limitations: List[str] = []

        try:
            resp = self.session.post(OSV_QUERY_URL, json=query_payload, timeout=self.timeout)
            duration_ms = (time.perf_counter() - start_t) * 1000.0

            if resp.status_code == 404:
                return PackageSecurityStatus(
                    package_name=name,
                    ecosystem=ecosystem,
                    version=version,
                    is_pinned=is_pinned,
                    status="NO_KNOWN_ADVISORY",
                    vulnerabilities=[],
                    limitations_and_ambiguity=["Package not found or no advisories exist in OSV database."],
                    query_duration_ms=duration_ms,
                )

            if resp.status_code != 200:
                return PackageSecurityStatus(
                    package_name=name,
                    ecosystem=ecosystem,
                    version=version,
                    is_pinned=is_pinned,
                    status="QUERY_ERROR",
                    limitations_and_ambiguity=[f"OSV returned HTTP {resp.status_code}: {resp.text[:200]}"],
                    query_duration_ms=duration_ms,
                )

            data = resp.json()
            raw_vulns = data.get("vulns", [])

        except requests.exceptions.Timeout:
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            return PackageSecurityStatus(
                package_name=name,
                ecosystem=ecosystem,
                version=version,
                is_pinned=is_pinned,
                status="QUERY_ERROR",
                limitations_and_ambiguity=[f"OSV request timed out after {self.timeout}s. Network safety unverified."],
                query_duration_ms=duration_ms,
            )
        except requests.exceptions.RequestException as exc:
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            return PackageSecurityStatus(
                package_name=name,
                ecosystem=ecosystem,
                version=version,
                is_pinned=is_pinned,
                status="QUERY_ERROR",
                limitations_and_ambiguity=[f"OSV connection error: {str(exc)}. Network safety unverified."],
                query_duration_ms=duration_ms,
            )

        # Parse extracted vulnerabilities
        vulnerabilities: List[VulnerabilityEvidence] = []
        all_fixed: List[str] = []

        for v in raw_vulns:
            vid = v.get("id", "UNKNOWN-ID")
            aliases = v.get("aliases", [])
            summary = v.get("summary", "")
            details = v.get("details", "")
            sev_level, cvss = _parse_severity(v)
            aff_ranges, fixes = _extract_affected_ranges_and_fixes(v, name)

            for fix in fixes:
                if fix not in all_fixed:
                    all_fixed.append(fix)

            refs = [ref.get("url") for ref in v.get("references", []) if ref.get("url")]

            vulnerabilities.append(
                VulnerabilityEvidence(
                    id=vid,
                    aliases=aliases,
                    summary=summary,
                    details=details,
                    severity_level=sev_level,
                    cvss_score=cvss,
                    affected_ranges=aff_ranges,
                    fixed_versions=fixes,
                    references=refs,
                    database_specific=v.get("database_specific", {}),
                )
            )

        # Determine definitive package status
        if not is_pinned:
            if vulnerabilities:
                status = "AMBIGUOUS_UNPINNED"
                limitations.append(
                    f"Dependency is unpinned. OSV reports {len(vulnerabilities)} known advisories for '{name}', "
                    "but exact affected status cannot be resolved without a locked version."
                )
            else:
                status = "INSUFFICIENT_DATA"
                limitations.append(
                    "Dependency is unpinned with no exact version specified. Safety cannot be verified."
                )
        else:
            if vulnerabilities:
                status = "CONFIRMED_VULNERABLE"
            else:
                status = "NO_KNOWN_ADVISORY"
                limitations.append(
                    "No known advisory found in OSV. Note: Absence of advisories in OSV does not guarantee zero vulnerabilities."
                )

        rec_fix = _find_recommended_fix(version, all_fixed) if vulnerabilities else None

        return PackageSecurityStatus(
            package_name=name,
            ecosystem=ecosystem,
            version=version,
            is_pinned=is_pinned,
            status=status,
            vulnerabilities=vulnerabilities,
            recommended_fixed_version=rec_fix,
            all_fixed_versions=all_fixed,
            limitations_and_ambiguity=limitations,
            query_duration_ms=duration_ms,
        )

    def query_batch(
        self,
        queries: List[tuple[str, str, Optional[str]]]
    ) -> List[PackageSecurityStatus]:
        """Query OSV in batch where possible, falling back to individual queries for unpinned items."""
        if not queries:
            return []

        # OSV batch query requires version for accurate matching
        # Separate pinned vs unpinned queries
        results: Dict[tuple[str, str, Optional[str]], PackageSecurityStatus] = {}
        pinned_queries: List[tuple[str, str, str]] = []
        unpinned_queries: List[tuple[str, str, Optional[str]]] = []

        for name, eco, ver in queries:
            if ver:
                pinned_queries.append((name, eco, ver))
            else:
                unpinned_queries.append((name, eco, ver))

        # Run unpinned queries individually
        for name, eco, ver in unpinned_queries:
            results[(name, eco, ver)] = self.query_package(name, eco, ver)

        if not pinned_queries:
            return [results[q] for q in queries]

        # Execute batch query for pinned dependencies
        # OSV querybatch accepts max 1000 items per request
        batch_payload = {
            "queries": [
                {"package": {"name": name, "ecosystem": eco}, "version": ver}
                for name, eco, ver in pinned_queries
            ]
        }

        start_t = time.perf_counter()
        try:
            resp = self.session.post(OSV_BATCH_URL, json=batch_payload, timeout=self.timeout)
            batch_duration = (time.perf_counter() - start_t) * 1000.0

            if resp.status_code == 200:
                batch_results = resp.json().get("results", [])
                for (name, eco, ver), res_item in zip(pinned_queries, batch_results):
                    raw_vulns = res_item.get("vulns", [])
                    vulns_list: List[VulnerabilityEvidence] = []
                    all_fixed: List[str] = []

                    for v in raw_vulns:
                        vid = v.get("id", "UNKNOWN-ID")
                        aliases = v.get("aliases", [])
                        summary = v.get("summary", "")
                        details = v.get("details", "")
                        sev_level, cvss = _parse_severity(v)
                        aff_ranges, fixes = _extract_affected_ranges_and_fixes(v, name)
                        for fix in fixes:
                            if fix not in all_fixed:
                                all_fixed.append(fix)
                        refs = [ref.get("url") for ref in v.get("references", []) if ref.get("url")]

                        vulns_list.append(
                            VulnerabilityEvidence(
                                id=vid,
                                aliases=aliases,
                                summary=summary,
                                details=details,
                                severity_level=sev_level,
                                cvss_score=cvss,
                                affected_ranges=aff_ranges,
                                fixed_versions=fixes,
                                references=refs,
                                database_specific=v.get("database_specific", {}),
                            )
                        )

                    limits: List[str] = []
                    if raw_vulns:
                        # OSV querybatch returns minimal [id, modified].
                        # Fetch full vulnerability records for rich evidence and fixed version extraction.
                        detailed_status = self.query_package(name, eco, ver)
                        results[(name, eco, ver)] = detailed_status
                    else:
                        status = "NO_KNOWN_ADVISORY"
                        limits.append("No known matching advisory found in OSV database.")
                        results[(name, eco, ver)] = PackageSecurityStatus(
                            package_name=name,
                            ecosystem=eco,
                            version=ver,
                            is_pinned=True,
                            status=status,
                            vulnerabilities=[],
                            recommended_fixed_version=None,
                            all_fixed_versions=[],
                            limitations_and_ambiguity=limits,
                            query_duration_ms=batch_duration / max(len(pinned_queries), 1),
                        )
            else:
                # If batch query fails, fallback to sequential
                logger.warning(f"OSV batch query returned HTTP {resp.status_code}, falling back to single queries.")
                for name, eco, ver in pinned_queries:
                    results[(name, eco, ver)] = self.query_package(name, eco, ver)

        except requests.exceptions.RequestException as exc:
            logger.warning(f"OSV batch query failed ({str(exc)}), falling back to individual queries.")
            for name, eco, ver in pinned_queries:
                results[(name, eco, ver)] = self.query_package(name, eco, ver)

        return [results[q] for q in queries]
