"""Dependency parser for LockSentry AI.

Supports:
1. Python requirements.txt (pins, specifiers, markers, flags, comments)
2. npm package-lock.json (v1, v2, v3 formats, scoped packages, dev flags)
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field


class Dependency(BaseModel):
    """Represents a single parsed software dependency."""
    name: str = Field(..., description="Normalized package name")
    version: Optional[str] = Field(None, description="Exact resolved or pinned version if available")
    specifier: Optional[str] = Field(None, description="Raw version constraint or specifier")
    ecosystem: str = Field(..., description="Package ecosystem: PyPI or npm")
    is_direct: bool = Field(True, description="True if top-level dependency, False if transitive")
    is_dev: bool = Field(False, description="True if identified as a development dependency")
    is_exact: bool = Field(False, description="True if version is an exact pin rather than a range")
    raw_line: str = Field("", description="Original line or entry string from source")
    source_file: str = Field("", description="Filename or label where dependency was parsed")
    parse_warning: Optional[str] = Field(None, description="Warning if parsing encountered ambiguity")


class DependencyDiff(BaseModel):
    """Represents a comparative difference between existing and proposed dependency versions."""
    name: str
    ecosystem: str
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    change_type: str = Field(..., description="ADDED, REMOVED, UPDATED, DOWNGRADED, or UNCHANGED")
    is_direct: bool = True
    is_dev: bool = False
    is_major_bump: bool = False
    version_comparison_warning: Optional[str] = None


# Regex for parsing Python requirement specifiers
_REQ_NAME_RE = re.compile(r"^([a-zA-Z0-9_\-\.]+)")
_REQ_EXACT_RE = re.compile(r"==\s*([a-zA-Z0-9_\-\.\+]+)")
_REQ_SPEC_RE = re.compile(r"([<>=!~]=?[\s*a-zA-Z0-9_\-\.\+*, ]+)")


def parse_requirements_txt(content: str, filename: str = "requirements.txt") -> List[Dependency]:
    """Parse Python requirements.txt contents into Dependency objects."""
    dependencies: List[Dependency] = []
    lines = content.splitlines()

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Skip CLI option flags such as -r, -i, --extra-index-url, -f, -e
        if line.startswith(("-", "--")):
            continue

        # Strip inline comments (e.g., requests==2.25.0 # security patch)
        # Be careful not to split URLs with #frag
        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        # Handle environment markers (e.g., requests==2.25.0 ; python_version < '3.8')
        marker_part = None
        if ";" in line:
            parts = line.split(";", 1)
            line = parts[0].strip()
            marker_part = parts[1].strip()

        # Check for direct VCS or file URLs (e.g., git+https://... or ./pkg)
        if line.startswith(("git+", "http://", "https://", "svn+", "hg+", "file:", ".")):
            dependencies.append(
                Dependency(
                    name=line.split("/")[-1].split("@")[0].split(".git")[0] or f"vcs-package-{idx}",
                    version=None,
                    specifier=line,
                    ecosystem="PyPI",
                    is_direct=True,
                    is_exact=False,
                    raw_line=raw_line,
                    source_file=filename,
                    parse_warning="Direct URL/VCS dependency detected. Version cannot be pinned reliably.",
                )
            )
            continue

        # Match package name
        name_match = _REQ_NAME_RE.match(line)
        if not name_match:
            dependencies.append(
                Dependency(
                    name=f"unparsed-line-{idx}",
                    version=None,
                    specifier=None,
                    ecosystem="PyPI",
                    is_direct=True,
                    is_exact=False,
                    raw_line=raw_line,
                    source_file=filename,
                    parse_warning=f"Malformed requirements line could not be parsed: {line}",
                )
            )
            continue

        pkg_name = name_match.group(1).strip()
        remainder = line[name_match.end():].strip()

        # Check for extras (e.g. requests[security]==2.25.0)
        if remainder.startswith("["):
            extra_close = remainder.find("]")
            if extra_close != -1:
                remainder = remainder[extra_close + 1:].strip()

        exact_match = _REQ_EXACT_RE.search(remainder)
        if exact_match:
            exact_ver = exact_match.group(1).strip()
            dependencies.append(
                Dependency(
                    name=pkg_name,
                    version=exact_ver,
                    specifier=f"=={exact_ver}",
                    ecosystem="PyPI",
                    is_direct=True,
                    is_exact=True,
                    raw_line=raw_line,
                    source_file=filename,
                    parse_warning=f"Marker applied: {marker_part}" if marker_part else None,
                )
            )
        else:
            # Range or unpinned specifier
            spec_match = _REQ_SPEC_RE.search(remainder)
            spec_str = spec_match.group(1).strip() if spec_match else (remainder or "*")
            dependencies.append(
                Dependency(
                    name=pkg_name,
                    version=None,
                    specifier=spec_str,
                    ecosystem="PyPI",
                    is_direct=True,
                    is_exact=False,
                    raw_line=raw_line,
                    source_file=filename,
                    parse_warning="Non-pinned dependency constraint. Vulnerability matching requires exact version.",
                )
            )

    return dependencies


def parse_package_lock_json(content: str, filename: str = "package-lock.json") -> List[Dependency]:
    """Parse npm package-lock.json (supporting v1, v2, and v3) into Dependency objects."""
    dependencies: List[Dependency] = []
    try:
        data = json.loads(content)
    except Exception as exc:
        return [
            Dependency(
                name="invalid-json",
                version=None,
                specifier=None,
                ecosystem="npm",
                is_direct=False,
                is_exact=False,
                raw_line=content[:100],
                source_file=filename,
                parse_warning=f"Failed to parse JSON: {str(exc)}",
            )
        ]

    lockfile_version = data.get("lockfileVersion", 1)

    # Strategy 1: v2 / v3 format uses "packages" object
    if "packages" in data and isinstance(data["packages"], dict):
        packages_dict: Dict = data["packages"]
        for pkg_path, pkg_info in packages_dict.items():
            if not pkg_path:  # Root package is represented as empty string ""
                continue
            if not isinstance(pkg_info, dict):
                continue

            # Strip node_modules prefix, e.g. "node_modules/@babel/core" -> "@babel/core"
            if "node_modules/" in pkg_path:
                clean_name = pkg_path.split("node_modules/")[-1]
            else:
                clean_name = pkg_path

            version = pkg_info.get("version")
            is_dev = bool(pkg_info.get("dev", False))
            # Direct dependencies are typically top-level in node_modules without nested paths
            is_direct = pkg_path.count("node_modules/") == 1

            dependencies.append(
                Dependency(
                    name=clean_name,
                    version=str(version) if version else None,
                    specifier=str(version) if version else None,
                    ecosystem="npm",
                    is_direct=is_direct,
                    is_dev=is_dev,
                    is_exact=bool(version),
                    raw_line=f"{clean_name}@{version}",
                    source_file=filename,
                    parse_warning=None if version else "Missing resolved version in package-lock entry",
                )
            )

    # Strategy 2: v1 format or v2 fallback uses "dependencies" nested tree
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        def _walk_v1_deps(deps_dict: Dict, is_direct: bool = True):
            for pkg_name, pkg_info in deps_dict.items():
                if not isinstance(pkg_info, dict):
                    continue
                version = pkg_info.get("version")
                is_dev = bool(pkg_info.get("dev", False))
                dependencies.append(
                    Dependency(
                        name=pkg_name,
                        version=str(version) if version else None,
                        specifier=str(version) if version else None,
                        ecosystem="npm",
                        is_direct=is_direct,
                        is_dev=is_dev,
                        is_exact=bool(version),
                        raw_line=f"{pkg_name}@{version}",
                        source_file=filename,
                        parse_warning=None if version else "Missing resolved version in dependencies entry",
                    )
                )
                if "dependencies" in pkg_info and isinstance(pkg_info["dependencies"], dict):
                    _walk_v1_deps(pkg_info["dependencies"], is_direct=False)

        _walk_v1_deps(data["dependencies"], is_direct=True)

    else:
        dependencies.append(
            Dependency(
                name="empty-or-unsupported-lockfile",
                version=None,
                specifier=None,
                ecosystem="npm",
                is_direct=False,
                is_exact=False,
                raw_line="",
                source_file=filename,
                parse_warning=f"Unrecognized package-lock.json schema (lockfileVersion: {lockfile_version})",
            )
        )

    return dependencies


def parse_manifest_file(content: str, filename: str) -> List[Dependency]:
    """Auto-detect manifest format by filename extension and parse dependencies."""
    lower_name = filename.lower()
    if lower_name.endswith(".json") or "package-lock" in lower_name:
        return parse_package_lock_json(content, filename=filename)
    elif lower_name.endswith(".txt") or "requirements" in lower_name:
        return parse_requirements_txt(content, filename=filename)
    else:
        # Fallback inspection: check if starts with '{' (JSON) or line-based
        stripped = content.strip()
        if stripped.startswith("{"):
            return parse_package_lock_json(content, filename=filename)
        return parse_requirements_txt(content, filename=filename)


def compare_dependencies(
    old_deps: List[Dependency],
    new_deps: List[Dependency]
) -> List[DependencyDiff]:
    """Compute structural diffs between old and new dependency lists."""
    old_map: Dict[Tuple[str, str], Dependency] = {
        (d.ecosystem.lower(), d.name.lower()): d for d in old_deps
    }
    new_map: Dict[Tuple[str, str], Dependency] = {
        (d.ecosystem.lower(), d.name.lower()): d for d in new_deps
    }

    all_keys = set(old_map.keys()).union(new_map.keys())
    diffs: List[DependencyDiff] = []

    for key in sorted(all_keys):
        old_dep = old_map.get(key)
        new_dep = new_map.get(key)

        eco = new_dep.ecosystem if new_dep else (old_dep.ecosystem if old_dep else "unknown")
        name = new_dep.name if new_dep else (old_dep.name if old_dep else "unknown")
        is_direct = new_dep.is_direct if new_dep else (old_dep.is_direct if old_dep else True)
        is_dev = new_dep.is_dev if new_dep else (old_dep.is_dev if old_dep else False)

        old_ver = old_dep.version if old_dep else None
        new_ver = new_dep.version if new_dep else None

        if old_dep is None and new_dep is not None:
            diffs.append(
                DependencyDiff(
                    name=name,
                    ecosystem=eco,
                    old_version=None,
                    new_version=new_ver,
                    change_type="ADDED",
                    is_direct=is_direct,
                    is_dev=is_dev,
                    is_major_bump=False,
                )
            )
        elif old_dep is not None and new_dep is None:
            diffs.append(
                DependencyDiff(
                    name=name,
                    ecosystem=eco,
                    old_version=old_ver,
                    new_version=None,
                    change_type="REMOVED",
                    is_direct=is_direct,
                    is_dev=is_dev,
                    is_major_bump=False,
                )
            )
        else:
            # Both exist: check version comparison
            if old_ver == new_ver:
                diffs.append(
                    DependencyDiff(
                        name=name,
                        ecosystem=eco,
                        old_version=old_ver,
                        new_version=new_ver,
                        change_type="UNCHANGED",
                        is_direct=is_direct,
                        is_dev=is_dev,
                        is_major_bump=False,
                    )
                )
            else:
                # Attempt semver comparison using packaging.version
                change_type = "UPDATED"
                is_major = False
                warn = None
                if old_ver and new_ver:
                    try:
                        v_old = Version(old_ver)
                        v_new = Version(new_ver)
                        if v_new < v_old:
                            change_type = "DOWNGRADED"
                        elif v_new > v_old:
                            change_type = "UPDATED"
                            if v_new.major > v_old.major:
                                is_major = True
                    except InvalidVersion:
                        warn = f"Non-standard version format: '{old_ver}' -> '{new_ver}'"
                        change_type = "UPDATED"
                elif not old_ver and new_ver:
                    change_type = "UPDATED"
                elif old_ver and not new_ver:
                    change_type = "UPDATED"

                diffs.append(
                    DependencyDiff(
                        name=name,
                        ecosystem=eco,
                        old_version=old_ver,
                        new_version=new_ver,
                        change_type=change_type,
                        is_direct=is_direct,
                        is_dev=is_dev,
                        is_major_bump=is_major,
                        version_comparison_warning=warn,
                    )
                )

    return diffs
