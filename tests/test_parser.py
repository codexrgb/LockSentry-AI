"""Tests for dependency parsing module (requirements.txt and package-lock.json)."""

import pytest
from scanner.dependency_parser import (
    compare_dependencies,
    parse_manifest_file,
    parse_package_lock_json,
    parse_requirements_txt,
)


def test_parse_requirements_pinned():
    content = """
    # Security critical dependencies
    requests==2.25.0
    flask==2.0.1 # inline comment
    urllib3==1.26.4; python_version >= '3.8'
    """
    deps = parse_requirements_txt(content, "requirements.txt")
    assert len(deps) == 3

    req = next(d for d in deps if d.name == "requests")
    assert req.version == "2.25.0"
    assert req.is_exact is True
    assert req.ecosystem == "PyPI"

    flask = next(d for d in deps if d.name == "flask")
    assert flask.version == "2.0.1"
    assert flask.is_exact is True

    u3 = next(d for d in deps if d.name == "urllib3")
    assert u3.version == "1.26.4"
    assert u3.is_exact is True


def test_parse_requirements_unpinned_and_ranges():
    content = """
    requests>=2.20.0
    jinja2~=3.0.0
    black
    """
    deps = parse_requirements_txt(content, "requirements.txt")
    assert len(deps) == 3
    for d in deps:
        assert d.is_exact is False
        assert d.version is None
        assert d.parse_warning is not None


def test_parse_requirements_malformed_and_vcs():
    content = """
    git+https://github.com/psf/requests.git@v2.25.0
    @@invalid_token@@
    """
    deps = parse_requirements_txt(content, "requirements.txt")
    assert len(deps) == 2
    assert deps[0].parse_warning is not None
    assert "vcs" in deps[0].parse_warning.lower() or "url" in deps[0].parse_warning.lower()


def test_parse_package_lock_v2():
    content = """{
      "name": "sample",
      "version": "1.0.0",
      "lockfileVersion": 2,
      "packages": {
        "": { "name": "sample", "version": "1.0.0" },
        "node_modules/lodash": { "version": "4.17.15", "dev": false },
        "node_modules/@babel/core": { "version": "7.15.0", "dev": true }
      }
    }"""
    deps = parse_package_lock_json(content, "package-lock.json")
    assert len(deps) == 2

    lodash = next(d for d in deps if d.name == "lodash")
    assert lodash.version == "4.17.15"
    assert lodash.is_dev is False
    assert lodash.ecosystem == "npm"

    babel = next(d for d in deps if d.name == "@babel/core")
    assert babel.version == "7.15.0"
    assert babel.is_dev is True


def test_parse_package_lock_invalid_json():
    content = "{ corrupted json..."
    deps = parse_package_lock_json(content, "package-lock.json")
    assert len(deps) == 1
    assert deps[0].name == "invalid-json"
    assert "Failed to parse JSON" in (deps[0].parse_warning or "")


def test_compare_dependencies():
    content_old = """
    requests==2.25.0
    urllib3==1.26.4
    legacy-pkg==1.0.0
    """
    content_new = """
    requests==2.33.1
    urllib3==1.25.0
    new-pkg==0.1.0
    """
    old_deps = parse_requirements_txt(content_old)
    new_deps = parse_requirements_txt(content_new)

    diffs = compare_dependencies(old_deps, new_deps)
    diff_map = {d.name: d for d in diffs}

    assert "requests" in diff_map
    assert diff_map["requests"].change_type == "UPDATED"

    assert "urllib3" in diff_map
    assert diff_map["urllib3"].change_type == "DOWNGRADED"

    assert "legacy-pkg" in diff_map
    assert diff_map["legacy-pkg"].change_type == "REMOVED"

    assert "new-pkg" in diff_map
    assert diff_map["new-pkg"].change_type == "ADDED"
