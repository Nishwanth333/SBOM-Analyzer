"""
vuln_matcher.py
===============
Purpose
-------
Match each (library, version) pair from the SBOM against the
vulnerability database and return CVE identifiers, CVSS scores,
severities, patch availability, and a numeric vulnerability penalty.

Inputs
------
- library: str - dependency name
- version: str - dependency version (may be missing/blank)
- vuln_db: list[dict] - output of parser.load_vulnerability_db()

Outputs
-------
A `VulnMatchResult` dataclass with:
- cve_id: str | None            (comma-joined if multiple matches)
- cvss_score: float | None      (max CVSS across matches)
- severity: str                 (highest severity across matches)
- patch_available: bool | None
- vulnerability_penalty: float
- matched_cve_count: int

Workflow
--------
1. Index the vulnerability DB by lowercase library name for O(1) lookup.
2. For a given dependency, collect every DB record for that library.
3. For each candidate record, check whether the dependency's version
   falls inside the record's `version_range` (using
   packaging.specifiers.SpecifierSet). If no range is given, or the
   dependency's version is missing/unparseable, treat it conservatively
   as a potential match (cannot rule it out) but flag it.
4. Aggregate all matching records into one result: worst-case CVSS,
   worst-case severity, all CVE IDs, and whether *any* matched CVE
   still lacks a patch.
5. Convert the aggregated CVSS into a penalty score via a fixed,
   documented mapping (see `_cvss_to_penalty`).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}


@dataclass
class VulnMatchResult:
    """Aggregated vulnerability-match outcome for one dependency row."""

    cve_id: str | None = None
    cvss_score: float | None = None
    severity: str = "NONE"
    patch_available: bool | None = None
    vulnerability_penalty: float = 0.0
    matched_cve_count: int = 0
    matched_cves: list[dict] = field(default_factory=list)


def build_vuln_index(vuln_db: list[dict]) -> dict[str, list[dict]]:
    """Index vulnerability records by lowercase library name."""
    index: dict[str, list[dict]] = {}
    for record in vuln_db:
        key = record["library"].lower()
        index.setdefault(key, []).append(record)
    return index


def _version_in_range(version_str: str, version_range: str | None) -> bool:
    """
    Return True if `version_str` satisfies `version_range`.

    `version_range` follows PEP 440 specifier syntax, e.g. "<2.31.0",
    ">=1.0,<2.0", or an exact pin like "==1.2.3". If `version_range`
    is None, the record applies to all versions (True). If the
    dependency's version string cannot be parsed, we cannot safely
    rule the match out, so we return True and let the caller flag the
    ambiguity via `unknown_version`.
    """
    if not version_range:
        return True
    if not version_str:
        return True  # unknown version -> cannot rule out, be conservative

    try:
        specifier = SpecifierSet(version_range)
    except InvalidSpecifier:
        logger.warning(
            "Invalid version_range '%s' in vulnerability DB; treating as match.",
            version_range,
        )
        return True

    try:
        parsed_version = Version(version_str)
    except InvalidVersion:
        logger.warning("Unparseable dependency version '%s'; treating as match.", version_str)
        return True

    return specifier.contains(parsed_version, prereleases=True)


def _cvss_to_penalty(cvss_score: float) -> float:
    """
    Convert a CVSS 3.x score (0-10) into a risk-scorer penalty (0-40).

    Mapping (documented, configurable):
        0.0        -> 0
        0.1 - 3.9  -> 5   (LOW)
        4.0 - 6.9  -> 15  (MEDIUM)
        7.0 - 8.9  -> 25  (HIGH)
        9.0 - 10.0 -> 40  (CRITICAL)
    """
    if cvss_score <= 0:
        return 0.0
    if cvss_score < 4.0:
        return 5.0
    if cvss_score < 7.0:
        return 15.0
    if cvss_score < 9.0:
        return 25.0
    return 40.0


def match_vulnerabilities(
    library: str,
    version: str,
    vuln_index: dict[str, list[dict]],
) -> VulnMatchResult:
    """
    Match one dependency (library, version) against the indexed
    vulnerability database.

    Handles multiple CVEs per library, missing versions, and unknown
    libraries (returns a clean "no known vulnerability" result rather
    than raising, since an unknown library is not itself an error).
    """
    candidates = vuln_index.get(library.lower(), [])
    if not candidates:
        return VulnMatchResult()  # unknown library -> no data, not a crash

    matches: list[dict] = [
        record
        for record in candidates
        if _version_in_range(version, record.get("version_range"))
    ]

    if not matches:
        return VulnMatchResult()

    worst_cvss = max(m["cvss_score"] for m in matches)
    worst_severity = max(
        (m["severity"] for m in matches),
        key=lambda s: _SEVERITY_ORDER.get(s, 0),
    )
    any_unpatched = any(not m.get("patch_available", False) for m in matches)
    cve_ids = ", ".join(sorted({m["cve_id"] for m in matches}))

    penalty = _cvss_to_penalty(worst_cvss)
    if any_unpatched:
        penalty += 5.0  # extra penalty when no patch exists for at least one CVE

    return VulnMatchResult(
        cve_id=cve_ids,
        cvss_score=worst_cvss,
        severity=worst_severity,
        patch_available=not any_unpatched,
        vulnerability_penalty=round(penalty, 2),
        matched_cve_count=len(matches),
        matched_cves=matches,
    )
