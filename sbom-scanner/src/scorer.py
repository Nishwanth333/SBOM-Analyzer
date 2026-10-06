"""
scorer.py
=========
Purpose
-------
Combine the vulnerability, license, and maintenance penalties for a
single dependency into one configurable Risk Score, bucket it into a
LOW/MEDIUM/HIGH/CRITICAL risk level, identify the dominant risk driver
(`risk_type`), and produce a human-readable recommendation and a
compact list of machine-readable flags.

Inputs
------
- vulnerability_penalty: float
- license_penalty: float
- maintenance_penalty: float
- vuln_context: dict with keys {severity, cve_id, patch_available}
- license_context: dict with keys {status, reason}
- maintenance_context: dict with keys {status, age_years}
- weights: RiskWeights - configurable multipliers per component

Outputs
-------
A `ScoreResult` dataclass with:
- risk_score: float
- risk_level: str      ("LOW" | "MEDIUM" | "HIGH" | "CRITICAL")
- risk_type: str        (dominant contributing category)
- recommendation: str
- flags: list[str]

Workflow
--------
1. Apply configurable weights to each penalty component and sum them
   into a raw risk_score.
2. Clip to a sane [0, 100] range for stable downstream reporting.
3. Bucket the score into a risk_level using fixed, documented
   thresholds.
4. Determine risk_type as whichever component contributed the most
   weighted penalty (ties broken vulnerability > license > maintenance,
   since exploitable CVEs are the most acute risk).
5. Build a short list of `flags` (e.g. "CRITICAL_CVE", "GPL_LICENSE",
   "UNMAINTAINED") for quick filtering by the consuming dashboard.
6. Compose a one-line human-readable recommendation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass
class RiskWeights:
    """
    Configurable multipliers applied to each penalty component before
    summing. Defaults to 1.0 (i.e. use the raw penalties as-is), but
    callers can tune these to shift emphasis, e.g. weighting
    vulnerabilities more heavily than license concerns.
    """

    vulnerability: float = 1.0
    license: float = 1.0
    maintenance: float = 1.0


# Risk-level thresholds against the final (weighted, 0-100 clipped) score.
_RISK_LEVEL_THRESHOLDS = (
    (25.0, "LOW"),
    (50.0, "MEDIUM"),
    (75.0, "HIGH"),
    (float("inf"), "CRITICAL"),
)

_MAX_SCORE = 100.0
_MIN_SCORE = 0.0


@dataclass
class ScoreResult:
    """Final combined risk assessment for one dependency row."""

    risk_score: float
    risk_level: str
    risk_type: str
    recommendation: str
    flags: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _bucket_risk_level(score: float) -> str:
    """Map a numeric score onto a LOW/MEDIUM/HIGH/CRITICAL bucket."""
    for threshold, label in _RISK_LEVEL_THRESHOLDS:
        if score <= threshold:
            return label
    return "CRITICAL"  # unreachable given the inf sentinel, kept for safety


def _dominant_risk_type(
    weighted_vuln: float, weighted_license: float, weighted_maintenance: float
) -> str:
    """
    Identify which component drove the score the most. Ties are broken
    in order vulnerability > license > maintenance, reflecting that an
    exploitable CVE is generally the most urgent concern.
    """
    components = [
        ("VULNERABILITY", weighted_vuln),
        ("LICENSE", weighted_license),
        ("MAINTENANCE", weighted_maintenance),
    ]
    max_value = max(value for _, value in components)
    if max_value <= 0:
        return "NONE"
    for name, value in components:
        if value == max_value:
            return name
    return "NONE"  # defensive fallback, not reachable in practice


def _build_flags(
    vuln_context: dict, license_context: dict, maintenance_context: dict
) -> list[str]:
    """Build a compact list of machine-readable flags for dashboard filtering."""
    flags: list[str] = []

    severity = str(vuln_context.get("severity", "NONE")).upper()
    if severity in {"HIGH", "CRITICAL"}:
        flags.append(f"{severity}_CVE")
    if vuln_context.get("cve_id") and vuln_context.get("patch_available") is False:
        flags.append("UNPATCHED_CVE")

    license_status = str(license_context.get("status", "")).upper()
    if license_status == "RESTRICTED":
        flags.append("RESTRICTED_LICENSE")
    elif license_status == "REVIEW":
        flags.append("LICENSE_REVIEW_NEEDED")
    elif license_status == "UNKNOWN":
        flags.append("UNKNOWN_LICENSE")

    if str(maintenance_context.get("status", "")).upper() == "UNMAINTAINED":
        flags.append("UNMAINTAINED")
    elif str(maintenance_context.get("status", "")).upper() == "UNKNOWN":
        flags.append("UNKNOWN_MAINTENANCE_HISTORY")

    return flags


def _build_recommendation(
    risk_level: str,
    vuln_context: dict,
    license_context: dict,
    maintenance_context: dict,
    version_context: dict | None = None,
) -> str:
    """Compose a single human-readable, actionable recommendation string."""
    actions: list[str] = []

    version_context = version_context or {}
    if version_context.get("update_available"):
        current_version = version_context.get("installed_version")
        latest_version = version_context.get("latest_version")
        if latest_version:
            if current_version:
                actions.append(
                    f"upgrade from {current_version} to {latest_version} "
                    "(latest upstream release)"
                )
            else:
                actions.append(
                    f"upgrade to {latest_version} (latest upstream release)"
                )

    cve_id = vuln_context.get("cve_id")
    if cve_id:
        if vuln_context.get("patch_available") is False:
            actions.append(f"upgrade or replace immediately (unpatched {cve_id})")
        else:
            actions.append(f"upgrade to patch {cve_id}")

    license_status = str(license_context.get("status", "")).upper()
    if license_status == "RESTRICTED":
        actions.append("consult legal before shipping (restricted license)")
    elif license_status == "REVIEW":
        actions.append("have legal review the license terms")
    elif license_status == "UNKNOWN":
        actions.append("identify the license")

    if str(maintenance_context.get("status", "")).upper() == "UNMAINTAINED":
        age = maintenance_context.get("age_years")
        age_str = f"{age} years" if age is not None else "an extended period"
        actions.append(f"consider replacing this unmaintained library (stale {age_str})")

    if not actions:
        return "No action required; dependency appears healthy."

    prefix = {
        "LOW": "Low priority:",
        "MEDIUM": "Recommended:",
        "HIGH": "High priority:",
        "CRITICAL": "Urgent action required:",
    }.get(risk_level, "Recommended:")

    return f"{prefix} " + "; ".join(actions) + "."


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def compute_risk_score(
    vulnerability_penalty: float,
    license_penalty: float,
    maintenance_penalty: float,
    vuln_context: dict,
    license_context: dict,
    maintenance_context: dict,
    weights: RiskWeights | None = None,
    version_context: dict | None = None,
) -> ScoreResult:
    """
    Combine component penalties into a final risk score, level, type,
    recommendation, and flag list for one dependency row.
    """
    weights = weights or RiskWeights()

    weighted_vuln = vulnerability_penalty * weights.vulnerability
    weighted_license = license_penalty * weights.license
    weighted_maintenance = maintenance_penalty * weights.maintenance

    raw_score = weighted_vuln + weighted_license + weighted_maintenance
    clipped_score = min(max(raw_score, _MIN_SCORE), _MAX_SCORE)

    risk_level = _bucket_risk_level(clipped_score)
    risk_type = _dominant_risk_type(weighted_vuln, weighted_license, weighted_maintenance)
    flags = _build_flags(vuln_context, license_context, maintenance_context)
    recommendation = _build_recommendation(
        risk_level,
        vuln_context,
        license_context,
        maintenance_context,
        version_context,
    )

    return ScoreResult(
        risk_score=round(clipped_score, 2),
        risk_level=risk_level,
        risk_type=risk_type,
        recommendation=recommendation,
        flags=flags,
    )
