"""
license_checker.py
===================
Purpose
-------
Determine the compatibility/risk status of a dependency's declared
license against the organization's license policy (license_rules.json).

Inputs
------
- license_name: str - the license string from sbom_dependencies.csv
  (e.g. "MIT", "GPL-3.0", "" / "Unknown")
- license_rules: dict - output of parser.load_license_rules()

Outputs
-------
A `LicenseCheckResult` dataclass with:
- status: str      ("ALLOWED", "REVIEW", "RESTRICTED", "UNKNOWN")
- penalty: float
- reason: str

Workflow
--------
1. Normalize the license string (strip whitespace, handle common
   aliases/case differences).
2. Look up the normalized name directly in license_rules.
3. If not found, try a small set of common alias mappings (e.g.
   "Apache 2.0" -> "Apache-2.0").
4. If still not found, fall back to the "Unknown"/"default" rule from
   license_rules.json, or a hardcoded conservative default if the
   config provides none.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Common real-world spelling variants mapped to canonical SPDX-style keys.
# This keeps license_rules.json small while still recognizing the most
# frequent ways licenses show up in the wild.
_ALIASES = {
    "apache 2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "mit license": "MIT",
    "bsd": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "gpl": "GPL-3.0",
    "gplv3": "GPL-3.0",
    "gpl v3": "GPL-3.0",
    "gplv2": "GPL-2.0",
    "gpl v2": "GPL-2.0",
    "lgpl": "LGPL-2.1",
    "lgplv2.1": "LGPL-2.1",
    "lgplv3": "LGPL-3.0",
    "": "Unknown",
    "none": "Unknown",
    "n/a": "Unknown",
}

_FALLBACK_UNKNOWN_RULE = {
    "status": "UNKNOWN",
    "penalty": 10.0,
    "reason": "License could not be identified; treated as legal risk.",
}


@dataclass
class LicenseCheckResult:
    """Outcome of checking one dependency's license against policy."""

    status: str
    penalty: float
    reason: str


def _normalize(license_name: str) -> str:
    """Normalize a raw license string for lookup."""
    return (license_name or "").strip()


def check_license(license_name: str, license_rules: dict) -> LicenseCheckResult:
    """
    Determine compatibility status, penalty, and reason for a single
    dependency's license.

    Never raises: an unrecognized or missing license is a data
    condition to flag (status UNKNOWN), not an engine failure.
    """
    normalized = _normalize(license_name)

    # 1. Direct match (case-sensitive keys as authored in the policy file).
    rule = license_rules.get(normalized)

    # 2. Case-insensitive direct match.
    if rule is None:
        lower_map = {k.lower(): v for k, v in license_rules.items()}
        rule = lower_map.get(normalized.lower())

    # 3. Alias table.
    if rule is None:
        canonical = _ALIASES.get(normalized.lower())
        if canonical:
            rule = license_rules.get(canonical)

    # 4. Explicit "Unknown"/"default" entry in the policy file.
    if rule is None:
        rule = license_rules.get("Unknown") or license_rules.get("default")

    # 5. Hardcoded conservative fallback.
    if rule is None:
        logger.warning(
            "License '%s' not found in policy (including aliases); "
            "applying conservative UNKNOWN fallback.",
            license_name,
        )
        rule = _FALLBACK_UNKNOWN_RULE

    return LicenseCheckResult(
        status=str(rule.get("status", "UNKNOWN")).upper(),
        penalty=float(rule.get("penalty", 10.0)),
        reason=str(rule.get("reason", "No reason provided in policy.")),
    )
