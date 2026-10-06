"""
backend_interface.py

*** INTEGRATION SEAM between Person A (data/risk engine) and Person B (frontend) ***

Person A should replace the body of `analyze_all()` with a call into the real
pipeline (parser -> vuln_matcher -> license_checker -> maintenance -> scorer),
but the function MUST keep returning a pandas DataFrame with exactly the
columns listed in RESULT_SCHEMA below. As long as that contract holds, nothing
in app.py, report.py, or the templates needs to change.

Until the real engine is ready, this file generates DETERMINISTIC mock data
derived from the uploaded files, so the dashboard/report can be built and
tested end-to-end without waiting on Person A.
"""

import hashlib
import json
from pathlib import Path

import pandas as pd

# ---------------------------------------------------------------------------
# CONTRACT: analyze_all() must return a DataFrame with exactly these columns.
# Keep this list in sync with Person A — this is the only thing you both
# need to agree on.
# ---------------------------------------------------------------------------
RESULT_SCHEMA = [
    "app_id",
    "app_name",
    "library",
    "version",
    "license",
    "last_updated",
    "cve_ids",         # comma-separated string, e.g. "CVE-2021-44228,CVE-2022-0001"
    "cvss_score",       # float, 0.0 if none
    "risk_type",        # "clean" | "vulnerability" | "license_conflict" |
                        # "unmaintained" | "transitive_vulnerability"
    "severity",         # "None" | "Low" | "Medium" | "High" | "Critical"
    "risk_score",       # float/int, composite score (higher = riskier)
    "flags",            # comma-separated human-readable flags
    "recommendation",   # short remediation text
]

SEVERITY_LEVELS = ["None", "Low", "Medium", "High", "Critical"]
RISK_TYPES = ["clean", "vulnerability", "license_conflict", "unmaintained", "transitive_vulnerability"]


def _deterministic_score(seed: str, low: int, high: int) -> int:
    """Turn a string into a stable pseudo-random int in [low, high] (no randomness across runs)."""
    digest = hashlib.md5(seed.encode()).hexdigest()
    value = int(digest[:8], 16)
    return low + (value % (high - low + 1))


def _mock_row(app_id: str, app_name: str, library: str, version: str) -> dict:
    seed = f"{app_id}:{library}:{version}"
    risk_type = RISK_TYPES[_deterministic_score(seed + "type", 0, len(RISK_TYPES) - 1)]

    if risk_type == "clean":
        severity = "None"
        cvss = 0.0
        cve_ids = ""
        risk_score = _deterministic_score(seed + "score", 0, 10)
        flags = ""
        recommendation = "No action needed."
    else:
        severity = SEVERITY_LEVELS[_deterministic_score(seed + "sev", 1, 4)]
        cvss = round(_deterministic_score(seed + "cvss", 30, 98) / 10, 1)
        cve_ids = f"CVE-2023-{_deterministic_score(seed + 'cve', 1000, 9999)}"
        risk_score = _deterministic_score(seed + "score", 40, 95)
        flags = risk_type.replace("_", " ").title()
        recommendation = {
            "vulnerability": "Upgrade to the patched version immediately.",
            "license_conflict": "Review license terms with legal/compliance.",
            "unmaintained": "Evaluate for replacement or fork maintenance.",
            "transitive_vulnerability": "Trace the dependency chain and upgrade the root cause library.",
        }.get(risk_type, "Review manually.")

    return {
        "app_id": app_id,
        "app_name": app_name,
        "library": library,
        "version": version,
        "license": ["MIT", "Apache-2.0", "GPL-3.0", "LGPL-2.1", "Unknown"][
            _deterministic_score(seed + "lic", 0, 4)
        ],
        "last_updated": "2022-01-01" if risk_type == "unmaintained" else "2025-06-01",
        "cve_ids": cve_ids,
        "cvss_score": cvss,
        "risk_type": risk_type,
        "severity": severity,
        "risk_score": risk_score,
        "flags": flags,
        "recommendation": recommendation,
    }


def analyze_all(applications_path: Path, dependencies_path: Path) -> pd.DataFrame:
    """
    MOCK IMPLEMENTATION — replace with the real pipeline when Person A is ready.

    Reads the uploaded applications file (JSON) and dependencies file (CSV),
    and returns a risk-scored DataFrame matching RESULT_SCHEMA.

    Person A's real version might look like:

        from parser import load_sboms
        from vuln_matcher import match_vulnerabilities
        from license_checker import check_licenses
        from maintenance import check_maintenance
        from scorer import compute_scores

        apps, deps = load_sboms(applications_path, dependencies_path)
        deps = match_vulnerabilities(deps)
        deps = check_licenses(deps)
        deps = check_maintenance(deps)
        return compute_scores(apps, deps)  # must match RESULT_SCHEMA exactly
    """
    apps_data = json.loads(Path(applications_path).read_text())
    deps_df = pd.read_csv(dependencies_path)

    # Build app_id -> app_name lookup, tolerant of a couple of likely key names.
    app_lookup = {}
    records = apps_data if isinstance(apps_data, list) else apps_data.get("applications", [])
    for a in records:
        app_id = str(a.get("app_id", a.get("id", "")))
        app_lookup[app_id] = a.get("app_name", a.get("name", f"App {app_id}"))

    rows = []
    for _, dep in deps_df.iterrows():
        app_id = str(dep.get("app_id", "unknown"))
        app_name = app_lookup.get(app_id, dep.get("app_name", f"App {app_id}"))
        library = dep.get("library", dep.get("library_name", "unknown-lib"))
        version = str(dep.get("version", "0.0.0"))
        rows.append(_mock_row(app_id, app_name, library, version))

    if not rows:
        # Fallback sample data so the dashboard is never empty during development.
        rows = [_mock_row("app-1", "Sample App", f"lib-{i}", "1.0.0") for i in range(20)]

    df = pd.DataFrame(rows)
    return df[RESULT_SCHEMA]
