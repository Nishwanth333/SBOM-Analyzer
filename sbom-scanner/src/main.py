"""
main.py
=======
Purpose
-------
Public entry point for the Data & Risk Engine. Orchestrates parser,
vuln_matcher, license_checker, maintenance, and scorer into a single
function, `analyze_all`, that returns one clean, flat pandas DataFrame
ready for a frontend/dashboard to consume directly.

Inputs
------
- applications_path: str | Path
- dependencies_path: str | Path
- vulnerabilities_path: str | Path
- licenses_path: str | Path
- weights: scorer.RiskWeights | None (optional scoring tuning)
- reference_date: datetime.date | None (optional, for reproducible
  maintenance-age calculations; defaults to "today")

Outputs
-------
pandas.DataFrame with one row per (application, dependency) pair and
the columns:

    app_id, application_name, library, version, dependency_type,
    license, license_status, license_penalty,
    last_updated, maintenance_status, maintenance_penalty,
    cve_id, cvss_score, severity, patch_available, vulnerability_penalty,
    risk_score, risk_level, risk_type, recommendation, flags

Workflow
--------
1. Load and validate all four input files via parser.py.
2. Left-join dependencies onto applications by app_id (a dependency
   whose app_id is not in applications.json is kept and flagged via
   application_name = "UNKNOWN_APPLICATION" rather than silently
   dropped).
3. Build the vulnerability index once (O(1) lookups per row) instead
   of re-scanning the vulnerability DB per dependency.
4. For every dependency row, run vuln_matcher, license_checker, and
   maintenance in turn, then combine their outputs via scorer.
5. Assemble everything into one flat DataFrame, sorted by risk_score
   descending so the riskiest dependencies surface first.
"""

from __future__ import annotations

import logging
from datetime import date
from pathlib import Path

import pandas as pd

from . import parser
from . import scorer
from . import vuln_matcher
from . import maintenance
from . import license_checker
from . import github_updater
from . import repository_map

logger = logging.getLogger(__name__)

OUTPUT_COLUMNS = [
    "app_id",
    "application_name",
    "library",
    "version",
    "dependency_type",
    "license",
    "license_status",
    "license_penalty",
    "latest_version",
    "update_available",
    "last_updated",
    "maintenance_status",
    "maintenance_penalty",
    "cve_id",
    "cvss_score",
    "severity",
    "patch_available",
    "vulnerability_penalty",
    "risk_score",
    "risk_level",
    "risk_type",
    "recommendation",
    "flags",
]


def _score_one_row(
    row: pd.Series,
    vuln_index: dict,
    license_rules: dict,
    weights: scorer.RiskWeights,
    reference_date: date | None,
) -> dict:
    """Run the full per-dependency pipeline (vuln + license + maintenance + score)."""
    vuln_result = vuln_matcher.match_vulnerabilities(
        library=row["library"], version=row["version"], vuln_index=vuln_index
    )
    license_result = license_checker.check_license(
        license_name=row["license"], license_rules=license_rules
    )
    last_updated = row["last_updated"]
    existing_date = last_updated
    latest_version = None
    update_available = False
    repository_metadata = None
    for column in ("github_repo", "repository", "repository_url", "source_url"):
        candidate = row.get(column)
        if candidate is not None and not pd.isna(candidate) and str(candidate).strip():
            repository_metadata = str(candidate).strip()
            break

    try:
        repository = repository_map.resolve_repository(
            str(row["library"]), repository_metadata
        )
    except repository_map.InvalidRepositoryReference as exc:
        repository = None
        logger.warning(
            "Invalid repository metadata for %s@%s; using existing SBOM/data date: %s",
            row["library"],
            row["version"],
            exc,
        )

    if repository:
        try:
            release = github_updater.get_latest_release(str(repository).strip())
            if release.published_at:
                last_updated = release.published_at
                logger.info(
                    "Maintenance date source=GitHub repository=%s library=%s version=%s date=%s",
                    repository,
                    row["library"],
                    row["version"],
                    last_updated,
                )
            if release.version:
                latest_version = release.version
                update_available = github_updater.is_newer_version(
                    str(row["version"]), latest_version
                )
                logger.info(
                    "Latest package version source=GitHub repository=%s library=%s installed=%s latest=%s update_available=%s",
                    repository,
                    row["library"],
                    row["version"],
                    latest_version,
                    update_available,
                )
            if not release.published_at:
                logger.info(
                    "Maintenance date source=existing SBOM/data library=%s version=%s date=%s (GitHub release had no publication date)",
                    row["library"],
                    row["version"],
                    existing_date,
                )
        except github_updater.GitHubLookupError as exc:
            # Preserve the established CSV date and UNKNOWN-date behavior when
            # GitHub cannot provide a release date.
            logger.warning(
                "GitHub maintenance lookup failed for %s (%s); using existing SBOM/data date=%s",
                repository,
                exc,
                existing_date,
            )
    else:
        logger.info(
            "Maintenance date source=existing SBOM/data library=%s version=%s date=%s (no known GitHub repository)",
            row["library"],
            row["version"],
            existing_date,
        )

    maintenance_result = maintenance.assess_maintenance(
        last_updated=last_updated, reference_date=reference_date
    )

    score_result = scorer.compute_risk_score(
        vulnerability_penalty=vuln_result.vulnerability_penalty,
        license_penalty=license_result.penalty,
        maintenance_penalty=maintenance_result.penalty,
        vuln_context={
            "severity": vuln_result.severity,
            "cve_id": vuln_result.cve_id,
            "patch_available": vuln_result.patch_available,
        },
        license_context={
            "status": license_result.status,
            "reason": license_result.reason,
        },
        maintenance_context={
            "status": maintenance_result.status,
            "age_years": maintenance_result.age_years,
        },
        weights=weights,
    )

    return {
        "last_updated": last_updated,
        "latest_version": latest_version,
        "update_available": update_available,
        "license_status": license_result.status,
        "license_penalty": license_result.penalty,
        "maintenance_status": maintenance_result.status,
        "maintenance_penalty": maintenance_result.penalty,
        "cve_id": vuln_result.cve_id,
        "cvss_score": vuln_result.cvss_score,
        "severity": vuln_result.severity if vuln_result.matched_cve_count else "NONE",
        "patch_available": vuln_result.patch_available,
        "vulnerability_penalty": vuln_result.vulnerability_penalty,
        "risk_score": score_result.risk_score,
        "risk_level": score_result.risk_level,
        "risk_type": score_result.risk_type,
        "recommendation": score_result.recommendation,
        "flags": ", ".join(score_result.flags) if score_result.flags else "",
    }


def analyze_all(
    applications_path: str | Path,
    dependencies_path: str | Path,
    vulnerabilities_path: str | Path,
    licenses_path: str | Path,
    weights: scorer.RiskWeights | None = None,
    reference_date: date | None = None,
) -> pd.DataFrame:
    """
    Run the full SBOM risk analysis pipeline and return one clean,
    flat DataFrame — one row per (application, dependency) pair.

    Parameters
    ----------
    applications_path : path to applications.json
    dependencies_path : path to sbom_dependencies.csv
    vulnerabilities_path : path to vulnerability_db.json
    licenses_path : path to license_rules.json
    weights : optional RiskWeights to tune component contributions
    reference_date : optional date to measure maintenance staleness
        against (defaults to today); useful for reproducible tests

    Returns
    -------
    pandas.DataFrame with columns defined in `OUTPUT_COLUMNS`, sorted
    by risk_score descending.

    Raises
    ------
    FileLoadError, SchemaValidationError, DataQualityError
        (see exceptions.py) if any input file is missing, malformed,
        or fails a schema check.
    """
    # Refresh release dates for every new upload/analysis. The updater still
    # caches within this run so repeated app dependencies share one API call.
    github_updater.clear_release_cache()
    weights = weights or scorer.RiskWeights()

    logger.info("Loading input files...")
    applications_df = parser.load_applications(applications_path)
    dependencies_df = parser.load_dependencies(dependencies_path)
    vuln_db = parser.load_vulnerability_db(vulnerabilities_path)
    license_rules = parser.load_license_rules(licenses_path)

    logger.info(
        "Loaded %d application(s), %d dependency row(s), %d vulnerability "
        "record(s).",
        len(applications_df),
        len(dependencies_df),
        len(vuln_db),
    )

    merged = dependencies_df.merge(
    applications_df,
    on="app_id",
    how="left",
    suffixes=("", "_json")
)

    # Faculty dataset already provides application_name in the CSV.
    # If it doesn't exist, create it from the JSON "name" field.
    if "application_name" not in merged.columns:
        if "name" in merged.columns:
            merged["application_name"] = merged["name"]
        else:
            merged["application_name"] = "UNKNOWN_APPLICATION"

    unknown_app_mask = merged["application_name"].isna()

    if unknown_app_mask.any():
        merged.loc[unknown_app_mask, "application_name"] = "UNKNOWN_APPLICATION"
    if unknown_app_mask.any():
        logger.warning(
            "%d dependency row(s) reference an app_id not present in "
            "applications.json; labeling as UNKNOWN_APPLICATION.",
            int(unknown_app_mask.sum()),
        )
        merged.loc[unknown_app_mask, "application_name"] = "UNKNOWN_APPLICATION"

    vuln_index = vuln_matcher.build_vuln_index(vuln_db)

    logger.info("Scoring %d dependency row(s)...", len(merged))
    scored_records = merged.apply(
        lambda row: _score_one_row(row, vuln_index, license_rules, weights, reference_date),
        axis=1,
        result_type="expand",
    )

    result = pd.concat(
        [
            merged.drop(
                columns=["last_updated", "latest_version", "update_available"],
                errors="ignore",
            ).reset_index(drop=True),
            scored_records,
        ],
        axis=1,
    )
    result = result[OUTPUT_COLUMNS]
    result = result.sort_values("risk_score", ascending=False).reset_index(drop=True)

    logger.info("Analysis complete. %d row(s) scored.", len(result))
    return result
