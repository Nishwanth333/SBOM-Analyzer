"""
parser.py
=========
Purpose
-------
Load and validate all raw input files for the SBOM Risk Engine:
applications.json, sbom_dependencies.csv, vulnerability_db.json,
license_rules.json, and (optionally) dependency_labels.csv.

This module is the single point of contact with the filesystem. Every
other module (vuln_matcher, license_checker, maintenance, scorer,
self_eval) receives already-validated, already-cleaned in-memory
objects (DataFrames / dicts) from here and never touches disk itself.

Inputs
------
- applications_path:   path to applications.json
- dependencies_path:   path to sbom_dependencies.csv
- vulnerabilities_path: path to vulnerability_db.json
- licenses_path:       path to license_rules.json
- labels_path:         path to dependency_labels.csv (evaluation only)

Outputs
-------
- pandas.DataFrame for applications
- pandas.DataFrame for dependencies (cleaned: no dup rows, NaNs handled)
- list[dict] for vulnerability records
- dict for license rules
- pandas.DataFrame for ground-truth labels (evaluation only)

Workflow
--------
1. Confirm the file exists.
2. Parse JSON/CSV using pandas / the json stdlib.
3. Validate that required columns/keys are present (schema check).
4. Normalize dtypes, strip whitespace, drop exact duplicate rows.
5. Raise a typed exception (see exceptions.py) with an actionable
   message on any failure, rather than letting raw parser errors
   propagate.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from .exceptions import DataQualityError, FileLoadError, SchemaValidationError
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Schema contracts
# --------------------------------------------------------------------------- #

REQUIRED_APPLICATION_FIELDS = {"app_id", "application_name"}

REQUIRED_DEPENDENCY_COLUMNS = {
    "app_id",
    "library",
    "version",
    "dependency_type",
    "license",
}

REQUIRED_VULNERABILITY_FIELDS = {
    "library",
    "cve_id",
    "cvss_score",
    "severity",
    "patch_available",
}

REQUIRED_LABEL_COLUMNS = {"app_id", "library", "version", "ground_truth_risk_level"}


# --------------------------------------------------------------------------- #
# Low-level file helpers
# --------------------------------------------------------------------------- #

def _ensure_file_exists(path: str | Path) -> Path:
    """Resolve a path and confirm it exists, raising FileLoadError if not."""
    p = Path(path)
    if not p.is_file():
        raise FileLoadError(f"Required input file not found: {p}")
    return p


def _load_json(path: str | Path) -> Any:
    """Load and parse a JSON file, wrapping parse errors meaningfully."""
    p = _ensure_file_exists(path)
    try:
        with p.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise FileLoadError(f"Malformed JSON in {p}: {exc}") from exc
    except OSError as exc:
        raise FileLoadError(f"Could not read {p}: {exc}") from exc


def _load_csv(path: str | Path) -> pd.DataFrame:
    """Load a CSV file into a DataFrame, wrapping parse errors meaningfully."""
    p = _ensure_file_exists(path)
    try:
        return pd.read_csv(p)
    except pd.errors.EmptyDataError as exc:
        raise FileLoadError(f"CSV file is empty: {p}") from exc
    except pd.errors.ParserError as exc:
        raise FileLoadError(f"Malformed CSV in {p}: {exc}") from exc


def _validate_columns(df: pd.DataFrame, required: set[str], source: str) -> None:
    """Raise SchemaValidationError if any required column is missing."""
    missing = required - set(df.columns)
    if missing:
        raise SchemaValidationError(
            f"{source} is missing required column(s): {sorted(missing)}"
        )


def _validate_keys(records: list[dict], required: set[str], source: str) -> None:
    """Raise SchemaValidationError if any record is missing required keys."""
    if not isinstance(records, list):
        raise SchemaValidationError(f"{source} must be a JSON array of objects.")
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            raise SchemaValidationError(f"{source} record #{i} is not an object.")
        missing = required - set(record.keys())
        if missing:
            raise SchemaValidationError(
                f"{source} record #{i} is missing required key(s): {sorted(missing)}"
            )


# --------------------------------------------------------------------------- #
# Public loaders
# --------------------------------------------------------------------------- #

def load_applications(path: str | Path) -> pd.DataFrame:
    """
    Load applications.json into a validated DataFrame.

    Expected shape: a JSON array of objects, each with at least
    `app_id` and `application_name`.
    """
    records = _load_json(path)
    for record in records:
        if "name" in record and "application_name" not in record:
            record["application_name"] = record["name"]
    _validate_keys(records, REQUIRED_APPLICATION_FIELDS, "applications.json")

    df = pd.DataFrame(records)
    df["app_id"] = df["app_id"].astype(str).str.strip()
    df["application_name"] = df["application_name"].astype(str).str.strip()

    before = len(df)
    df = df.drop_duplicates(subset=["app_id"], keep="first").reset_index(drop=True)
    if len(df) < before:
        logger.warning(
            "Dropped %d duplicate application_id row(s) from applications.json",
            before - len(df),
        )

    if df["app_id"].eq("").any():
        raise DataQualityError("applications.json contains blank app_id value(s).")

    return df


def load_dependencies(path: str | Path) -> pd.DataFrame:
    """
    Load sbom_dependencies.csv into a validated, cleaned DataFrame.

    Expected columns: app_id, library, version, dependency_type, and
    license. `last_updated`, manually supplied `latest_version`, and
    repository metadata columns such as `github_repo`, `repository`,
    `repository_url`, and `source_url` are optional inputs. An absent
    `last_updated` is unknown if no GitHub date can be resolved.

    Cleaning performed:
    - Whitespace stripped from string columns.
    - Exact duplicate rows dropped.
    - Missing `license` -> "Unknown".
    - Missing `version` -> "" (handled explicitly downstream, never
      silently dropped, since an unknown version is itself a risk
      signal).
    - Rows missing `library` (the join key for vuln/license/maintenance
      checks) are dropped with a warning, since they cannot be scored.
    """
    df = _load_csv(path)
    # Support faculty dataset column names
    if "application_id" in df.columns and "app_id" not in df.columns:
        df = df.rename(columns={"application_id": "app_id"})
    _validate_columns(df, REQUIRED_DEPENDENCY_COLUMNS, "sbom_dependencies.csv")
    if "last_updated" not in df.columns:
        df["last_updated"] = ""

    string_cols = ["app_id", "library", "version", "dependency_type", "license"]
    for col in string_cols:
        # fillna BEFORE astype(str): modern pandas can leave real NaN
        # values as float NaN even after astype(str) depending on the
        # backing dtype, so NaNs must be cleared first rather than relying
        # on astype(str) turning them into the literal string "nan".
        df[col] = df[col].fillna("").astype(str).str.strip()
        df[col] = df[col].replace({"nan": "", "None": ""})

    if "latest_version" in df.columns:
        df["latest_version"] = (
            df["latest_version"].fillna("").astype(str).str.strip()
            .replace({"nan": "", "None": ""})
        )

    before = len(df)
    df = df.drop_duplicates(keep="first").reset_index(drop=True)
    if len(df) < before:
        logger.warning(
            "Dropped %d exact duplicate row(s) from sbom_dependencies.csv",
            before - len(df),
        )

    missing_library_mask = df["library"].eq("")
    if missing_library_mask.any():
        logger.warning(
            "Dropping %d row(s) with missing library name (cannot be scored).",
            int(missing_library_mask.sum()),
        )
        df = df.loc[~missing_library_mask].reset_index(drop=True)

    df["license"] = df["license"].replace("", "Unknown")
    df["dependency_type"] = df["dependency_type"].replace("", "unknown")

    if df.empty:
        raise DataQualityError(
            "sbom_dependencies.csv contained no usable rows after cleaning."
        )

    return df


def load_vulnerability_db(path: str | Path) -> list[dict]:
    """
    Load vulnerability_db.json into a validated list of records.

    Each record must contain at least: library, cve_id, cvss_score,
    severity, patch_available. `version_range` is optional; when
    absent the record is treated as matching all versions of that
    library.
    """
    records = _load_json(path)
    _validate_keys(records, REQUIRED_VULNERABILITY_FIELDS, "vulnerability_db.json")

    cleaned: list[dict] = []
    for i, record in enumerate(records):
        rec = dict(record)  # shallow copy, do not mutate caller's data
        rec["library"] = str(rec["library"]).strip()

        try:
            rec["cvss_score"] = float(rec["cvss_score"])
        except (TypeError, ValueError) as exc:
            raise DataQualityError(
                f"vulnerability_db.json record #{i} has a non-numeric cvss_score: "
                f"{rec.get('cvss_score')!r}"
            ) from exc

        rec["severity"] = str(rec.get("severity", "UNKNOWN")).strip().upper()
        rec["patch_available"] = bool(rec.get("patch_available", False))
        rec["version_range"] = rec.get("version_range") or rec.get("version") or None
        cleaned.append(rec)

    if not cleaned:
        raise DataQualityError("vulnerability_db.json contained zero records.")

    return cleaned


def load_license_rules(path: str | Path) -> dict:
    """
    Load license_rules.json into a dict keyed by license identifier.

    Expected shape:
        {
          "MIT": {"status": "ALLOWED", "penalty": 0, "reason": "..."},
          ...
        }

    A "default" or "Unknown" key is recommended (but not required) so
    license_checker.py has a fallback for unrecognized license strings.
    """
    rules = _load_json(path)
    if not isinstance(rules, dict):
        raise SchemaValidationError(
            "license_rules.json must be a JSON object keyed by license name."
        )

    for license_name, rule in rules.items():
        if not isinstance(rule, dict) or not {"status", "penalty"} <= set(rule.keys()):
            raise SchemaValidationError(
                f"license_rules.json entry '{license_name}' must contain "
                f"'status' and 'penalty'."
            )
    return rules


def load_ground_truth_labels(path: str | Path) -> pd.DataFrame:
    """
    Load dependency_labels.csv (evaluation-only ground truth).

    Expected columns: app_id, library, version, ground_truth_risk_level.
    """
    df = _load_csv(path)
    _validate_columns(df, REQUIRED_LABEL_COLUMNS, "dependency_labels.csv")

    for col in ["app_id", "library", "version"]:
        df[col] = df[col].astype(str).str.strip()
    df["ground_truth_risk_level"] = (
        df["ground_truth_risk_level"].astype(str).str.strip().str.upper()
    )
    return df.drop_duplicates().reset_index(drop=True)
