"""
maintenance.py
==============
Purpose
-------
Assess whether a dependency is actively maintained based on its
`last_updated` date. Libraries not updated within a configurable
staleness threshold (default 2 years) are flagged UNMAINTAINED.

Inputs
------
- last_updated: str - date string from sbom_dependencies.csv
  (e.g. "2021-03-15"); may be missing, blank, or malformed.
- reference_date: date - the date to measure staleness against
  (defaults to today; injectable for reproducible tests).
- staleness_years: float - threshold, default 2.0.

Outputs
-------
A `MaintenanceResult` dataclass with:
- status: str    ("MAINTAINED", "UNMAINTAINED", "UNKNOWN")
- penalty: float
- age_days: int | None
- age_years: float | None

Workflow
--------
1. Attempt to parse `last_updated` using pandas' flexible date parser.
2. If parsing fails or the value is missing, return status UNKNOWN
   with a conservative (non-zero) penalty, since an untraceable
   update history is itself a risk signal, but do not raise.
3. Compute age in days/years relative to `reference_date`.
4. Compare against `staleness_years` to assign MAINTAINED /
   UNMAINTAINED and the associated penalty.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime

import pandas as pd

logger = logging.getLogger(__name__)

DEFAULT_STALENESS_YEARS = 2.0
_DAYS_PER_YEAR = 365.25

_PENALTY_UNKNOWN_DATE = 8.0
_PENALTY_UNMAINTAINED = 15.0
_PENALTY_MAINTAINED = 0.0


@dataclass
class MaintenanceResult:
    """Outcome of assessing one dependency's maintenance status."""

    status: str
    penalty: float
    age_days: int | None
    age_years: float | None


def _parse_date(raw: str) -> date | None:
    """
    Parse a date string leniently. Returns None (never raises) if the
    value is blank or cannot be interpreted as a date.
    """
    if raw is None:
        return None
    raw_str = str(raw).strip()
    if raw_str == "" or raw_str.lower() in {"nan", "none", "n/a", "unknown"}:
        return None

    try:
        parsed = pd.to_datetime(raw_str, errors="raise", utc=False)
    except (ValueError, TypeError, pd.errors.ParserError):
        logger.warning("Could not parse last_updated value '%s'.", raw)
        return None

    if pd.isna(parsed):
        return None

    return parsed.date() if hasattr(parsed, "date") else parsed


def assess_maintenance(
    last_updated: str,
    reference_date: date | None = None,
    staleness_years: float = DEFAULT_STALENESS_YEARS,
) -> MaintenanceResult:
    """
    Evaluate a dependency's maintenance status from its last-updated date.

    `reference_date` defaults to `datetime.now().date()` but can be
    injected for deterministic unit tests.
    """
    reference_date = reference_date or datetime.now().date()

    parsed_date = _parse_date(last_updated)
    if parsed_date is None:
        return MaintenanceResult(
            status="UNKNOWN",
            penalty=_PENALTY_UNKNOWN_DATE,
            age_days=None,
            age_years=None,
        )

    if parsed_date > reference_date:
        logger.warning(
            "last_updated '%s' is in the future relative to reference_date "
            "'%s'; clamping age to 0.",
            parsed_date,
            reference_date,
        )
        age_days = 0
    else:
        age_days = (reference_date - parsed_date).days

    age_years = round(age_days / _DAYS_PER_YEAR, 2)

    if age_years > staleness_years:
        return MaintenanceResult(
            status="UNMAINTAINED",
            penalty=_PENALTY_UNMAINTAINED,
            age_days=age_days,
            age_years=age_years,
        )

    return MaintenanceResult(
        status="MAINTAINED",
        penalty=_PENALTY_MAINTAINED,
        age_days=age_days,
        age_years=age_years,
    )
