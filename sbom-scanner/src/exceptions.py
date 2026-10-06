"""
exceptions.py
=============
Centralized custom exception hierarchy for the SBOM Risk Engine.

Keeping exceptions in one module avoids duplication across parser.py,
vuln_matcher.py, license_checker.py, maintenance.py, and scorer.py, and
lets callers catch a single base class (`RiskEngineError`) if desired.
"""


class RiskEngineError(Exception):
    """Base exception for all Risk Engine errors."""


class SchemaValidationError(RiskEngineError):
    """Raised when an input file is missing required columns/keys."""


class FileLoadError(RiskEngineError):
    """Raised when a file cannot be read, parsed, or located on disk."""


class DataQualityError(RiskEngineError):
    """Raised when data fails sanity checks (e.g. unparseable rows)."""
