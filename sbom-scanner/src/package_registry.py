"""Look up current release metadata from explicitly mapped public registries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from packaging.version import InvalidVersion, Version

_PYPI_BASE = "https://pypi.org/pypi"
_TIMEOUT_SECONDS = 5


class RegistryLookupError(Exception):
    """Base class for expected package registry lookup failures."""


class RegistryPackageNotFound(RegistryLookupError):
    pass


class RegistryNetworkTimeout(RegistryLookupError):
    pass


class RegistryAPIFailure(RegistryLookupError):
    pass


@dataclass(frozen=True)
class RegistryRelease:
    version: str | None
    published_at: str | None


def _get_json(url: str) -> dict:
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "SBOM-Analyzer"},
    )
    try:
        with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            raise RegistryPackageNotFound("PyPI package was not found.") from exc
        raise RegistryAPIFailure(f"PyPI returned HTTP {exc.code}.") from exc
    except TimeoutError as exc:
        raise RegistryNetworkTimeout("Timed out contacting PyPI.") from exc
    except URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise RegistryNetworkTimeout("Timed out contacting PyPI.") from exc
        raise RegistryAPIFailure(f"Could not contact PyPI: {exc.reason}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RegistryAPIFailure("PyPI returned invalid JSON.") from exc


def _published_date(release_files: object) -> str | None:
    if not isinstance(release_files, list):
        return None
    timestamps = []
    for item in release_files:
        if not isinstance(item, dict):
            continue
        value = item.get("upload_time_iso_8601") or item.get("upload_time")
        if not value:
            continue
        try:
            timestamps.append(
                datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
            )
        except ValueError:
            continue
    return min(timestamps).isoformat() if timestamps else None


@lru_cache(maxsize=256)
def get_latest_pypi_release(project: str) -> RegistryRelease:
    """Return PyPI's current project version and its first upload date."""
    if not isinstance(project, str) or not project.strip():
        raise RegistryPackageNotFound("PyPI project name is empty.")
    data = _get_json(f"{_PYPI_BASE}/{quote(project.strip(), safe='')}/json")
    info = data.get("info") or {}
    raw_version = info.get("version")
    version = None
    if raw_version:
        try:
            version = str(Version(str(raw_version)))
        except InvalidVersion:
            version = None

    releases = data.get("releases") or {}
    published_at = _published_date(releases.get(str(raw_version))) if raw_version else None
    if not version and not published_at:
        raise RegistryAPIFailure("PyPI response had no usable version or publication date.")
    return RegistryRelease(version=version, published_at=published_at)


def clear_release_cache() -> None:
    """Clear cached PyPI metadata before a new analysis run."""
    get_latest_pypi_release.cache_clear()
