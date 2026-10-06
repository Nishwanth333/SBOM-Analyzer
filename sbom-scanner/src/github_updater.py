"""Look up a GitHub repository's latest published release date.

Public repositories can be queried anonymously. Set ``GITHUB_TOKEN`` (or
``GH_TOKEN``) to raise the API rate limit when the anonymous limit is reached.
All lookup failures use typed exceptions so callers can retain their existing
maintenance-date fallback without coupling this module to maintenance.py.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
from packaging.version import InvalidVersion, Version

_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_API_BASE = "https://api.github.com/repos"
_TIMEOUT_SECONDS = 5
_FAILURE_COOLDOWN_SECONDS = 60
_api_failure_until = 0.0
_api_failure: GitHubLookupError | None = None

# Exact, well-known package-to-repository mappings for common dependencies.
# SBOM repository metadata always takes precedence; unknown names are not
# guessed because popular package names can refer to unrelated projects.
class GitHubLookupError(Exception):
    """Base class for expected GitHub lookup failures."""


class InvalidRepositoryName(GitHubLookupError):
    pass


class RepositoryNotFound(GitHubLookupError):
    pass


class NoReleasesAvailable(GitHubLookupError):
    pass


class GitHubAPIFailure(GitHubLookupError):
    pass


class GitHubNetworkTimeout(GitHubLookupError):
    pass


class GitHubRateLimitExceeded(GitHubLookupError):
    pass


@dataclass(frozen=True)
class LatestRelease:
    """Version and publication date from a GitHub latest-release response."""

    version: str | None
    published_at: str | None


def _get_json(url: str) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SBOM-Analyzer",
    }
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 429 or (exc.code == 403 and (
            exc.headers.get("X-RateLimit-Remaining") == "0"
            or "rate limit" in exc.read().decode("utf-8", errors="ignore").lower()
        )):
            raise GitHubRateLimitExceeded("GitHub API rate limit exceeded.") from exc
        if exc.code == 404:
            raise RepositoryNotFound("GitHub repository was not found.") from exc
        raise GitHubAPIFailure(f"GitHub API returned HTTP {exc.code}.") from exc
    except TimeoutError as exc:
        raise GitHubNetworkTimeout("Timed out contacting the GitHub API.") from exc
    except URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise GitHubNetworkTimeout("Timed out contacting the GitHub API.") from exc
        raise GitHubAPIFailure(f"Could not contact the GitHub API: {exc.reason}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise GitHubAPIFailure("GitHub API returned invalid JSON.") from exc


@lru_cache(maxsize=512)
def _latest_release(repository: str) -> LatestRelease:
    encoded = quote(repository, safe="/")
    release_url = f"{_API_BASE}/{encoded}/releases/latest"
    try:
        release = _get_json(release_url)
    except RepositoryNotFound as release_error:
        # The latest-release endpoint also returns 404 when a repository has
        # no published releases. Verify repository existence to distinguish it.
        try:
            _get_json(f"{_API_BASE}/{encoded}")
        except RepositoryNotFound:
            raise
        raise NoReleasesAvailable(
            f"GitHub repository '{repository}' has no published releases."
        ) from release_error

    published_at = release.get("published_at")
    published_date = None
    if published_at:
        try:
            published_date = datetime.fromisoformat(
                published_at.replace("Z", "+00:00")
            ).date().isoformat()
        except (AttributeError, TypeError, ValueError) as exc:
            raise GitHubAPIFailure(
                "GitHub returned an invalid release publication date."
            ) from exc

    release_tag = release.get("tag_name")
    normalized_version = None
    if release_tag:
        try:
            normalized_version = str(Version(str(release_tag).strip()))
        except InvalidVersion:
            # A release can have a useful date but a non-package tag. Keep
            # maintenance analysis working and leave that SBOM version alone.
            normalized_version = None

    if not published_date and not normalized_version:
        raise NoReleasesAvailable(
            f"GitHub repository '{repository}' has no usable release version or date."
        )
    return LatestRelease(version=normalized_version, published_at=published_date)


def _get_release(repository: str) -> LatestRelease:
    """Fetch a release through the cache and preserve the outage cooldown."""
    global _api_failure_until, _api_failure

    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository.strip()):
        raise InvalidRepositoryName("Repository must be a GitHub 'owner/repository' slug.")
    if time.monotonic() < _api_failure_until and _api_failure is not None:
        raise type(_api_failure)(str(_api_failure))
    try:
        result = _latest_release(repository.strip())
    except (GitHubNetworkTimeout, GitHubRateLimitExceeded, GitHubAPIFailure) as exc:
        _api_failure = exc
        _api_failure_until = time.monotonic() + _FAILURE_COOLDOWN_SECONDS
        raise
    _api_failure = None
    _api_failure_until = 0.0
    return result


def get_latest_release(repository: str) -> LatestRelease:
    """Return the latest parseable package version and release date.

    GitHub release tags such as ``v2.32.5`` are normalized to ``2.32.5``.
    Non-version tags are returned as no version, so they cannot rewrite an
    SBOM version accidentally.
    """
    return _get_release(repository)


def get_latest_release_date(repository: str) -> str:
    """Return latest release's publication date as ``YYYY-MM-DD``.

    ``repository`` must be an ``owner/repository`` slug, such as
    ``psf/requests``. Raises a specific :class:`GitHubLookupError` subclass
    for invalid names, missing repositories/releases, rate limits, timeouts,
    or other API/network failures.
    """
    release = _get_release(repository)
    if release.published_at is None:
        raise NoReleasesAvailable(
            f"GitHub repository '{repository}' has no published release date."
        )
    return release.published_at


def clear_release_cache() -> None:
    """Forget successful release lookups before a fresh analysis run.

    Repeated dependencies can still share a result during one analysis, while
    later uploads fetch current GitHub release data instead of reusing a date
    cached for the lifetime of the Flask process.
    """
    _latest_release.cache_clear()


def is_newer_version(current: str, latest: str) -> bool:
    """Return whether a parseable latest version is newer than current."""
    current = str(current).strip()
    latest = str(latest).strip()
    if not current:
        return bool(latest)
    try:
        return Version(latest) > Version(current)
    except InvalidVersion:
        return False
