"""Curated package-to-GitHub repository mappings.

Add verified package names to ``PACKAGE_REPOSITORIES`` as mappings are
confirmed. Names are matched case-insensitively; unmapped packages return
``None`` so callers can retain their existing maintenance data.
"""

from __future__ import annotations

import re

PACKAGE_REPOSITORIES: dict[str, str] = {
    "requests": "psf/requests",
    "flask": "pallets/flask",
    "numpy": "numpy/numpy",
    "pandas": "pandas-dev/pandas",
}

_REPOSITORY_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:\.git|/.*)?/?$",
    re.IGNORECASE,
)


class InvalidRepositoryReference(ValueError):
    """Raised when explicit repository metadata is not a GitHub slug or URL."""


def resolve_repository(library: str, repository: str | None = None) -> str | None:
    """Resolve explicit repository metadata or a curated package mapping.

    Explicit repository metadata takes precedence. Package matching uses the
    exact package name after trimming and case folding; it never guesses a
    repository from an unmapped name.
    """
    if repository is not None and str(repository).strip():
        value = str(repository).strip()
        url_match = _GITHUB_URL_RE.fullmatch(value)
        if url_match:
            return url_match.group(1)
        if _REPOSITORY_SLUG_RE.fullmatch(value):
            return value
        raise InvalidRepositoryReference(
            "Repository metadata must be an owner/repo slug or GitHub URL."
        )

    return PACKAGE_REPOSITORIES.get(str(library).strip().casefold())
