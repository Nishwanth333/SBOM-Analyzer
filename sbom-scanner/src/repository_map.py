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
    # Additional verified upstreams for common packages in the supplied
    # multi-ecosystem SBOM. Keep ambiguous names (for example, inquirer)
    # unmapped until the SBOM provides an ecosystem or package URL.
    "netty-all": "netty/netty",
    "logrus": "sirupsen/logrus",
    "cryptography": "pyca/cryptography",
    "pyyaml": "yaml/pyyaml",
    "safety": "pyupio/safety",
    "guava": "google/guava",
    "lodash": "lodash/lodash",
    "jackson-core": "FasterXML/jackson-core",
    "logback-classic": "qos-ch/logback",
    "nodemon": "remy/nodemon",
    "resty": "go-resty/resty",
    "sqlalchemy": "sqlalchemy/sqlalchemy",
    "mux": "gorilla/mux",
    "protobuf-go": "protocolbuffers/protobuf-go",
    "assertj-core": "assertj/assertj",
    "micrometer-core": "micrometer-metrics/micrometer",
    "moment": "moment/moment",
    "jetty-server": "jetty/jetty.project",
}

# Use the canonical PyPI project name only for packages identified here.
# This is a fallback for projects that publish packages to PyPI but do not
# create GitHub Release objects (for example, pyca/cryptography).
PYPI_PACKAGES: dict[str, str] = {
    "cryptography": "cryptography",
    "pyyaml": "PyYAML",
    "safety": "safety",
    "sqlalchemy": "SQLAlchemy",
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


def resolve_pypi_package(library: str) -> str | None:
    """Return a curated PyPI project name without guessing from a library name."""
    return PYPI_PACKAGES.get(str(library).strip().casefold())
