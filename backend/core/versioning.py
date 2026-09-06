"""API versioning and deprecation.

The problem this solves has already occurred: adding pagination changed the
shape of three list endpoints from an array to `{items, pagination}`. Any
integrator would have broken without warning. Versioning makes that kind of
change announceable rather than sudden.

Approach: URL-prefixed versions (`/v1/violations`). Header-based negotiation is
more elegant but harder to test, harder to curl, and invisible in a browser —
the version being in the URL means a support conversation can quote it.

Unversioned paths continue to work and are treated as `/v1`. Breaking existing
clients in order to introduce versioning would be self-defeating.
"""


CURRENT_VERSION = "v1"
SUPPORTED_VERSIONS = ("v1",)

# Deprecations are declared here rather than scattered across endpoints, so the
# full picture is visible in one place and can be published.
#
# Each entry: path -> (deprecated_on, sunset_on, replacement, reason)
DEPRECATIONS: dict[str, tuple] = {
    # Example of the intended shape, kept as documentation of the contract:
    # "/v1/scans/reset": (
    #     date(2026, 12, 1), date(2027, 3, 1), "/v1/scans/bulk-delete",
    #     "Replaced by a scoped deletion endpoint with dry-run support.",
    # ),
}

# Minimum notice before an endpoint is removed. Stated as policy so the
# decision is not made case by case under delivery pressure.
MIN_DEPRECATION_DAYS = 90


def deprecation_headers(path: str) -> dict:
    """RFC 8594 headers for a deprecated path.

    Machine-readable, so a client's monitoring can flag an impending removal
    without anyone reading a changelog.
    """
    entry = DEPRECATIONS.get(path)
    if not entry:
        return {}

    deprecated_on, sunset_on, replacement, _reason = entry
    headers = {
        "Deprecation": deprecated_on.isoformat(),
        "Sunset": sunset_on.isoformat(),
    }
    if replacement:
        headers["Link"] = f'<{replacement}>; rel="successor-version"'
    return headers


def version_info() -> dict:
    """The versioning contract, published rather than assumed."""
    return {
        "current_version": CURRENT_VERSION,
        "supported_versions": list(SUPPORTED_VERSIONS),
        "unversioned_paths_resolve_to": CURRENT_VERSION,
        "policy": {
            "minimum_deprecation_notice_days": MIN_DEPRECATION_DAYS,
            "breaking_change_definition": [
                "Removing or renaming a field in a response",
                "Changing a field's type",
                "Adding a required request parameter",
                "Changing the shape of a response envelope",
                "Removing an endpoint",
            ],
            "non_breaking": [
                "Adding an optional response field",
                "Adding an optional request parameter",
                "Adding a new endpoint",
                "Relaxing a validation rule",
            ],
        },
        "deprecations": [
            {
                "path": path,
                "deprecated_on": dep.isoformat(),
                "sunset_on": sunset.isoformat(),
                "replacement": replacement,
                "reason": reason,
            }
            for path, (dep, sunset, replacement, reason) in DEPRECATIONS.items()
        ],
    }