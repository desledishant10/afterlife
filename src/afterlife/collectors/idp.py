from pathlib import Path

from afterlife.collectors.base import Collector


class GoogleWorkspaceCollector(Collector):
    source = "google"

    def run(self) -> int:
        # Week 4 implementation plan:
        #   - service-account auth with domain-wide delegation
        #   - admin SDK Directory API: users().list()
        #   - map: suspended → "suspended", archived → "deprovisioned"
        #   - capture lastLoginTime for staleness rules
        raise NotImplementedError("Google Workspace collector — implement in Week 4")


class OktaCollector(Collector):
    source = "okta"

    def run(self) -> int:
        # Week 4 implementation plan:
        #   - GET /api/v1/users with paginator (link header)
        #   - statuses of interest: SUSPENDED, DEPROVISIONED, ACTIVE
        #   - lastLogin for staleness; also enumerate OAuth tokens via /api/v1/users/{id}/tokens
        raise NotImplementedError("Okta collector — implement in Week 4")


def build_idp_collector(provider: str, db_path: Path) -> Collector:
    if provider == "google":
        return GoogleWorkspaceCollector(db_path)
    if provider == "okta":
        return OktaCollector(db_path)
    raise ValueError(f"Unknown IdP provider: {provider!r}")
