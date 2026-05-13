from pathlib import Path

from afterlife.collectors.base import Collector
from afterlife.collectors.google_workspace import GoogleWorkspaceCollector


class OktaCollector(Collector):
    source = "okta"

    def run(self) -> int:
        # TODO future commit:
        #   - GET /api/v1/users with paginator (link header)
        #   - statuses of interest: SUSPENDED, DEPROVISIONED, ACTIVE
        #   - lastLogin for staleness; OAuth tokens via /api/v1/users/{id}/tokens
        raise NotImplementedError("Okta collector — implement in a future commit")


def build_idp_collector(provider: str, db_path: Path, **kwargs) -> Collector:
    if provider == "google":
        return GoogleWorkspaceCollector(db_path=db_path, **kwargs)
    if provider == "okta":
        return OktaCollector(db_path)
    raise ValueError(f"Unknown IdP provider: {provider!r}")
