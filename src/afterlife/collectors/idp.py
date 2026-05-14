from pathlib import Path

from afterlife.collectors.base import Collector
from afterlife.collectors.google_workspace import GoogleWorkspaceCollector
from afterlife.collectors.okta import OktaCollector


def build_idp_collector(provider: str, db_path: Path, **kwargs) -> Collector:
    if provider == "google":
        google_keys = {"service_account_file", "admin_email", "access_token"}
        filtered = {k: v for k, v in kwargs.items() if k in google_keys}
        return GoogleWorkspaceCollector(db_path=db_path, **filtered)
    if provider == "okta":
        okta_keys = {"domain", "api_token", "api_url"}
        filtered = {k: v for k, v in kwargs.items() if k in okta_keys}
        return OktaCollector(db_path=db_path, **filtered)
    raise ValueError(f"Unknown IdP provider: {provider!r}")
