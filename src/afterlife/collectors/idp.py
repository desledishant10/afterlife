from pathlib import Path

from afterlife.collectors.azure_entra import AzureEntraIDCollector
from afterlife.collectors.base import Collector
from afterlife.collectors.google_workspace import GoogleWorkspaceCollector
from afterlife.collectors.okta import OktaCollector


def build_idp_collector(provider: str, db_path: Path, **kwargs) -> Collector:
    if provider == "google":
        keys = {"service_account_file", "admin_email", "access_token"}
        filtered = {k: v for k, v in kwargs.items() if k in keys}
        return GoogleWorkspaceCollector(db_path=db_path, **filtered)
    if provider == "okta":
        keys = {"domain", "api_token", "api_url"}
        filtered = {k: v for k, v in kwargs.items() if k in keys}
        return OktaCollector(db_path=db_path, **filtered)
    if provider == "azure":
        keys = {"tenant_id", "client_id", "client_secret", "access_token"}
        filtered = {k: v for k, v in kwargs.items() if k in keys}
        return AzureEntraIDCollector(db_path=db_path, **filtered)
    raise ValueError(f"Unknown IdP provider: {provider!r}")
