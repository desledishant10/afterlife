from dataclasses import dataclass


@dataclass
class Config:
    unused_days_threshold: int = 90
    never_used_grace_days: int = 30
    unrotated_key_days: int = 180
    oauth_stale_days: int = 90
    inactive_admin_days: int = 30
    privilege_drift_days: int = 90
    privilege_drift_min_unused: int = 5


DEFAULT = Config()
