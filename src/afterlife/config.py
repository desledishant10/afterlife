from dataclasses import dataclass


@dataclass
class Config:
    unused_days_threshold: int = 90
    never_used_grace_days: int = 30
    unrotated_key_days: int = 180
    oauth_stale_days: int = 90


DEFAULT = Config()
