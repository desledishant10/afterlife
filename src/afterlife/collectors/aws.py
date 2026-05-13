from pathlib import Path

from afterlife.collectors.base import Collector


class AWSCollector(Collector):
    source = "aws"

    def __init__(self, profile: str, region: str, db_path: Path):
        super().__init__(db_path)
        self.profile = profile
        self.region = region

    def run(self) -> int:
        # Week 1 implementation plan:
        #   - boto3.Session(profile_name=self.profile, region_name=self.region)
        #   - iam.list_users() with paginator
        #   - iam.list_access_keys() per user
        #   - iam.get_access_key_last_used() for each key
        #   - iam.list_roles() and last-used per role
        #   - iam.generate_credential_report() then iam.get_credential_report() to parse CSV
        #     (gives password_last_used, access_key_1_last_rotated, etc.)
        #   - for each user/role/key: build Identity / Credential and call db.upsert_*
        raise NotImplementedError("AWS collector — implement in Week 1")
