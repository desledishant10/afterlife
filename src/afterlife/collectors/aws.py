from pathlib import Path
from typing import Any, Iterator

import boto3

from afterlife import db
from afterlife.collectors.base import Collector
from afterlife.models import Credential, Identity

EMAIL_TAG_KEYS = ("email", "Email", "owner", "Owner", "owner_email", "OwnerEmail")


class AWSCollector(Collector):
    """Pulls IAM users, access keys, and roles from one AWS account.

    Users become Identity rows with `source="aws"` and the user ARN as id.
    Access keys become Credential rows owned by the IAM user (`owner_source="aws"`).
    Roles become ownerless Credential rows of type `aws_iam_role`; the trust policy
    governs who can assume them, so there is no single owner to record.

    Cross-source ownership (linking an AWS user to its Okta identity) is built later
    in the identity-graph layer (Week 5), not at collection time.
    """

    source = "aws"

    def __init__(
        self,
        db_path: Path,
        *,
        profile: str = "default",
        region: str = "us-east-1",
        session: boto3.Session | None = None,
    ):
        super().__init__(db_path)
        self.profile = profile
        self.region = region
        self._session = session

    def run(self) -> int:
        iam = self._client()
        count = 0
        with db.connect(self.db_path) as conn:
            for user in self._iter_users(iam):
                db.upsert_identity(conn, self._user_to_identity(user))
                count += 1
                for key in self._iter_access_keys(iam, user["UserName"]):
                    db.upsert_credential(
                        conn, self._access_key_to_credential(iam, user, key)
                    )
                    count += 1
            for role in self._iter_roles(iam):
                db.upsert_credential(conn, self._role_to_credential(role))
                count += 1
        return count

    def _client(self):
        if self._session is None:
            self._session = boto3.Session(
                profile_name=self.profile, region_name=self.region
            )
        return self._session.client("iam")

    def _iter_users(self, iam) -> Iterator[dict[str, Any]]:
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                user_name = user["UserName"]
                yield {
                    **user,
                    "Tags": self._user_tags(iam, user_name),
                    "ScopePolicies": self._user_policies(iam, user_name),
                }

    def _user_tags(self, iam, user_name: str) -> list[dict[str, str]]:
        tags: list[dict[str, str]] = []
        for page in iam.get_paginator("list_user_tags").paginate(UserName=user_name):
            tags.extend(page.get("Tags", []))
        return tags

    def _user_policies(self, iam, user_name: str) -> list[str]:
        """Attached managed + inline policy names for an IAM user.

        Returns a flat list of scope strings used by blast-radius scoring.
        Inline policies are prefixed `inline:` so scoring can distinguish
        them if needed; for v0.1 both are treated as elevated signals.
        """
        scopes: list[str] = []
        for page in iam.get_paginator("list_attached_user_policies").paginate(
            UserName=user_name
        ):
            scopes.extend(p["PolicyName"] for p in page.get("AttachedPolicies", []))
        for page in iam.get_paginator("list_user_policies").paginate(
            UserName=user_name
        ):
            scopes.extend(f"inline:{n}" for n in page.get("PolicyNames", []))
        return scopes

    def _iter_access_keys(self, iam, user_name: str) -> Iterator[dict[str, Any]]:
        for page in iam.get_paginator("list_access_keys").paginate(UserName=user_name):
            yield from page["AccessKeyMetadata"]

    def _iter_roles(self, iam) -> Iterator[dict[str, Any]]:
        for page in iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                # list_roles omits RoleLastUsed; get_role fills it in
                detail = iam.get_role(RoleName=role["RoleName"])["Role"]
                detail["ScopePolicies"] = self._role_policies(iam, role["RoleName"])
                yield detail

    def _role_policies(self, iam, role_name: str) -> list[str]:
        scopes: list[str] = []
        for page in iam.get_paginator("list_attached_role_policies").paginate(
            RoleName=role_name
        ):
            scopes.extend(p["PolicyName"] for p in page.get("AttachedPolicies", []))
        for page in iam.get_paginator("list_role_policies").paginate(
            RoleName=role_name
        ):
            scopes.extend(f"inline:{n}" for n in page.get("PolicyNames", []))
        return scopes

    def _user_to_identity(self, user: dict[str, Any]) -> Identity:
        tags = {t["Key"]: t["Value"] for t in user.get("Tags") or []}
        return Identity(
            source="aws",
            source_id=user["Arn"],
            email=_find_email(tags),
            name=user["UserName"],
            status="active",
            last_seen=user.get("PasswordLastUsed"),
            metadata={
                "user_id": user["UserId"],
                "create_date": _iso(user.get("CreateDate")),
                "path": user.get("Path"),
                "tags": tags,
            },
        )

    def _access_key_to_credential(
        self, iam, user: dict[str, Any], key: dict[str, Any]
    ) -> Credential:
        info = (
            iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"]).get(
                "AccessKeyLastUsed"
            )
            or {}
        )
        return Credential(
            source="aws",
            credential_id=key["AccessKeyId"],
            credential_type="aws_access_key",
            owner_source="aws",
            owner_id=user["Arn"],
            created_at=key.get("CreateDate"),
            last_used_at=info.get("LastUsedDate"),
            scopes=list(user.get("ScopePolicies") or []),
            is_active=(key.get("Status") == "Active"),
            metadata={
                "user_name": user["UserName"],
                "status": key.get("Status"),
                "last_used_service": info.get("ServiceName"),
                "last_used_region": info.get("Region"),
            },
        )

    def _role_to_credential(self, role: dict[str, Any]) -> Credential:
        last_used = (role.get("RoleLastUsed") or {}).get("LastUsedDate")
        return Credential(
            source="aws",
            credential_id=role["Arn"],
            credential_type="aws_iam_role",
            owner_source=None,
            owner_id=None,
            created_at=role.get("CreateDate"),
            last_used_at=last_used,
            scopes=list(role.get("ScopePolicies") or []),
            is_active=True,
            metadata={
                "role_name": role["RoleName"],
                "path": role.get("Path"),
                "max_session_duration": role.get("MaxSessionDuration"),
                "last_used_region": (role.get("RoleLastUsed") or {}).get("Region"),
            },
        )


def _find_email(tags: dict[str, str]) -> str | None:
    for k in EMAIL_TAG_KEYS:
        v = tags.get(k)
        if v and "@" in v:
            return v.lower()
    return None


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None
