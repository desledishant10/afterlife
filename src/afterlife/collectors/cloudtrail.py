"""CloudTrail usage-enrichment collector.

CloudTrail is the audit log of what actually happened, so it is the
ground-truth source for how AWS credentials are really used. Unlike the other
collectors it does not create identities or credentials; it reads recent
management events (via cloudtrail:LookupEvents) and attaches observed usage to
the AWS credentials the AWS collector already found:

- `last_used_at` is advanced to the most recent observed activity (never
  moved backwards), sharpening UNUSED-CREDENTIAL / NEVER-USED / INACTIVE-ADMIN.
- `metadata.observed_services` records the services each principal actually
  touched, with the last time, which is the "used" side of privilege review.

Principals are matched to credentials by their stable identifier: an IAM
access key by its key id, and an assumed role by its role ARN
(userIdentity.sessionContext.sessionIssuer.arn). Principals with no matching
credential are skipped, so run this after `scan aws`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3

from afterlife import db
from afterlife.collectors.base import Collector


class CloudTrailCollector(Collector):
    source = "cloudtrail"

    def __init__(
        self,
        db_path: Path,
        *,
        profile: str | None = None,
        region: str | None = None,
        session: boto3.Session | None = None,
        client: Any = None,
        lookback_days: int = 90,
    ):
        super().__init__(db_path)
        self.profile = profile
        self.region = region
        self._session = session
        self._client = client
        self.lookback_days = lookback_days

    def run(self) -> int:
        events = self._lookup_events(self._cloudtrail())
        usage = _aggregate(events)
        return self._enrich(usage)

    def _cloudtrail(self):
        if self._client is not None:
            return self._client
        if self._session is None:
            kwargs: dict[str, str] = {}
            if self.profile:
                kwargs["profile_name"] = self.profile
            if self.region:
                kwargs["region_name"] = self.region
            self._session = boto3.Session(**kwargs)
        return self._session.client("cloudtrail")

    def _lookup_events(self, client) -> list[dict[str, Any]]:
        start = datetime.now(UTC) - timedelta(days=self.lookback_days)
        events: list[dict[str, Any]] = []
        for page in client.get_paginator("lookup_events").paginate(StartTime=start):
            events.extend(page.get("Events", []))
        return events

    def _enrich(self, usage: dict[str, dict]) -> int:
        count = 0
        with db.connect(self.db_path) as conn:
            for key, u in usage.items():
                row = conn.execute(
                    "SELECT last_used_at, metadata FROM credentials "
                    "WHERE source = 'aws' AND credential_id = ?",
                    (key,),
                ).fetchone()
                if row is None:
                    continue
                meta = json.loads(row["metadata"]) if row["metadata"] else {}
                meta["observed_services"] = [
                    {"service": s, "last_used": t.isoformat()}
                    for s, t in sorted(u["services"].items())
                ]
                meta["cloudtrail_last_activity"] = u["last_activity"].isoformat()
                meta["cloudtrail_event_count"] = u["count"]
                observed = u["last_activity"].isoformat()
                stored = row["last_used_at"]
                last_used = max(x for x in (observed, stored) if x)
                conn.execute(
                    "UPDATE credentials SET last_used_at = ?, metadata = ? "
                    "WHERE source = 'aws' AND credential_id = ?",
                    (last_used, json.dumps(meta), key),
                )
                count += 1
        return count


def _event_time(event: dict[str, Any], detail: dict[str, Any]) -> datetime | None:
    t = event.get("EventTime")
    if isinstance(t, datetime):
        return t if t.tzinfo else t.replace(tzinfo=UTC)
    raw = detail.get("eventTime")
    if raw:
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            return None
    return None


def _event_keys(detail: dict[str, Any], event: dict[str, Any]) -> list[str]:
    identity = detail.get("userIdentity") or {}
    keys: list[str] = []
    access_key = identity.get("accessKeyId") or event.get("AccessKeyId")
    if access_key:
        keys.append(access_key)
    session_ctx = identity.get("sessionContext") or {}
    issuer = session_ctx.get("sessionIssuer") or {}
    role_arn = issuer.get("arn")
    if role_arn:
        keys.append(role_arn)
    return keys


def _aggregate(events: list[dict[str, Any]]) -> dict[str, dict]:
    usage: dict[str, dict] = {}
    for event in events:
        try:
            detail = json.loads(event.get("CloudTrailEvent") or "{}")
        except (json.JSONDecodeError, TypeError):
            detail = {}
        when = _event_time(event, detail)
        if when is None:
            continue
        service = None
        source = detail.get("eventSource")
        if source:
            service = str(source).split(".", 1)[0]
        for key in _event_keys(detail, event):
            entry = usage.setdefault(
                key, {"last_activity": when, "services": {}, "count": 0}
            )
            entry["count"] += 1
            if when > entry["last_activity"]:
                entry["last_activity"] = when
            if service:
                prev = entry["services"].get(service)
                if prev is None or when > prev:
                    entry["services"][service] = when
    return usage
