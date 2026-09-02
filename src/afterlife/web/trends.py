"""Finding-history trends, computed from the lifecycle timestamps.

Every finding carries `first_seen` and (when it goes away) `resolved_at`, so the
open finding count at any past moment is just the findings that had appeared but
had not yet resolved. From that we derive an open-over-time series (split by
severity), the per-period new/resolved flow, and headline stats. Pure and
timezone-safe so it is easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

SEVERITIES = ("critical", "high", "medium", "low")


@dataclass
class _Point:
    sev: str
    first: datetime
    resolved: datetime | None


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def _empty() -> dict:
    return {
        "empty": True,
        "open_now": 0,
        "total_ever": 0,
        "resolved_total": 0,
        "median_ttr_days": None,
        "buckets": [],
        "max_open": 0,
        "max_flow": 0,
        "range_start": None,
        "range_end": None,
    }


def compute_trends(findings: list[dict], now: datetime, *, buckets: int = 14) -> dict:
    parsed: list[_Point] = []
    for f in findings:
        first = _parse(f.get("first_seen"))
        if first is None:
            continue
        sev = f.get("severity")
        parsed.append(
            _Point(
                sev=sev if sev in SEVERITIES else "low",
                first=first,
                resolved=_parse(f.get("resolved_at")),
            )
        )
    if not parsed:
        return _empty()

    start = min(p.first for p in parsed)
    end = now if now > start else start + timedelta(days=1)
    span = (end - start) / buckets or timedelta(days=1)

    def bucket_index(t: datetime) -> int:
        if t <= start:
            return 0
        if t >= end:
            return buckets - 1
        return min(int((t - start) / span), buckets - 1)

    new_hist = [0] * buckets
    res_hist = [0] * buckets
    for p in parsed:
        new_hist[bucket_index(p.first)] += 1
        if p.resolved is not None:
            res_hist[bucket_index(p.resolved)] += 1

    bucket_data = []
    max_open = 0
    for i in range(buckets):
        b_end = start + span * (i + 1)
        open_by_sev = {s: 0 for s in SEVERITIES}
        for p in parsed:
            if p.first <= b_end and (p.resolved is None or p.resolved > b_end):
                open_by_sev[p.sev] += 1
        total_open = sum(open_by_sev.values())
        max_open = max(max_open, total_open)
        bucket_data.append(
            {
                "label": b_end.strftime("%b %d"),
                "open": open_by_sev,
                "open_total": total_open,
                "new": new_hist[i],
                "resolved": res_hist[i],
            }
        )

    ttrs = [
        (p.resolved - p.first).total_seconds() / 86400
        for p in parsed
        if p.resolved is not None and p.resolved >= p.first
    ]
    median_ttr = _median(ttrs)
    max_flow = max(new_hist + res_hist + [0])

    return {
        "empty": False,
        "open_now": sum(1 for p in parsed if p.resolved is None),
        "total_ever": len(parsed),
        "resolved_total": sum(1 for p in parsed if p.resolved is not None),
        "median_ttr_days": round(median_ttr, 1) if median_ttr is not None else None,
        "buckets": bucket_data,
        "max_open": max_open,
        "max_flow": max_flow,
        "range_start": start.strftime("%b %d, %Y"),
        "range_end": end.strftime("%b %d, %Y"),
    }
