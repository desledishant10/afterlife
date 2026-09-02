"""Trend computation from finding-lifecycle timestamps."""

from datetime import UTC, datetime

from afterlife.web.trends import compute_trends

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _f(sev, first, resolved=None):
    return {
        "severity": sev,
        "first_seen": first,
        "last_seen": first,
        "resolved_at": resolved,
        "status": "resolved" if resolved else "open",
    }


def test_empty_history():
    d = compute_trends([], NOW)
    assert d["empty"] is True
    assert d["open_now"] == 0
    assert d["buckets"] == []


def test_open_now_and_totals():
    findings = [
        _f("critical", "2026-08-01T00:00:00+00:00"),  # open
        _f("high", "2026-08-10T00:00:00+00:00", "2026-08-20T00:00:00+00:00"),
        _f("low", "2026-08-15T00:00:00+00:00"),  # open
    ]
    d = compute_trends(findings, NOW)
    assert d["empty"] is False
    assert d["open_now"] == 2
    assert d["total_ever"] == 3
    assert d["resolved_total"] == 1
    # The final bucket ends at "now", so its open total is the current open count.
    assert d["buckets"][-1]["open_total"] == 2
    assert d["max_open"] >= 2


def test_median_time_to_resolve():
    findings = [
        _f("high", "2026-08-01T00:00:00+00:00", "2026-08-11T00:00:00+00:00"),  # 10d
        _f("high", "2026-08-01T00:00:00+00:00", "2026-08-05T00:00:00+00:00"),  # 4d
    ]
    d = compute_trends(findings, NOW)
    assert d["median_ttr_days"] == 7.0


def test_new_and_resolved_flow_totals():
    findings = [
        _f("high", "2026-08-01T00:00:00+00:00", "2026-08-28T00:00:00+00:00"),
        _f("low", "2026-08-01T00:00:00+00:00"),
    ]
    d = compute_trends(findings, NOW, buckets=4)
    assert sum(b["new"] for b in d["buckets"]) == 2
    assert sum(b["resolved"] for b in d["buckets"]) == 1


def test_naive_timestamps_are_tolerated():
    # A timestamp without a timezone must not crash the comparison.
    d = compute_trends([_f("high", "2026-08-01T00:00:00")], NOW)
    assert d["open_now"] == 1


def test_severity_split_in_buckets():
    findings = [_f("critical", "2026-08-01T00:00:00+00:00")]
    d = compute_trends(findings, NOW)
    assert d["buckets"][-1]["open"]["critical"] == 1
    assert d["buckets"][-1]["open"]["low"] == 0
