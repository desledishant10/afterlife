import pytest

from afterlife import db
from afterlife.scan_runs import latest_per_source, list_runs, record_run


def test_record_run_writes_started_and_finished(fresh_db):
    with record_run(fresh_db, "aws") as run:
        run["records_collected"] = 42

    runs = list_runs(fresh_db)
    assert len(runs) == 1
    r = runs[0]
    assert r["source"] == "aws"
    assert r["records_collected"] == 42
    assert r["error"] is None
    assert r["started_at"] is not None
    assert r["finished_at"] is not None


def test_record_run_captures_error(fresh_db):
    with pytest.raises(RuntimeError):
        with record_run(fresh_db, "github"):
            raise RuntimeError("boom")

    runs = list_runs(fresh_db)
    assert len(runs) == 1
    assert runs[0]["error"] == "boom"
    assert runs[0]["records_collected"] is None
    assert runs[0]["finished_at"] is not None


def test_list_runs_orders_newest_first(fresh_db):
    with record_run(fresh_db, "aws") as run:
        run["records_collected"] = 1
    with record_run(fresh_db, "github") as run:
        run["records_collected"] = 2

    runs = list_runs(fresh_db)
    assert [r["source"] for r in runs] == ["github", "aws"]


def test_latest_per_source_returns_one_row_per_source(fresh_db):
    with record_run(fresh_db, "aws") as run:
        run["records_collected"] = 10
    with record_run(fresh_db, "aws") as run:
        run["records_collected"] = 20
    with record_run(fresh_db, "github") as run:
        run["records_collected"] = 5

    latest = latest_per_source(fresh_db)
    assert set(latest.keys()) == {"aws", "github"}
    assert latest["aws"]["records_collected"] == 20
    assert latest["github"]["records_collected"] == 5
