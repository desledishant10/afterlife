"""Pipeline runner: scan -> analyze -> notify, one shot and on a loop."""

from pathlib import Path

import httpx
import respx

from afterlife import db
from afterlife.models import Severity
from afterlife.notify import NotifyConfig
from afterlife.runner import (
    SOURCE_BUILDERS,
    RunConfig,
    SourceNotConfigured,
    detect_sources,
    run_pipeline,
    watch,
)
from tests.conftest import make_credential, make_identity

WEBHOOK = "https://hooks.example.com/afterlife"


class _FakeCollector:
    source = "fake"

    def __init__(self, db_path):
        self.db_path = db_path

    def run(self):
        # Seed a suspended owner + its credential so OFFBOARDED-OWNER fires.
        with db.connect(self.db_path) as conn:
            db.upsert_identity(conn, make_identity(status="suspended"))
            db.upsert_credential(conn, make_credential())
        return 2


def _fake_builders():
    return {"fake": lambda db_path, env: _FakeCollector(db_path)}


# ---------- pipeline ----------


def test_run_pipeline_scans_then_analyzes(fresh_db):
    msgs: list[str] = []
    cfg = RunConfig(sources=["fake"], db_path=fresh_db)
    result = run_pipeline(cfg, env={}, builders=_fake_builders(), emit=msgs.append)

    assert result.sources[0].source == "fake"
    assert result.sources[0].records == 2
    assert result.delta is not None
    assert result.delta.new >= 1
    assert any("analyzed" in m for m in msgs)


def test_run_pipeline_initializes_missing_db(tmp_path):
    # run/watch are automation entrypoints: no prior `afterlife init` needed.
    dbp = tmp_path / "brand-new.db"
    cfg = RunConfig(sources=["fake"], db_path=dbp)
    result = run_pipeline(cfg, env={}, builders=_fake_builders())
    assert dbp.exists()
    assert result.delta is not None
    assert result.delta.new >= 1


def test_run_pipeline_skips_unconfigured_source_but_still_analyzes(fresh_db):
    def boom(db_path, env):
        raise SourceNotConfigured("x", "X_TOKEN")

    cfg = RunConfig(sources=["x"], db_path=fresh_db)
    result = run_pipeline(cfg, env={}, builders={"x": boom})
    assert result.sources[0].error is not None
    assert "not configured" in result.sources[0].error
    assert result.delta is not None  # analysis still ran


def test_run_pipeline_records_scan_error(fresh_db):
    class Boom:
        source = "boom"

        def __init__(self, db_path):
            pass

        def run(self):
            raise RuntimeError("api down")

    cfg = RunConfig(sources=["boom"], db_path=fresh_db)
    result = run_pipeline(cfg, env={}, builders={"boom": lambda d, e: Boom(d)})
    assert "api down" in result.sources[0].error


def test_run_pipeline_unknown_source(fresh_db):
    cfg = RunConfig(sources=["nope"], db_path=fresh_db)
    result = run_pipeline(cfg, env={}, builders={})
    assert result.sources[0].error == "unknown source"


@respx.mock
def test_run_pipeline_notifies_on_new_finding(fresh_db):
    respx.post(WEBHOOK).mock(return_value=httpx.Response(200))
    cfg = RunConfig(
        sources=["fake"],
        db_path=fresh_db,
        notify=True,
        notify_config=NotifyConfig(webhook_url=WEBHOOK, min_severity=Severity.HIGH),
    )
    result = run_pipeline(cfg, env={}, builders=_fake_builders())
    assert result.notify_results.get("webhook") == "sent"


# ---------- watch loop ----------


def test_watch_runs_fixed_cycles_without_real_sleep(fresh_db):
    sleeps: list[float] = []
    cfg = RunConfig(sources=["fake"], db_path=fresh_db, interval_seconds=42)
    cycles = watch(
        cfg,
        env={},
        builders=_fake_builders(),
        sleep=sleeps.append,
        max_cycles=3,
    )
    assert cycles == 3
    # Sleeps happen between cycles, not after the last one.
    assert sleeps == [42, 42]


# ---------- detection + config ----------


def test_detect_sources_from_env():
    env = {"GITHUB_TOKEN": "t", "GITHUB_ORG": "o", "SLACK_TOKEN": "x"}
    found = detect_sources(env)
    assert "github" in found
    assert "slack" in found
    assert "aws" in found  # always buildable via the default chain
    assert "vault" not in found


def test_run_config_from_yaml(tmp_path):
    p = tmp_path / "afterlife.yml"
    p.write_text(
        "db_path: custom.db\n"
        "interval_seconds: 120\n"
        "sources: [aws, github]\n"
        "notify: false\n"
    )
    cfg = RunConfig.from_yaml(p, env={})
    assert cfg.sources == ["aws", "github"]
    assert cfg.interval_seconds == 120
    assert cfg.db_path == Path("custom.db")
    assert cfg.notify is False
    assert cfg.notify_config is None


def test_run_config_from_yaml_enables_notify_config(tmp_path):
    p = tmp_path / "afterlife.yml"
    p.write_text("sources: [aws]\nnotify: true\n")
    cfg = RunConfig.from_yaml(p, env={"AFTERLIFE_WEBHOOK_URL": WEBHOOK})
    assert cfg.notify is True
    assert cfg.notify_config is not None
    assert cfg.notify_config.webhook_url == WEBHOOK


def test_cloudtrail_is_opt_in_not_autodetected():
    # cloudtrail is a registered source (usable via --source) but excluded from
    # auto-detection because it is an enrichment over aws.
    assert "cloudtrail" in SOURCE_BUILDERS
    detected = detect_sources({})
    assert "aws" in detected
    assert "cloudtrail" not in detected
