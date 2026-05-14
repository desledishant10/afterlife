"""Scan-run tracking.

Every `afterlife scan ...` invocation (and the demo's in-process scans) is
wrapped in `record_run`. Each call writes a row to the `scan_runs` table with
the source, start time, end time, records collected, and any error message.

The dashboard's /scan-history page reads these rows back to show when each
source was last touched. The Overview page uses the most recent run per
source as a "last scan" indicator.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from afterlife import db


@contextmanager
def record_run(db_path: Path, source: str) -> Iterator[dict[str, Any]]:
    """Record a scan run, capturing duration, count, and exceptions.

    Usage:
        with record_run(db_path, "aws") as run:
            run["records_collected"] = AWSCollector(...).run()
    """
    started = datetime.now(timezone.utc)
    run_id: int | None = None
    with db.connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO scan_runs (source, started_at) VALUES (?, ?)",
            (source, started.isoformat()),
        )
        run_id = cur.lastrowid

    state: dict[str, Any] = {"records_collected": None, "error": None}
    try:
        yield state
    except Exception as e:
        state["error"] = str(e)
        raise
    finally:
        finished = datetime.now(timezone.utc).isoformat()
        with db.connect(db_path) as conn:
            conn.execute(
                """
                UPDATE scan_runs
                SET finished_at = ?, records_collected = ?, error = ?
                WHERE id = ?
                """,
                (
                    finished,
                    state.get("records_collected"),
                    state.get("error"),
                    run_id,
                ),
            )


def list_runs(db_path: Path, limit: int = 200) -> list[dict[str, Any]]:
    with db.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, source, started_at, finished_at,
                   records_collected, error
            FROM scan_runs
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def latest_per_source(db_path: Path) -> dict[str, dict[str, Any]]:
    """Map source -> most recent run row (used by Overview)."""
    with db.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT source, started_at, finished_at, records_collected, error
            FROM scan_runs
            WHERE finished_at IS NOT NULL
            GROUP BY source
            HAVING started_at = MAX(started_at)
            """
        ).fetchall()
    return {r["source"]: dict(r) for r in rows}
