import sqlite3
from datetime import datetime, timedelta, timezone

from spamhaus_reporter.db import Database, parse_ts


def test_v10_recent_history_migrates_and_gets_cooldown(tmp_path):
    path = tmp_path / "x.sqlite3"
    now = datetime.now(timezone.utc)
    with sqlite3.connect(path) as con:
        con.executescript("""
        CREATE TABLE submission_ledger (
            client_ip TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            threat_type TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            http_status INTEGER,
            spamhaus_submission_id TEXT,
            response_json TEXT NOT NULL DEFAULT '{}',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            first_claimed_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            submitted_at TEXT,
            remote_submission_ts TEXT
        );
        """)
        t = (now - timedelta(hours=1)).isoformat()
        con.execute(
            """INSERT INTO submission_ledger(
               client_ip,state,threat_type,reason,category,http_status,
               spamhaus_submission_id,response_json,attempt_count,first_claimed_at,
               updated_at,submitted_at,remote_submission_ts)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("203.0.113.50","submitted","attack","old","wordpress",200,"id","{}",1,t,t,t,None),
        )
        con.commit()

    db = Database(path)
    row = db.latest_attempt("203.0.113.50")
    assert row is not None
    assert row["state"] == "submitted"
    assert row["evidence_last_at"] is not None
    assert row["cooldown_until"] is None
    assert db.backfill_missing_cooldowns(cooldown_hours=24, now=now) == 1
    row = db.latest_attempt("203.0.113.50")
    assert parse_ts(row["cooldown_until"]) > now
    ok, _ = db.can_submit(
        client_ip="203.0.113.50",
        evidence_last_at=(now + timedelta(minutes=1)).isoformat(),
        now=now,
    )
    assert not ok
