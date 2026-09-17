from datetime import datetime, timedelta, timezone

from spamhaus_reporter.db import Database

UTC = timezone.utc
T0 = datetime(2026, 9, 17, 0, 0, tzinfo=UTC)


def item(ip, ts=T0):
    return {
        "submission_type": "ip",
        "source": {"object": ip},
        "threat_type": "attack",
        "reason": "remote",
        "id": "abc",
        "submission_ts": ts.isoformat().replace("+00:00", "Z"),
    }


def test_recent_remote_submission_blocks_until_cooldown(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    assert db.reconcile_remote_submission(
        item("203.0.113.12"), cooldown_hours=24,
        import_cutoff=T0 - timedelta(hours=48),
    )
    row = db.latest_attempt("203.0.113.12")
    assert row["state"] == "remote_existing"
    ok, _ = db.can_submit(
        client_ip="203.0.113.12",
        evidence_last_at=(T0 + timedelta(hours=1)).isoformat(),
        now=T0 + timedelta(hours=23),
    )
    assert not ok
    ok, _ = db.can_submit(
        client_ip="203.0.113.12",
        evidence_last_at=(T0 + timedelta(hours=1)).isoformat(),
        now=T0 + timedelta(hours=24, seconds=1),
    )
    assert ok


def test_old_remote_item_is_not_stored(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    assert not db.reconcile_remote_submission(
        item("203.0.113.13", T0 - timedelta(days=10)),
        cooldown_hours=24,
        import_cutoff=T0 - timedelta(hours=48),
    )
    assert db.latest_attempt("203.0.113.13") is None


def test_remote_reconciles_unknown_local_post(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    token = db.claim_ip(
        client_ip="203.0.113.14", threat_type="attack", reason="r", category="wordpress",
        evidence_first_at=T0.isoformat(), evidence_last_at=T0.isoformat(),
        cooldown_hours=24, now=T0,
    )
    assert token
    assert db.mark_sending(token, cooldown_hours=24, now=T0)
    db.finalize_submission(
        claim_token=token, state="unknown", http_status=None,
        submission_id=None, response={"error": "timeout"}, cooldown_hours=24, now=T0,
    )
    assert db.reconcile_remote_submission(
        item("203.0.113.14", T0 + timedelta(seconds=5)),
        cooldown_hours=24, import_cutoff=T0 - timedelta(hours=48),
    )
    row = db.latest_attempt("203.0.113.14")
    assert row["state"] == "remote_existing"
    assert row["spamhaus_submission_id"] == "abc"


def test_much_later_remote_submission_does_not_rewrite_old_unknown(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    token = db.claim_ip(
        client_ip="203.0.113.15", threat_type="attack", reason="r", category="wordpress",
        evidence_first_at=T0.isoformat(), evidence_last_at=T0.isoformat(),
        cooldown_hours=24, now=T0,
    )
    assert token
    assert db.mark_sending(token, cooldown_hours=24, now=T0)
    db.finalize_submission(
        claim_token=token, state="unknown", http_status=None,
        submission_id=None, response={"error": "timeout"}, cooldown_hours=24, now=T0,
    )

    later = T0 + timedelta(hours=30)
    assert db.reconcile_remote_submission(
        item("203.0.113.15", later),
        cooldown_hours=24,
        import_cutoff=T0 - timedelta(hours=48),
    )

    rows = db.attempts(limit=10)
    same_ip = [r for r in rows if r["client_ip"] == "203.0.113.15"]
    assert len(same_ip) == 2
    assert same_ip[0]["state"] == "remote_existing"
    assert same_ip[1]["state"] == "unknown"


def test_abandoned_pre_send_does_not_mask_older_remote_cooldown(tmp_path):
    db = Database(tmp_path / "x.sqlite3")

    # A local claim happens after a remote submission would have occurred, but
    # crashes before POST and is later abandoned.
    local_claim_time = T0 + timedelta(hours=1)
    token = db.claim_ip(
        client_ip="203.0.113.16", threat_type="attack", reason="r", category="wordpress",
        evidence_first_at=local_claim_time.isoformat(),
        evidence_last_at=local_claim_time.isoformat(),
        cooldown_hours=24, now=local_claim_time,
    )
    assert token
    recovered_claimed, recovered_sending = db.recover_stale_attempts(
        claimed_stale_minutes=30,
        sending_stale_minutes=30,
        cooldown_hours=24,
        now=local_claim_time + timedelta(minutes=31),
    )
    assert (recovered_claimed, recovered_sending) == (1, 0)

    # Remote history later reveals a submission from T0. It must still be
    # imported even though the abandoned local claim has a later claimed_at.
    assert db.reconcile_remote_submission(
        item("203.0.113.16", T0),
        cooldown_hours=24,
        import_cutoff=T0 - timedelta(hours=48),
    )

    ok, why = db.can_submit(
        client_ip="203.0.113.16",
        evidence_last_at=(T0 + timedelta(hours=2)).isoformat(),
        now=T0 + timedelta(hours=2),
    )
    assert not ok
    assert "cooldown" in why
