from datetime import datetime, timedelta, timezone

from spamhaus_reporter.db import Database

UTC = timezone.utc
T0 = datetime(2026, 9, 17, 0, 0, tzinfo=UTC)


def claim(db, ip="203.0.113.10", *, first=T0, last=None, now=T0):
    last = last or first
    return db.claim_ip(
        client_ip=ip,
        threat_type="attack",
        reason="reason",
        category="wordpress",
        evidence_first_at=first.isoformat(),
        evidence_last_at=last.isoformat(),
        cooldown_hours=24,
        now=now,
    )


def test_atomic_claim_blocks_second_process(tmp_path):
    path = tmp_path / "x.sqlite3"
    a = Database(path)
    b = Database(path)
    token = claim(a)
    assert token
    assert claim(b) is None


def test_success_blocks_within_cooldown(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    token = claim(db)
    assert token
    assert db.mark_sending(token, cooldown_hours=24, now=T0)
    db.finalize_submission(
        claim_token=token, state="submitted", http_status=200,
        submission_id="id1", response={}, cooldown_hours=24, now=T0,
    )
    ok, why = db.can_submit(
        client_ip="203.0.113.10",
        evidence_last_at=(T0 + timedelta(hours=1)).isoformat(),
        now=T0 + timedelta(hours=23, minutes=59),
    )
    assert not ok
    assert "cooldown" in why


def test_after_cooldown_requires_new_evidence(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    token = claim(db)
    assert db.mark_sending(token, cooldown_hours=24, now=T0)
    db.finalize_submission(
        claim_token=token, state="submitted", http_status=200,
        submission_id="id1", response={}, cooldown_hours=24, now=T0,
    )
    # Same evidence is never recycled just because the 24h timer elapsed.
    ok, why = db.can_submit(
        client_ip="203.0.113.10", evidence_last_at=T0.isoformat(),
        now=T0 + timedelta(hours=24, seconds=1),
    )
    assert not ok
    assert "no evidence newer" in why
    # A later attack is eligible after cooldown.
    ok, _ = db.can_submit(
        client_ip="203.0.113.10",
        evidence_last_at=(T0 + timedelta(hours=2)).isoformat(),
        now=T0 + timedelta(hours=24, seconds=1),
    )
    assert ok


def test_unknown_timeout_is_not_retried_inside_cooldown(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    token = claim(db)
    assert db.mark_sending(token, cooldown_hours=24, now=T0)
    db.finalize_submission(
        claim_token=token, state="unknown", http_status=None,
        submission_id=None, response={"error": "timeout"}, cooldown_hours=24, now=T0,
    )
    assert claim(
        db,
        first=T0 + timedelta(hours=1),
        last=T0 + timedelta(hours=1),
        now=T0 + timedelta(hours=2),
    ) is None


def test_abandoned_pre_send_can_reuse_same_evidence(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    token = claim(db)
    assert token
    recovered_claimed, recovered_sending = db.recover_stale_attempts(
        claimed_stale_minutes=30,
        sending_stale_minutes=30,
        cooldown_hours=24,
        now=T0 + timedelta(minutes=31),
    )
    assert (recovered_claimed, recovered_sending) == (1, 0)
    token2 = claim(db, now=T0 + timedelta(minutes=31))
    assert token2 and token2 != token


def test_stale_sending_becomes_unknown(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    token = claim(db)
    assert db.mark_sending(token, cooldown_hours=24, now=T0)
    recovered_claimed, recovered_sending = db.recover_stale_attempts(
        claimed_stale_minutes=30,
        sending_stale_minutes=30,
        cooldown_hours=24,
        now=T0 + timedelta(minutes=31),
    )
    assert (recovered_claimed, recovered_sending) == (0, 1)
    assert db.latest_attempt("203.0.113.10")["state"] == "unknown"


def test_post_attempt_cap_counts_sending_even_if_unknown(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    token = claim(db)
    assert db.mark_sending(token, cooldown_hours=24, now=T0)
    assert db.count_post_attempts_since((T0 - timedelta(minutes=1)).isoformat()) == 1


def test_terminal_attempts_are_pruned_but_recent_remain(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    token = claim(db)
    assert db.mark_sending(token, cooldown_hours=24, now=T0)
    db.finalize_submission(
        claim_token=token, state="submitted", http_status=200,
        submission_id="id", response={}, cooldown_hours=24, now=T0,
    )
    assert db.prune_attempts_before((T0 + timedelta(days=1)).isoformat()) == 1
    assert db.latest_attempt("203.0.113.10") is None


def test_post_attempt_cap_does_not_count_remote_history_rows(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    remote = {
        "submission_type": "ip",
        "source": {"object": "203.0.113.200"},
        "threat_type": "attack",
        "reason": "remote",
        "id": "remote-id",
        "submission_ts": T0.isoformat().replace("+00:00", "Z"),
    }
    assert db.reconcile_remote_submission(
        remote,
        cooldown_hours=24,
        import_cutoff=T0 - timedelta(hours=48),
    )
    assert db.count_post_attempts_since((T0 - timedelta(minutes=1)).isoformat()) == 0


def test_abandoned_pre_send_cannot_mask_older_submission_cooldown(tmp_path):
    db = Database(tmp_path / "x.sqlite3")

    # Seed an older definitive submission with an active cooldown.
    first = claim(db, ip="203.0.113.201", now=T0)
    assert first
    assert db.mark_sending(first, cooldown_hours=24, now=T0)
    db.finalize_submission(
        claim_token=first, state="submitted", http_status=200,
        submission_id="id", response={}, cooldown_hours=24, now=T0,
    )

    # Inject a newer abandoned pre-send row to model a legacy/race condition.
    with db.immediate() as con:
        con.execute(
            """
            INSERT INTO submission_attempts(
                claim_token, client_ip, state, threat_type, reason, category,
                evidence_first_at, evidence_last_at, claimed_at, finished_at, updated_at
            ) VALUES (?, ?, 'abandoned_pre_send', 'attack', 'r', 'wordpress', ?, ?, ?, ?, ?)
            """,
            (
                "abandoned-mask-test", "203.0.113.201",
                (T0 + timedelta(hours=1)).isoformat(),
                (T0 + timedelta(hours=1)).isoformat(),
                (T0 + timedelta(hours=1)).isoformat(),
                (T0 + timedelta(hours=1)).isoformat(),
                (T0 + timedelta(hours=1)).isoformat(),
            ),
        )

    ok, why = db.can_submit(
        client_ip="203.0.113.201",
        evidence_last_at=(T0 + timedelta(hours=2)).isoformat(),
        now=T0 + timedelta(hours=2),
    )
    assert not ok
    assert "cooldown" in why
    assert claim(
        db,
        ip="203.0.113.201",
        first=T0 + timedelta(hours=2),
        last=T0 + timedelta(hours=2),
        now=T0 + timedelta(hours=2),
    ) is None
