from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import requests

from spamhaus_reporter.abuse_support import categories_for_candidate, make_comment
from spamhaus_reporter.abuseipdb import AbuseIPDBAmbiguousSubmissionError, AbuseIPDBClient
from spamhaus_reporter.config import Settings
from spamhaus_reporter.models import Candidate, Finding
from spamhaus_reporter import cli


def candidate(now: datetime) -> Candidate:
    return Candidate(
        ip="203.0.113.88",
        host="example.com",
        zone="example.com",
        first_seen=now - timedelta(seconds=2),
        last_seen=now,
        request_count=6,
        unique_paths=["/.env", "/.env.old", "/app/.env"],
        findings=[Finding("secrets_config", ["/.env", "/.env.old", "/app/.env"], 3)],
        status="READY",
        primary_category="secrets_config",
        confidence=96,
        reason="Observed sensitive configuration-file probing against example.com.",
        countries=["US"],
        asns=[64500],
        sources=["firewallcustom"],
        user_agents=["ua"],
    )


def settings(tmp_path) -> Settings:
    raw = {
        "spamhaus": {
            "resubmit_cooldown_hours": 24,
            "duplicate_backoff_hours": 24,
            "definitive_error_backoff_hours": 24,
            "max_post_attempts_per_24h": 25,
        },
        "abuseipdb": {
            "enabled": True,
            "resubmit_cooldown_hours": 24,
            "rate_limit_backoff_hours": 1,
            "definitive_error_backoff_hours": 24,
            "max_post_attempts_per_24h": 100,
            "category_map": {"secrets_config": [21]},
        },
        "classification": {
            "review_horizon_hours": 24,
            "auto_submit_categories": ["secrets_config"],
        },
        "storage": {
            "sqlite_path": "./db.sqlite3",
            "event_retention_hours": 48,
            "submission_attempt_retention_hours": 168,
            "unknown_attempt_retention_hours": 168,
            "claimed_stale_minutes": 30,
            "sending_stale_minutes": 30,
        },
    }
    return Settings(
        raw=raw,
        zones=[],
        spamhaus_api_key="s",
        abuseipdb_api_key="a",
        cloudflare_api_token="c",
        config_path=tmp_path / "config.yaml",
    )


class FakeAbuseIPDB:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}
        self.calls = 0

    def submit_ip_once(self, **kwargs):
        self.calls += 1
        if self.status == 200:
            return 200, {"data": {"ipAddress": kwargs["ip"], "abuseConfidenceScore": 50}}, self.headers
        if self.status == 429:
            return 429, {"errors": [{"detail": "same IP too soon"}]}, self.headers
        return self.status, {"errors": [{"detail": "failure"}]}, self.headers


def test_default_category_mapping_is_conservative():
    c = candidate(datetime.now(timezone.utc))
    assert categories_for_candidate(c, {}) == [21]
    c.primary_category = "webshell"
    assert categories_for_candidate(c, {}) == [15, 21]


def test_abuseipdb_comment_is_bounded_ascii():
    c = candidate(datetime.now(timezone.utc))
    c.host = "example.com\nINJECT"
    c.unique_paths = ["/" + "x" * 400 for _ in range(8)]
    comment = make_comment(c)
    assert len(comment.encode("utf-8")) <= 1024
    assert "\n" not in comment
    assert all(ord(ch) < 128 for ch in comment)


def test_abuseipdb_transport_error_is_not_retried(monkeypatch):
    client = AbuseIPDBClient(api_key="x")
    calls = {"n": 0}

    def post(*args, **kwargs):
        calls["n"] += 1
        raise requests.Timeout("boom")

    monkeypatch.setattr(client.session, "post", post)
    with pytest.raises(AbuseIPDBAmbiguousSubmissionError):
        client.submit_ip_once(
            ip="203.0.113.1",
            categories=[21],
            comment="observed probing",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
    assert calls["n"] == 1


def test_success_is_stored_and_not_posted_again_immediately(tmp_path, monkeypatch):
    s = settings(tmp_path)
    fake = FakeAbuseIPDB(200)
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(cli, "_abuseipdb", lambda _settings: fake)
    monkeypatch.setattr(cli, "recent_candidates", lambda _settings: [candidate(now)])

    assert cli.submit_abuseipdb_ready(s, actually_send=True) == 1
    assert fake.calls == 1
    assert cli._db(s).abuseipdb_latest_attempt("203.0.113.88")["state"] == "submitted"

    assert cli.submit_abuseipdb_ready(s, actually_send=True) == 0
    assert fake.calls == 1


def test_rate_limit_retry_after_is_persisted(tmp_path, monkeypatch):
    s = settings(tmp_path)
    fake = FakeAbuseIPDB(429, {"Retry-After": "1800"})
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(cli, "_abuseipdb", lambda _settings: fake)
    monkeypatch.setattr(cli, "recent_candidates", lambda _settings: [candidate(now)])

    assert cli.submit_abuseipdb_ready(s, actually_send=True) == 1
    row = cli._db(s).abuseipdb_latest_attempt("203.0.113.88")
    assert row["state"] == "rate_limited"
    cooldown = datetime.fromisoformat(row["cooldown_until"])
    # Configured minimum backoff is one hour, which is more conservative than 1800s.
    assert cooldown > datetime.now(timezone.utc) + timedelta(minutes=55)


def test_dry_run_never_calls_post(tmp_path, monkeypatch):
    s = settings(tmp_path)
    fake = FakeAbuseIPDB(200)
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(cli, "_abuseipdb", lambda _settings: fake)
    monkeypatch.setattr(cli, "recent_candidates", lambda _settings: [candidate(now)])

    assert cli.submit_abuseipdb_ready(s, actually_send=False) == 0
    assert fake.calls == 0


def test_abuseipdb_atomic_claim_blocks_second_instance(tmp_path):
    from spamhaus_reporter.db import Database

    db_path = tmp_path / "claims.sqlite3"
    db1 = Database(db_path)
    db2 = Database(db_path)
    now = datetime.now(timezone.utc)
    kwargs = dict(
        client_ip="203.0.113.99",
        categories=[21],
        comment="observed probing",
        category="wordpress",
        evidence_first_at=now.isoformat(),
        evidence_last_at=now.isoformat(),
    )
    assert db1.abuseipdb_claim_ip(**kwargs) is not None
    assert db2.abuseipdb_claim_ip(**kwargs) is None
