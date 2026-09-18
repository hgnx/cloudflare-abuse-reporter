from datetime import datetime, timezone

from spamhaus_reporter.config import Settings
from spamhaus_reporter.models import Candidate, Finding
from spamhaus_reporter import cli


def candidate(now):
    return Candidate(
        ip="203.0.113.77",
        host="example.com",
        zone="example.com",
        first_seen=now,
        last_seen=now,
        request_count=4,
        unique_paths=["/xmlrpc.php", "/a/wp-includes/x", "/b/wp-includes/x", "/wp-login.php"],
        findings=[Finding("wordpress", ["/xmlrpc.php"], 4)],
        status="READY",
        primary_category="wordpress",
        confidence=95,
        reason="Observed WordPress/CMS reconnaissance against example.com. 4 blocked requests.",
        countries=["US"],
        asns=[64500],
        sources=["firewallcustom"],
        user_agents=["ua"],
    )


class FakeSpamhaus:
    def __init__(self):
        self.calls = 0
    def resolve_threat_type(self, preferred):
        return "attack"
    def submit_ip_once(self, ip, threat_type, reason):
        self.calls += 1
        return 208, {"status": 208, "message": "submission already reported"}


def test_208_is_stored_and_not_posted_again_immediately(tmp_path, monkeypatch):
    raw = {
        "spamhaus": {
            "preferred_threat_type": "attack",
            "resubmit_cooldown_hours": 24,
            "duplicate_backoff_hours": 24,
            "definitive_error_backoff_hours": 24,
            "max_post_attempts_per_24h": 25,
        },
        "classification": {
            "review_horizon_hours": 24,
            "auto_submit_categories": ["wordpress"],
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
    settings = Settings(raw=raw, zones=[], spamhaus_api_key="x", abuseipdb_api_key="z", cloudflare_api_token="y", config_path=tmp_path / "config.yaml")
    fake = FakeSpamhaus()
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(cli, "_spamhaus", lambda _settings: fake)
    monkeypatch.setattr(cli, "recent_candidates", lambda _settings: [candidate(now)])

    assert cli.submit_ready(settings, actually_send=True, reconcile=False) == 1
    assert fake.calls == 1
    assert cli._db(settings).latest_attempt("203.0.113.77")["state"] == "duplicate"

    # Second execution sees the local cooldown and does not call Spamhaus again.
    assert cli.submit_ready(settings, actually_send=True, reconcile=False) == 0
    assert fake.calls == 1


def test_best_ready_per_ip_prefers_newest_evidence_watermark():
    older = candidate(datetime(2026, 9, 17, 0, 0, tzinfo=timezone.utc))
    newer = candidate(datetime(2026, 9, 17, 1, 0, tzinfo=timezone.utc))
    older.confidence = 99
    newer.confidence = 80

    selected = cli._best_ready_per_ip([older, newer], {"wordpress"})
    assert len(selected) == 1
    assert selected[0].last_seen == newer.last_seen
