from datetime import datetime, timezone

from spamhaus_reporter.db import Database
from spamhaus_reporter.models import Event


def test_event_dedup(tmp_path):
    db = Database(tmp_path / "x.sqlite3")
    e = Event(
        zone="example.com",
        zone_id="zone",
        host="www.example.com",
        client_ip="203.0.113.1",
        path="/.env",
        query="",
        action="block",
        source="firewallcustom",
        user_agent="ua",
        country="US",
        asn=64500,
        observed_at=datetime(2026, 9, 17, tzinfo=timezone.utc),
    )
    assert db.insert_events([e]) == (1, 0)
    assert db.insert_events([e]) == (0, 1)
