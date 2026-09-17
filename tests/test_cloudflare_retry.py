from datetime import datetime, timezone

import requests

from spamhaus_reporter.cloudflare import CloudflareClient


class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.headers = headers or {}
        self.text = "x"
    def json(self):
        return self._body


class FakeSession:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0
        self.headers = {}
    def post(self, *args, **kwargs):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_read_query_retries_transport_failure(monkeypatch):
    c = CloudflareClient("key", "https://example.invalid", max_retries=2)
    fake = FakeSession([
        requests.Timeout("timeout"),
        FakeResponse(200, {"data": {"viewer": {"zones": [{"firewallEventsAdaptive": []}]}}}),
    ])
    c.session = fake
    monkeypatch.setattr("spamhaus_reporter.cloudflare.time.sleep", lambda _: None)
    rows = c.fetch_events(
        zone_name="example.com", zone_id="z",
        start=datetime(2026, 9, 17, 0, 0, tzinfo=timezone.utc),
        end=datetime(2026, 9, 17, 0, 1, tzinfo=timezone.utc),
        limit=5000, actions=["block"],
    )
    assert rows == []
    assert fake.calls == 2
