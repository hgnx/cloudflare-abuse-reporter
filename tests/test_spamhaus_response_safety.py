import requests
import pytest

from spamhaus_reporter.spamhaus import SpamhausAmbiguousSubmissionError, SpamhausClient


class FailingSession:
    def __init__(self):
        self.calls = 0
        self.headers = {}
    def post(self, *args, **kwargs):
        self.calls += 1
        raise requests.Timeout("timeout")


def test_post_is_never_retried_after_ambiguous_failure():
    c = SpamhausClient("key", "https://example.invalid", max_get_retries=9)
    fake = FailingSession()
    c.session = fake
    with pytest.raises(SpamhausAmbiguousSubmissionError):
        c.submit_ip_once("203.0.113.20", "attack", "reason")
    assert fake.calls == 1


def test_reason_byte_limit_is_enforced():
    c = SpamhausClient("key", "https://example.invalid")
    with pytest.raises(ValueError):
        c.submit_ip_once("203.0.113.20", "attack", "가" * 100)
