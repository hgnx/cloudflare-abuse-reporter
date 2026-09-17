from spamhaus_reporter.classifier import make_reason


def test_reason_is_ascii_and_control_safe():
    reason = make_reason(
        host="evil.example\nINJECT\x1b[31m한글",
        category="secrets_config",
        paths=["/.env\nfoo", "/서비스-account.json"],
        unique_count=2,
        request_count=4,
    )
    assert "\n" not in reason
    assert "\x1b" not in reason
    assert reason.isascii()
    assert len(reason) <= 255
    assert len(reason.encode()) <= 255
