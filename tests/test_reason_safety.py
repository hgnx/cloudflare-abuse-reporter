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


def test_spamhaus_reason_redacts_target_host_by_default():
    reason = make_reason(
        host="private.example.com",
        category="wordpress",
        paths=["/wp-login.php", "/xmlrpc.php"],
        unique_count=2,
        request_count=4,
    )
    assert "private.example.com" not in reason
    assert "a web application under my control" in reason


def test_spamhaus_reason_can_include_target_host_when_opted_in():
    reason = make_reason(
        host="public.example.com",
        category="wordpress",
        paths=["/wp-login.php", "/xmlrpc.php"],
        unique_count=2,
        request_count=4,
        include_target_host=True,
    )
    assert "public.example.com" in reason
