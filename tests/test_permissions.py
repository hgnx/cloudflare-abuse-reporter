import logging
import os

from spamhaus_reporter import cli
from spamhaus_reporter.config import Settings


def settings_for(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("zones: []\n", encoding="utf-8")
    return Settings(
        raw={},
        zones=[],
        spamhaus_api_key="x",
        cloudflare_api_token="y",
        config_path=config,
    )


def warning_messages(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


def test_env_0600_does_not_warn(tmp_path, caplog):
    env = tmp_path / ".env"
    env.write_text("SPAMHAUS_API_KEY=x\n", encoding="utf-8")
    os.chmod(env, 0o600)
    with caplog.at_level(logging.WARNING):
        cli._warn_permissions(settings_for(tmp_path))
    assert not warning_messages(caplog)


def test_env_0640_does_not_warn(tmp_path, caplog):
    env = tmp_path / ".env"
    env.write_text("SPAMHAUS_API_KEY=x\n", encoding="utf-8")
    os.chmod(env, 0o640)
    with caplog.at_level(logging.WARNING):
        cli._warn_permissions(settings_for(tmp_path))
    assert not warning_messages(caplog)


def test_env_0644_warns(tmp_path, caplog):
    env = tmp_path / ".env"
    env.write_text("SPAMHAUS_API_KEY=x\n", encoding="utf-8")
    os.chmod(env, 0o644)
    with caplog.at_level(logging.WARNING):
        cli._warn_permissions(settings_for(tmp_path))
    assert any("expected 0600 or restricted 0640" in m for m in warning_messages(caplog))


def test_env_0660_warns(tmp_path, caplog):
    env = tmp_path / ".env"
    env.write_text("SPAMHAUS_API_KEY=x\n", encoding="utf-8")
    os.chmod(env, 0o660)
    with caplog.at_level(logging.WARNING):
        cli._warn_permissions(settings_for(tmp_path))
    assert any("expected 0600 or restricted 0640" in m for m in warning_messages(caplog))
