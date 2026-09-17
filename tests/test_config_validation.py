from pathlib import Path

import pytest

from spamhaus_reporter.config import ConfigError, load_settings


def write_cfg(tmp_path: Path, extra=""):
    text = f"""
zones:
  - name: example.com
    zone_id: 0123456789abcdef0123456789abcdef
cloudflare:
  poll_minutes: 10
  overlap_minutes: 3
  bootstrap_minutes: 60
  max_catchup_hours: 23
  max_events_per_query: 5000
  request_timeout_seconds: 30
  max_retries: 3
spamhaus:
  resubmit_cooldown_hours: 24
  duplicate_backoff_hours: 24
  definitive_error_backoff_hours: 24
  remote_reconcile_horizon_hours: 48
  max_post_attempts_per_24h: 25
  request_timeout_seconds: 30
  max_get_retries: 3
classification:
  aggregation_window_minutes: 10
  review_horizon_hours: 24
  auto_submit_categories: [wordpress]
  allowlist_cidrs: []
storage:
  event_retention_hours: 48
  submission_attempt_retention_hours: 168
  unknown_attempt_retention_hours: 168
  claimed_stale_minutes: 30
  sending_stale_minutes: 30
  log_max_bytes: 5000000
  log_backup_count: 3
{extra}
"""
    p = tmp_path / "config.yaml"
    p.write_text(text)
    (tmp_path / ".env").write_text("SPAMHAUS_API_KEY=x\nCLOUDFLARE_API_TOKEN=y\n")
    return p


def test_good_config_loads(tmp_path, monkeypatch):
    monkeypatch.delenv("SPAMHAUS_API_KEY", raising=False)
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    s = load_settings(write_cfg(tmp_path))
    assert s.zones[0].name == "example.com"


def test_event_retention_cannot_be_shorter_than_review_horizon(tmp_path, monkeypatch):
    monkeypatch.delenv("SPAMHAUS_API_KEY", raising=False)
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    p = write_cfg(tmp_path)
    text = p.read_text().replace("event_retention_hours: 48", "event_retention_hours: 12")
    p.write_text(text)
    with pytest.raises(ConfigError):
        load_settings(p)


def test_remote_reconcile_horizon_cannot_exceed_spamhaus_history_window(tmp_path, monkeypatch):
    monkeypatch.delenv("SPAMHAUS_API_KEY", raising=False)
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    p = write_cfg(tmp_path)
    text = p.read_text().replace("remote_reconcile_horizon_hours: 48", "remote_reconcile_horizon_hours: 721")
    p.write_text(text)
    with pytest.raises(ConfigError, match="<= 720"):
        load_settings(p)
