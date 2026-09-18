from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class ZoneConfig:
    name: str
    zone_id: str


@dataclass(frozen=True)
class Settings:
    raw: dict[str, Any]
    zones: list[ZoneConfig]
    spamhaus_api_key: str
    abuseipdb_api_key: str
    cloudflare_api_token: str
    config_path: Path


def get(raw: dict[str, Any], dotted: str, default: Any = None) -> Any:
    cur: Any = raw
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _positive_int(raw: dict[str, Any], dotted: str, default: int) -> int:
    try:
        value = int(get(raw, dotted, default))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{dotted} must be an integer") from exc
    if value <= 0:
        raise ConfigError(f"{dotted} must be > 0")
    return value


def _positive_float(raw: dict[str, Any], dotted: str, default: float) -> float:
    try:
        value = float(get(raw, dotted, default))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{dotted} must be a number") from exc
    if value <= 0:
        raise ConfigError(f"{dotted} must be > 0")
    return value


def load_settings(config_path: str | Path = "config.yaml") -> Settings:
    config_path = Path(config_path).resolve()
    if not config_path.exists():
        raise ConfigError(f"Config not found: {config_path}")
    load_dotenv(config_path.parent / ".env")

    with config_path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    if not isinstance(raw, dict):
        raise ConfigError("config.yaml root must be a mapping")

    zones_raw = raw.get("zones") or []
    if not isinstance(zones_raw, list):
        raise ConfigError("zones must be a list")
    zones: list[ZoneConfig] = []
    seen_names: set[str] = set()
    seen_ids: set[str] = set()
    for item in zones_raw:
        if not isinstance(item, dict):
            raise ConfigError("Every zone entry must be a mapping")
        name = str(item.get("name", "")).strip().lower().rstrip(".")
        zone_id = str(item.get("zone_id", "")).strip()
        if not name or "." not in name:
            raise ConfigError(f"Invalid zone name: {name!r}")
        if not zone_id or zone_id.startswith("REPLACE_"):
            raise ConfigError(f"Zone ID is not configured for {name}")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", zone_id):
            raise ConfigError(f"Cloudflare Zone ID for {name} must be a 32-character hexadecimal ID")
        if name in seen_names:
            raise ConfigError(f"Duplicate zone name: {name}")
        if zone_id in seen_ids:
            raise ConfigError(f"Duplicate Cloudflare Zone ID: {zone_id}")
        seen_names.add(name)
        seen_ids.add(zone_id)
        zones.append(ZoneConfig(name=name, zone_id=zone_id))
    if not zones:
        raise ConfigError("At least one zone must be configured")

    spamhaus_key = os.getenv("SPAMHAUS_API_KEY", "").strip()
    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    cf_token = os.getenv("CLOUDFLARE_API_TOKEN", "").strip()
    if not spamhaus_key or spamhaus_key.lower() == "replace_me":
        raise ConfigError("SPAMHAUS_API_KEY is missing from environment/.env")
    if not cf_token or cf_token.lower() == "replace_me":
        raise ConfigError("CLOUDFLARE_API_TOKEN is missing from environment/.env")

    abuse_enabled = get(raw, "abuseipdb.enabled", False)
    if not isinstance(abuse_enabled, bool):
        raise ConfigError("abuseipdb.enabled must be true or false, not a string")
    if abuse_enabled and (not abuseipdb_key or abuseipdb_key.lower() == "replace_me"):
        raise ConfigError("ABUSEIPDB_API_KEY is missing from environment/.env while abuseipdb.enabled is true")

    _positive_int(raw, "cloudflare.poll_minutes", 10)
    _positive_int(raw, "cloudflare.overlap_minutes", 3)
    _positive_int(raw, "cloudflare.bootstrap_minutes", 60)
    _positive_int(raw, "cloudflare.max_catchup_hours", 23)
    max_events = _positive_int(raw, "cloudflare.max_events_per_query", 5000)
    if max_events > 10000:
        raise ConfigError("cloudflare.max_events_per_query should not exceed 10000")
    _positive_int(raw, "cloudflare.request_timeout_seconds", 30)
    _positive_int(raw, "cloudflare.max_retries", 3)

    horizon = _positive_int(raw, "classification.review_horizon_hours", 24)
    _positive_int(raw, "classification.aggregation_window_minutes", 10)
    _positive_int(raw, "classification.directory_enum_min_unique_paths", 30)
    _positive_int(raw, "classification.directory_enum_min_total_requests", 40)
    _positive_int(raw, "classification.directory_enum_max_window_seconds", 600)
    cooldown = _positive_float(raw, "spamhaus.resubmit_cooldown_hours", 24)
    duplicate_backoff = _positive_float(raw, "spamhaus.duplicate_backoff_hours", 24)
    error_backoff = _positive_float(raw, "spamhaus.definitive_error_backoff_hours", 24)
    remote_horizon = _positive_float(raw, "spamhaus.remote_reconcile_horizon_hours", 48)
    # Spamhaus documents submission history as limited to the last 30 days.
    # Reject larger reconciliation horizons so operators do not get a false
    # sense of duplicate protection from history the API cannot provide.
    if remote_horizon > 24 * 30:
        raise ConfigError("spamhaus.remote_reconcile_horizon_hours must be <= 720 (30 days)")
    page_items = _positive_int(raw, "spamhaus.remote_history_page_items", 1000)
    if page_items > 10000:
        raise ConfigError("spamhaus.remote_history_page_items must be <= 10000")
    _positive_int(raw, "spamhaus.remote_history_max_pages", 100)
    _positive_int(raw, "spamhaus.max_post_attempts_per_24h", 25)
    _positive_int(raw, "spamhaus.request_timeout_seconds", 30)
    _positive_int(raw, "spamhaus.max_get_retries", 3)

    abuse_cooldown = _positive_float(raw, "abuseipdb.resubmit_cooldown_hours", 24)
    if abuse_cooldown * 60 < 15:
        raise ConfigError("abuseipdb.resubmit_cooldown_hours must be at least 0.25 (15 minutes)")
    _positive_float(raw, "abuseipdb.rate_limit_backoff_hours", 1)
    _positive_float(raw, "abuseipdb.definitive_error_backoff_hours", 24)
    _positive_int(raw, "abuseipdb.max_post_attempts_per_24h", 100)
    _positive_int(raw, "abuseipdb.request_timeout_seconds", 30)
    _positive_int(raw, "abuseipdb.max_get_retries", 3)

    category_map = get(raw, "abuseipdb.category_map", {}) or {}
    if not isinstance(category_map, dict):
        raise ConfigError("abuseipdb.category_map must be a mapping")
    for category, ids in category_map.items():
        if not isinstance(ids, list) or not ids:
            raise ConfigError(f"abuseipdb.category_map.{category} must be a non-empty list")
        for cid in ids:
            try:
                value = int(cid)
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"Invalid AbuseIPDB category ID {cid!r} for {category}") from exc
            if value < 1 or value > 23:
                raise ConfigError(f"AbuseIPDB category ID must be between 1 and 23: {value}")

    event_retention = _positive_int(raw, "storage.event_retention_hours", 36)
    attempts_retention = _positive_int(raw, "storage.submission_attempt_retention_hours", 72)
    unknown_retention = _positive_int(raw, "storage.unknown_attempt_retention_hours", 72)
    _positive_int(raw, "storage.claimed_stale_minutes", 30)
    _positive_int(raw, "storage.sending_stale_minutes", 30)
    _positive_int(raw, "storage.log_max_bytes", 5_000_000)
    _positive_int(raw, "storage.log_backup_count", 3)

    if event_retention < horizon:
        raise ConfigError("storage.event_retention_hours must be >= classification.review_horizon_hours")
    abuse_rate_backoff = float(get(raw, "abuseipdb.rate_limit_backoff_hours", 1))
    abuse_error_backoff = float(get(raw, "abuseipdb.definitive_error_backoff_hours", 24))
    if attempts_retention < max(24.0, cooldown, duplicate_backoff, error_backoff, abuse_cooldown, abuse_rate_backoff, abuse_error_backoff):
        raise ConfigError(
            "storage.submission_attempt_retention_hours must be >= the largest provider cooldown/backoff"
        )
    if unknown_retention < max(cooldown, abuse_cooldown):
        raise ConfigError("storage.unknown_attempt_retention_hours must be >= the largest provider resubmit cooldown")
    if remote_horizon < cooldown:
        raise ConfigError("spamhaus.remote_reconcile_horizon_hours must be >= resubmit_cooldown_hours")

    auto_enabled = get(raw, "classification.auto_submit_enabled", False)
    if not isinstance(auto_enabled, bool):
        raise ConfigError("classification.auto_submit_enabled must be true or false, not a string")

    actions = get(raw, "cloudflare.actions", ["block"]) or []
    if not isinstance(actions, list) or not actions or not all(isinstance(x, str) and x.strip() for x in actions):
        raise ConfigError("cloudflare.actions must be a non-empty list of action strings")

    thresholds = get(raw, "classification.thresholds", {}) or {}
    if not isinstance(thresholds, dict):
        raise ConfigError("classification.thresholds must be a mapping")
    for name, value in thresholds.items():
        try:
            ivalue = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"classification.thresholds.{name} must be an integer") from exc
        if ivalue <= 0:
            raise ConfigError(f"classification.thresholds.{name} must be > 0")

    allow_asns = get(raw, "classification.allowlist_asns", []) or []
    if not isinstance(allow_asns, list):
        raise ConfigError("classification.allowlist_asns must be a list")
    for asn in allow_asns:
        try:
            if int(asn) <= 0:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"Invalid allowlist ASN: {asn}") from exc

    ua_regexes = get(raw, "classification.allowlist_user_agent_regexes", []) or []
    if not isinstance(ua_regexes, list):
        raise ConfigError("classification.allowlist_user_agent_regexes must be a list")
    for pattern in ua_regexes:
        try:
            re.compile(str(pattern))
        except re.error as exc:
            raise ConfigError(f"Invalid allowlist user-agent regex: {pattern}") from exc

    cidrs = get(raw, "classification.allowlist_cidrs", []) or []
    if not isinstance(cidrs, list):
        raise ConfigError("classification.allowlist_cidrs must be a list")
    for cidr in cidrs:
        try:
            ipaddress.ip_network(str(cidr), strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid allowlist CIDR: {cidr}") from exc

    categories = get(raw, "classification.auto_submit_categories", []) or []
    if not isinstance(categories, list) or not categories:
        raise ConfigError("classification.auto_submit_categories must be a non-empty list")
    known_categories = {
        "wordpress", "secrets_config", "source_control", "db_admin", "backup_dump",
        "cloud_credentials", "api_debug", "webshell", "traversal_lfi", "admin_login",
        "generic_scan", "directory_enum",
    }
    unknown_categories = sorted({str(x) for x in categories} - known_categories)
    if unknown_categories:
        raise ConfigError(f"Unknown auto-submit categories: {', '.join(unknown_categories)}")
    unknown_abuse_map = sorted({str(x) for x in category_map} - known_categories)
    if unknown_abuse_map:
        raise ConfigError(f"Unknown abuseipdb.category_map categories: {', '.join(unknown_abuse_map)}")

    return Settings(
        raw=raw,
        zones=zones,
        spamhaus_api_key=spamhaus_key,
        abuseipdb_api_key=abuseipdb_key,
        cloudflare_api_token=cf_token,
        config_path=config_path,
    )
