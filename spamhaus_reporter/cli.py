from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable

from .classifier import Candidate, candidates_from_rows
from .abuse_support import categories_for_candidate, make_comment
from .abuseipdb import AbuseIPDBAmbiguousSubmissionError, AbuseIPDBClient, AbuseIPDBError
from .cloudflare import CloudflareClient, CloudflareError
from .config import ConfigError, Settings, get, load_settings
from .db import Database, parse_ts
from .lock import AlreadyRunningError, ProcessLock
from .spamhaus import SpamhausAmbiguousSubmissionError, SpamhausClient, SpamhausError

LOG = logging.getLogger("spamhaus_reporter")


def _path(settings: Settings, dotted: str, default: str) -> Path:
    p = Path(str(get(settings.raw, dotted, default)))
    return p if p.is_absolute() else settings.config_path.parent / p


def _setup_logging(settings: Settings) -> None:
    log_path = _path(settings, "storage.log_path", "./spamhaus_reporter.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    try:
        handlers.append(
            RotatingFileHandler(
                log_path,
                maxBytes=int(get(settings.raw, "storage.log_max_bytes", 5_000_000)),
                backupCount=int(get(settings.raw, "storage.log_backup_count", 3)),
                encoding="utf-8",
            )
        )
        try:
            os.chmod(log_path, 0o600)
        except OSError:
            pass
    except OSError:
        pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
        force=True,
    )


def _db(settings: Settings) -> Database:
    return Database(_path(settings, "storage.sqlite_path", "./spamhaus_reporter.sqlite3"))


def _cf(settings: Settings) -> CloudflareClient:
    return CloudflareClient(
        token=settings.cloudflare_api_token,
        graphql_url=str(
            get(
                settings.raw,
                "cloudflare.graphql_url",
                "https://api.cloudflare.com/client/v4/graphql",
            )
        ),
        timeout=int(get(settings.raw, "cloudflare.request_timeout_seconds", 30)),
        max_retries=int(get(settings.raw, "cloudflare.max_retries", 3)),
    )


def _spamhaus(settings: Settings) -> SpamhausClient:
    return SpamhausClient(
        api_key=settings.spamhaus_api_key,
        base_url=str(
            get(
                settings.raw,
                "spamhaus.base_url",
                "https://submit.spamhaus.org/portal/api/v1",
            )
        ),
        timeout=int(get(settings.raw, "spamhaus.request_timeout_seconds", 30)),
        max_get_retries=int(get(settings.raw, "spamhaus.max_get_retries", 3)),
    )


def _abuseipdb(settings: Settings) -> AbuseIPDBClient:
    return AbuseIPDBClient(
        api_key=settings.abuseipdb_api_key,
        base_url=str(
            get(
                settings.raw,
                "abuseipdb.base_url",
                "https://api.abuseipdb.com/api/v2",
            )
        ),
        timeout=int(get(settings.raw, "abuseipdb.request_timeout_seconds", 30)),
        max_get_retries=int(get(settings.raw, "abuseipdb.max_get_retries", 3)),
    )


def _abuse_enabled(settings: Settings) -> bool:
    return bool(get(settings.raw, "abuseipdb.enabled", False))


def _cooldown(settings: Settings) -> float:
    return float(get(settings.raw, "spamhaus.resubmit_cooldown_hours", 24))


def _abuse_cooldown(settings: Settings) -> float:
    return float(get(settings.raw, "abuseipdb.resubmit_cooldown_hours", 24))


def maintenance(settings: Settings, *, compact: bool = False) -> None:
    db = _db(settings)
    now = datetime.now(timezone.utc)
    backfilled = db.backfill_missing_cooldowns(cooldown_hours=_cooldown(settings), now=now)
    recovered_claimed, recovered_sending = db.recover_stale_attempts(
        claimed_stale_minutes=int(get(settings.raw, "storage.claimed_stale_minutes", 30)),
        sending_stale_minutes=int(get(settings.raw, "storage.sending_stale_minutes", 30)),
        cooldown_hours=_cooldown(settings),
        now=now,
    )
    abuse_recovered_claimed, abuse_recovered_sending = db.abuseipdb_recover_stale_attempts(
        claimed_stale_minutes=int(get(settings.raw, "storage.claimed_stale_minutes", 30)),
        sending_stale_minutes=int(get(settings.raw, "storage.sending_stale_minutes", 30)),
        cooldown_hours=_abuse_cooldown(settings),
        now=now,
    )
    event_cutoff = now - timedelta(
        hours=int(get(settings.raw, "storage.event_retention_hours", 36))
    )
    attempt_cutoff = now - timedelta(
        hours=int(get(settings.raw, "storage.submission_attempt_retention_hours", 72))
    )
    unknown_cutoff = now - timedelta(
        hours=int(get(settings.raw, "storage.unknown_attempt_retention_hours", 72))
    )
    pruned_events = db.prune_events_before(event_cutoff.isoformat())
    pruned_attempts = db.prune_attempts_before(attempt_cutoff.isoformat())
    pruned_unknown = db.prune_unknown_before(unknown_cutoff.isoformat())
    pruned_abuse_attempts = db.prune_abuseipdb_attempts_before(attempt_cutoff.isoformat())
    pruned_abuse_unknown = db.prune_abuseipdb_unknown_before(unknown_cutoff.isoformat())
    db.maintenance_checkpoint()
    if compact:
        db.compact()
    if any((
        backfilled, recovered_claimed, recovered_sending, abuse_recovered_claimed,
        abuse_recovered_sending, pruned_events, pruned_attempts, pruned_unknown,
        pruned_abuse_attempts, pruned_abuse_unknown,
    )):
        LOG.info(
            "maintenance backfilled_cooldowns=%d spamhaus_recovered_claimed=%d "
            "spamhaus_recovered_sending=%d abuseipdb_recovered_claimed=%d "
            "abuseipdb_recovered_sending=%d pruned_events=%d spamhaus_pruned_attempts=%d "
            "spamhaus_pruned_unknown=%d abuseipdb_pruned_attempts=%d abuseipdb_pruned_unknown=%d",
            backfilled, recovered_claimed, recovered_sending, abuse_recovered_claimed,
            abuse_recovered_sending, pruned_events, pruned_attempts, pruned_unknown,
            pruned_abuse_attempts, pruned_abuse_unknown,
        )


def collect_incremental(
    settings: Settings, *, bootstrap_minutes: int | None = None
) -> tuple[int, int, list[str]]:
    db = _db(settings)
    cf = _cf(settings)
    now = datetime.now(timezone.utc)
    actions = list(get(settings.raw, "cloudflare.actions", ["block"]) or ["block"])
    limit = int(get(settings.raw, "cloudflare.max_events_per_query", 5000))
    overlap = int(get(settings.raw, "cloudflare.overlap_minutes", 3))
    bootstrap = int(
        bootstrap_minutes or get(settings.raw, "cloudflare.bootstrap_minutes", 60)
    )
    max_catchup_hours = int(get(settings.raw, "cloudflare.max_catchup_hours", 23))

    total_inserted = 0
    total_duplicate = 0
    failures: list[str] = []
    for zone in settings.zones:
        cursor = db.get_zone_cursor(zone.name)
        if cursor:
            cursor_dt = parse_ts(cursor)
            if cursor_dt is None:
                LOG.warning("Invalid cursor for %s; using bootstrap window", zone.name)
                start = now - timedelta(minutes=bootstrap)
            else:
                start = cursor_dt - timedelta(minutes=overlap)
                floor = now - timedelta(hours=max_catchup_hours)
                if start < floor:
                    LOG.warning(
                        "%s cursor older than catch-up bound; clipping start to %s",
                        zone.name,
                        floor.isoformat(),
                    )
                    start = floor
        else:
            start = now - timedelta(minutes=bootstrap)

        try:
            events = cf.fetch_events(
                zone_name=zone.name,
                zone_id=zone.zone_id,
                start=start,
                end=now,
                limit=limit,
                actions=actions,
            )
            inserted, duplicate = db.insert_events(events)
            # Cursor only advances after both network fetch and durable DB insert.
            db.set_zone_cursor(zone.name, now.isoformat())
            total_inserted += inserted
            total_duplicate += duplicate
            print(
                f"{zone.name}: fetched={len(events)} inserted={inserted} duplicates={duplicate}"
            )
        except Exception as exc:
            failures.append(zone.name)
            LOG.exception("Collection failed for %s: %s", zone.name, exc)

    maintenance(settings)
    return total_inserted, total_duplicate, failures


def recent_candidates(settings: Settings) -> list[Candidate]:
    db = _db(settings)
    horizon = int(get(settings.raw, "classification.review_horizon_hours", 24))
    since = datetime.now(timezone.utc) - timedelta(hours=horizon)
    classifier_config = dict(get(settings.raw, "classification", {}) or {})
    classifier_config["include_target_host_in_reports"] = bool(
        get(settings.raw, "privacy.include_target_host", False)
    )
    return candidates_from_rows(db.events_since(since.isoformat()), classifier_config)


def _fmt_list(values: Iterable[object], limit: int = 5) -> str:
    vals = [str(v).replace("\x1b", "?").replace("\n", " ").replace("\r", " ") for v in values]
    return ", ".join(vals if len(vals) <= limit else vals[:limit] + [f"(+{len(vals)-limit})"])


def print_candidates(settings: Settings, status: str | None = None) -> list[Candidate]:
    db = _db(settings)
    candidates = recent_candidates(settings)
    if status:
        candidates = [c for c in candidates if c.status == status.upper()]
    if not candidates:
        print("No matching candidates.")
        return []
    now = datetime.now(timezone.utc)
    for c in candidates:
        spamhaus_eligible, spamhaus_why = db.can_submit(
            client_ip=c.ip, evidence_last_at=c.last_seen.isoformat(), now=now
        )
        spamhaus_latest = db.latest_attempt(c.ip)
        spamhaus_state = spamhaus_latest["state"] if spamhaus_latest else "-"
        if _abuse_enabled(settings):
            abuse_eligible, abuse_why = db.abuseipdb_can_submit(
                client_ip=c.ip, evidence_last_at=c.last_seen.isoformat(), now=now
            )
            abuse_latest = db.abuseipdb_latest_attempt(c.ip)
            abuse_state = abuse_latest["state"] if abuse_latest else "-"
        else:
            abuse_eligible, abuse_why, abuse_state = False, "disabled", "-"
        print("-" * 100)
        print(
            f"{c.status:<6} IP={c.ip} zone={c.zone} host={c.host} confidence={c.confidence} "
            f"requests={c.request_count}"
        )
        print(
            f"  Spamhaus: state={spamhaus_state} eligible={spamhaus_eligible} ({spamhaus_why}) | "
            f"AbuseIPDB: state={abuse_state} eligible={abuse_eligible} ({abuse_why})"
        )
        print(
            f"  window: {c.first_seen.isoformat()} -> {c.last_seen.isoformat()} | "
            f"category: {c.primary_category}"
        )
        print(
            f"  findings: {_fmt_list([f'{f.category}:{f.unique_count}' for f in c.findings], 10)}"
        )
        print(f"  paths: {_fmt_list(c.unique_paths, 10)}")
        print(f"  reason[{len(c.reason)}]: {c.reason}")
    return candidates


def _best_ready_per_ip(
    candidates: list[Candidate], allowed_categories: set[str]
) -> list[Candidate]:
    best: dict[str, Candidate] = {}
    for c in candidates:
        if c.status != "READY" or c.primary_category not in allowed_categories:
            continue
        prev = best.get(c.ip)
        # Prefer the newest READY window for an IP. This makes the recorded
        # evidence watermark monotonic and prevents an older high-confidence
        # window from leaving already-known newer READY evidence available for
        # a later cooldown cycle. Confidence is only the tie-breaker.
        if prev is None or (c.last_seen, c.confidence) > (prev.last_seen, prev.confidence):
            best[c.ip] = c
    return sorted(best.values(), key=lambda c: (-c.confidence, c.ip))


def sync_remote(settings: Settings) -> int:
    """Reconcile only recent remote IP submissions needed for cooldown safety."""
    db = _db(settings)
    spamhaus = _spamhaus(settings)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(
        hours=float(get(settings.raw, "spamhaus.remote_reconcile_horizon_hours", 48))
    )

    # Spamhaus exposes up to 30 days. Keep only the newest recent item per IP so
    # local storage remains bounded and reconciliation is deterministic.
    latest_by_ip: dict[str, dict] = {}
    latest_ts: dict[str, datetime] = {}
    for item in spamhaus.iter_submissions(
        items=int(get(settings.raw, "spamhaus.remote_history_page_items", 1000)),
        max_pages=int(get(settings.raw, "spamhaus.remote_history_max_pages", 100)),
    ):
        if str(item.get("submission_type") or "").lower() != "ip":
            continue
        source = item.get("source") or {}
        ip = str(source.get("object") or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        ts = parse_ts(str(item.get("submission_ts") or ""))
        if ts is None or ts < cutoff:
            continue
        if ip not in latest_ts or ts > latest_ts[ip]:
            latest_ts[ip] = ts
            latest_by_ip[ip] = item

    imported = 0
    for item in latest_by_ip.values():
        if db.reconcile_remote_submission(
            item,
            cooldown_hours=_cooldown(settings),
            import_cutoff=cutoff,
        ):
            imported += 1
    print(
        f"Spamhaus reconciliation: recent_remote_ips={len(latest_by_ip)} "
        f"added_or_reconciled={imported}."
    )
    return imported


def submit_ready(
    settings: Settings, *, actually_send: bool, reconcile: bool = True
) -> int:
    db = _db(settings)
    spamhaus = _spamhaus(settings)

    # Before a real POST, reconciliation is mandatory. If this GET fails, the
    # exception aborts the run before any new report is sent (fail closed).
    if reconcile:
        sync_remote(settings)
    maintenance(settings)

    preferred = str(get(settings.raw, "spamhaus.preferred_threat_type", "attack"))
    threat_type = spamhaus.resolve_threat_type(preferred)
    allowed = set(get(settings.raw, "classification.auto_submit_categories", []) or [])
    ready = _best_ready_per_ip(recent_candidates(settings), allowed)

    now = datetime.now(timezone.utc)
    eligible: list[Candidate] = []
    for c in ready:
        ok, why = db.can_submit(
            client_ip=c.ip, evidence_last_at=c.last_seen.isoformat(), now=now
        )
        if ok:
            eligible.append(c)
        else:
            LOG.info("%s skipped before claim: %s", c.ip, why)

    if not eligible:
        print("No eligible READY candidates.")
        return 0

    if not actually_send:
        print(f"DRY RUN: threat_type={threat_type!r}; {len(eligible)} eligible candidate(s).")
        for c in eligible:
            print(f"  {c.ip} | {c.primary_category} | {c.reason}")
        return 0

    cap = int(get(settings.raw, "spamhaus.max_post_attempts_per_24h", 25))
    day_start = now - timedelta(hours=24)
    remaining = max(cap - db.count_post_attempts_since(day_start.isoformat()), 0)
    if remaining <= 0:
        print(f"24h local POST cap reached ({cap}). Nothing sent.")
        return 0

    cooldown_hours = _cooldown(settings)
    duplicate_backoff = float(get(settings.raw, "spamhaus.duplicate_backoff_hours", 24))
    error_backoff = float(get(settings.raw, "spamhaus.definitive_error_backoff_hours", 24))

    posted = 0
    for c in eligible[:remaining]:
        if len(c.reason) > 255 or len(c.reason.encode("utf-8")) > 255:
            LOG.error("%s skipped: generated reason exceeds Spamhaus 255-byte safety cap", c.ip)
            continue
        token = db.claim_ip(
            client_ip=c.ip,
            threat_type=threat_type,
            reason=c.reason,
            category=c.primary_category,
            evidence_first_at=c.first_seen.isoformat(),
            evidence_last_at=c.last_seen.isoformat(),
            cooldown_hours=cooldown_hours,
        )
        if token is None:
            print(f"{c.ip}: skipped; no longer eligible or another process claimed it")
            continue

        # From this point onward a crash may be ambiguous. Persist 'sending' and
        # cooldown BEFORE issuing the one and only POST.
        if not db.mark_sending(token, cooldown_hours=cooldown_hours):
            LOG.error("Could not transition claim %s for %s to sending; no POST issued", token, c.ip)
            continue

        try:
            status_code, body = spamhaus.submit_ip_once(c.ip, threat_type, c.reason)
        except SpamhausAmbiguousSubmissionError as exc:
            db.finalize_submission(
                claim_token=token,
                state="unknown",
                http_status=None,
                submission_id=None,
                response={"error": str(exc)},
                cooldown_hours=cooldown_hours,
            )
            LOG.error(
                "%s marked UNKNOWN; no automatic POST retry before cooldown/reconciliation: %s",
                c.ip,
                exc,
            )
            posted += 1
            continue

        body_status = body.get("status") if isinstance(body, dict) else None
        try:
            effective = int(body_status) if body_status is not None else int(status_code)
        except (TypeError, ValueError):
            effective = int(status_code)
        submission_id = body.get("id") if isinstance(body, dict) else None

        if effective == 200:
            state = "submitted"
            backoff = cooldown_hours
        elif effective == 208:
            state = "duplicate"
            backoff = duplicate_backoff
        elif effective in {400, 401, 403, 404, 422}:
            state = "failed_definitive"
            backoff = error_backoff
        else:
            # 429/5xx/unexpected response semantics are not documented as an
            # idempotent failure. Treat as ambiguous and never immediately retry.
            state = "unknown"
            backoff = cooldown_hours

        db.finalize_submission(
            claim_token=token,
            state=state,
            http_status=status_code,
            submission_id=str(submission_id) if submission_id else None,
            response=body,
            cooldown_hours=backoff,
        )
        posted += 1
        print(f"{c.ip}: {state} (HTTP {status_code})")

        # Authentication/authorization/endpoint errors are systemic. Stop the
        # batch immediately so a bad configuration cannot generate many failures.
        if effective in {401, 403, 404}:
            raise SpamhausError(
                f"Systemic Spamhaus API error HTTP {effective}; batch stopped after {c.ip}"
            )
        if state == "failed_definitive":
            LOG.error("Definitive Spamhaus rejection for %s: %s", c.ip, body)
        elif state == "unknown":
            LOG.error("Ambiguous Spamhaus response for %s; no immediate retry: %s", c.ip, body)

    if len(eligible) > remaining:
        print(f"Skipped {len(eligible)-remaining} candidate(s) due to 24h POST cap.")
    return posted


def submit_abuseipdb_ready(settings: Settings, *, actually_send: bool) -> int:
    if not _abuse_enabled(settings):
        print("AbuseIPDB backend is disabled; nothing sent.")
        return 0

    db = _db(settings)
    client = _abuseipdb(settings)
    maintenance(settings)

    allowed = set(get(settings.raw, "classification.auto_submit_categories", []) or [])
    ready = _best_ready_per_ip(recent_candidates(settings), allowed)
    category_map = get(settings.raw, "abuseipdb.category_map", {}) or {}

    now = datetime.now(timezone.utc)
    eligible: list[Candidate] = []
    for c in ready:
        ok, why = db.abuseipdb_can_submit(
            client_ip=c.ip, evidence_last_at=c.last_seen.isoformat(), now=now
        )
        if ok:
            eligible.append(c)
        else:
            LOG.info("AbuseIPDB %s skipped before claim: %s", c.ip, why)

    if not eligible:
        print("No eligible READY candidates for AbuseIPDB.")
        return 0

    if not actually_send:
        print(f"DRY RUN (AbuseIPDB): {len(eligible)} eligible candidate(s).")
        for c in eligible:
            categories = categories_for_candidate(c, category_map)
            comment = make_comment(
                c, include_target_host=bool(get(settings.raw, "privacy.include_target_host", False))
            )
            print(f"  {c.ip} | categories={','.join(map(str, categories))} | {c.primary_category} | {comment}")
        return 0

    cap = int(get(settings.raw, "abuseipdb.max_post_attempts_per_24h", 100))
    day_start = now - timedelta(hours=24)
    remaining = max(cap - db.abuseipdb_count_post_attempts_since(day_start.isoformat()), 0)
    if remaining <= 0:
        print(f"AbuseIPDB 24h local POST cap reached ({cap}). Nothing sent.")
        return 0

    cooldown_hours = _abuse_cooldown(settings)
    rate_backoff = float(get(settings.raw, "abuseipdb.rate_limit_backoff_hours", 1))
    error_backoff = float(get(settings.raw, "abuseipdb.definitive_error_backoff_hours", 24))

    posted = 0
    for c in eligible[:remaining]:
        categories = categories_for_candidate(c, category_map)
        comment = make_comment(
            c, include_target_host=bool(get(settings.raw, "privacy.include_target_host", False))
        )
        if len(comment.encode("utf-8")) > 1024:
            LOG.error("%s skipped: generated AbuseIPDB comment exceeds 1024-byte cap", c.ip)
            continue

        token = db.abuseipdb_claim_ip(
            client_ip=c.ip,
            categories=categories,
            comment=comment,
            category=c.primary_category,
            evidence_first_at=c.first_seen.isoformat(),
            evidence_last_at=c.last_seen.isoformat(),
        )
        if token is None:
            print(f"AbuseIPDB {c.ip}: skipped; no longer eligible or another process claimed it")
            continue

        # As with Spamhaus, persist the ambiguous boundary before issuing the
        # one-and-only REPORT POST.
        if not db.abuseipdb_mark_sending(token, cooldown_hours=cooldown_hours):
            LOG.error("Could not transition AbuseIPDB claim %s for %s to sending; no POST issued", token, c.ip)
            continue

        try:
            status_code, body, headers = client.submit_ip_once(
                ip=c.ip,
                categories=categories,
                comment=comment,
                timestamp=c.first_seen.astimezone(timezone.utc).isoformat(),
            )
        except AbuseIPDBAmbiguousSubmissionError as exc:
            db.abuseipdb_finalize_submission(
                claim_token=token,
                state="unknown",
                http_status=None,
                response={"error": str(exc)},
                cooldown_hours=cooldown_hours,
            )
            LOG.error(
                "AbuseIPDB %s marked UNKNOWN; no automatic POST retry before cooldown: %s",
                c.ip,
                exc,
            )
            posted += 1
            continue

        effective = int(status_code)
        response_record = {"body": body, "rate_headers": headers}
        if effective == 200:
            state = "submitted"
            backoff = cooldown_hours
            explicit_until = None
        elif effective == 429:
            state = "rate_limited"
            backoff = rate_backoff
            explicit_until = None
            retry_after = headers.get("Retry-After") or headers.get("retry-after")
            if retry_after:
                try:
                    seconds = max(float(retry_after), 0.0)
                    explicit_until = datetime.now(timezone.utc) + timedelta(seconds=seconds)
                except ValueError:
                    explicit_until = None
            if explicit_until is None:
                reset = headers.get("X-RateLimit-Reset") or headers.get("x-ratelimit-reset")
                if reset:
                    try:
                        explicit_until = datetime.fromtimestamp(float(reset), tz=timezone.utc)
                    except (ValueError, OSError, OverflowError):
                        explicit_until = None
            # Never shorten the configured per-IP cooldown merely because the
            # provider returned a shorter Retry-After. The retry header can only
            # extend our local safety window.
            minimum_until = datetime.now(timezone.utc) + timedelta(
                hours=max(rate_backoff, cooldown_hours)
            )
            if explicit_until is None or explicit_until < minimum_until:
                explicit_until = minimum_until
        elif effective in {400, 401, 402, 403, 404, 422}:
            state = "failed_definitive"
            backoff = error_backoff
            explicit_until = None
        else:
            state = "unknown"
            backoff = cooldown_hours
            explicit_until = None

        db.abuseipdb_finalize_submission(
            claim_token=token,
            state=state,
            http_status=status_code,
            response=response_record,
            cooldown_hours=None if explicit_until is not None else backoff,
            cooldown_until=explicit_until,
        )
        posted += 1
        print(f"AbuseIPDB {c.ip}: {state} (HTTP {status_code})")

        if effective in {401, 403, 404}:
            raise AbuseIPDBError(
                f"Systemic AbuseIPDB API error HTTP {effective}; batch stopped after {c.ip}"
            )
        if state == "failed_definitive":
            LOG.error("Definitive AbuseIPDB rejection for %s: %s", c.ip, body)
        elif state == "rate_limited":
            LOG.warning("AbuseIPDB rate-limited %s; local backoff applied: %s", c.ip, headers)
        elif state == "unknown":
            LOG.error("Ambiguous AbuseIPDB response for %s; no immediate retry: %s", c.ip, body)

    if len(eligible) > remaining:
        print(f"AbuseIPDB skipped {len(eligible)-remaining} candidate(s) due to 24h POST cap.")
    return posted


def _warn_permissions(settings: Settings) -> None:
    env_path = settings.config_path.parent / ".env"
    if os.name == "nt" or not env_path.exists():
        return
    try:
        mode = stat.S_IMODE(env_path.stat().st_mode)
    except OSError:
        return
    # Two production-safe layouts are supported:
    #   * 0600, owned by the service user; or
    #   * 0640, owned by root with a dedicated service group for read-only access.
    # Group-read is therefore acceptable. Warn on group write/execute or any
    # access for "other" users.
    if mode & 0o027:
        LOG.warning(
            ".env permissions are %o; expected 0600 or restricted 0640 (no group write/execute, no other access)",
            mode,
        )


def setup_check(settings: Settings) -> None:
    _warn_permissions(settings)
    print(f"Config: {settings.config_path}")
    print(f"Rolling event retention: {get(settings.raw, 'storage.event_retention_hours', 36)}h")
    print(f"Local re-submit cooldown: {_cooldown(settings):g}h")
    for z in settings.zones:
        print(f"Zone: {z.name} ({z.zone_id})")

    spamhaus = _spamhaus(settings)
    preferred = str(get(settings.raw, "spamhaus.preferred_threat_type", "attack"))
    resolved = spamhaus.resolve_threat_type(preferred)
    print(f"Spamhaus: API key accepted; threat type {preferred!r} -> {resolved!r}")
    sync_remote(settings)

    if _abuse_enabled(settings):
        _abuseipdb(settings).check_auth()
        print(
            "AbuseIPDB: API key accepted by read-only CHECK endpoint; "
            "REPORT privilege will be exercised only by a real submission."
        )
    else:
        print("AbuseIPDB: disabled")

    cf = _cf(settings)
    now = datetime.now(timezone.utc)
    for z in settings.zones:
        events = cf.fetch_events(
            zone_name=z.name,
            zone_id=z.zone_id,
            start=now - timedelta(minutes=5),
            end=now,
            limit=int(get(settings.raw, "cloudflare.max_events_per_query", 5000)),
            actions=list(get(settings.raw, "cloudflare.actions", ["block"]) or ["block"]),
        )
        print(f"Cloudflare {z.name}: access OK ({len(events)} event(s) in last 5 min)")
    maintenance(settings)


def print_attempts(settings: Settings, limit: int, provider: str = "all") -> None:
    db = _db(settings)
    any_rows = False
    if provider in {"all", "spamhaus"}:
        rows = db.attempts(limit=limit)
        if rows:
            any_rows = True
            print("=== Spamhaus attempts ===")
            for r in rows:
                print(
                    f"{r['claimed_at']} {r['client_ip']} {r['state']} {r['category']} "
                    f"HTTP={r['http_status']} cooldown={r['cooldown_until'] or '-'} "
                    f"id={r['spamhaus_submission_id'] or '-'}"
                )
                if r["reason"]:
                    print(f"  {r['reason']}")
    if provider in {"all", "abuseipdb"}:
        rows = db.abuseipdb_attempts(limit=limit)
        if rows:
            any_rows = True
            print("=== AbuseIPDB attempts ===")
            for r in rows:
                print(
                    f"{r['claimed_at']} {r['client_ip']} {r['state']} {r['category']} "
                    f"categories={r['categories']} HTTP={r['http_status']} "
                    f"cooldown={r['cooldown_until'] or '-'}"
                )
                if r["comment"]:
                    print(f"  {r['comment']}")
    if not any_rows:
        print("Submission attempt history is empty.")

def health_check(settings: Settings) -> int:
    maintenance(settings)
    db = _db(settings)
    snap = db.health_snapshot()
    print(f"SQLite quick_check: {snap['quick_check']}")
    print(
        f"DB size: {snap['db_bytes']} bytes | events={snap['event_count']} "
        f"spamhaus_attempts={snap['attempt_count']} abuseipdb_attempts={snap['abuseipdb_attempt_count']}"
    )
    print(f"Spamhaus attempt states: {snap['states']}")
    print(f"AbuseIPDB attempt states: {snap['abuseipdb_states']}")
    if snap["quick_check"] != "ok":
        return 4

    now = datetime.now(timezone.utc)
    poll = int(get(settings.raw, "cloudflare.poll_minutes", 10))
    # Allow three polling intervals plus five minutes of scheduler/network jitter.
    stale_after = timedelta(minutes=max(poll * 3 + 5, 35))
    bad = False
    for z in settings.zones:
        raw = snap["cursors"].get(z.name)
        ts = parse_ts(raw) if raw else None
        if ts is None:
            print(f"Zone {z.name}: NO CURSOR")
            bad = True
            continue
        age = now - ts
        print(f"Zone {z.name}: cursor={ts.isoformat()} age={age}")
        if age > stale_after:
            bad = True
    return 5 if bad else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Production-hardened rolling Cloudflare -> Spamhaus + AbuseIPDB reporter"
    )
    p.add_argument("--config", default="config.yaml")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("setup-check")
    c = sub.add_parser("collect")
    c.add_argument("--bootstrap-minutes", type=int)
    r = sub.add_parser("review")
    r.add_argument("--status", choices=["READY", "REVIEW", "IGNORE"])
    sub.add_parser("sync-remote")
    s = sub.add_parser("submit")
    s.add_argument("--ready", action="store_true", required=True)
    s.add_argument("--yes", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument(
        "--provider",
        choices=["all", "spamhaus", "abuseipdb"],
        default="all",
        help="reporting backend(s) to preview/submit",
    )
    run = sub.add_parser("run")
    run.add_argument("--auto-submit", action="store_true")
    hist = sub.add_parser("attempts")
    hist.add_argument("--limit", type=int, default=100)
    hist.add_argument(
        "--provider", choices=["all", "spamhaus", "abuseipdb"], default="all"
    )
    maint = sub.add_parser("maintenance")
    maint.add_argument("--compact", action="store_true")
    sub.add_parser("health")
    return p


def main(argv: list[str] | None = None) -> int:
    if os.name != "nt":
        os.umask(0o077)
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings(args.config)
        _setup_logging(settings)
        lock_path = _path(settings, "storage.lock_path", "./spamhaus_reporter.lock")
        with ProcessLock(lock_path):
            if args.command == "setup-check":
                setup_check(settings)
            elif args.command == "collect":
                _, _, failures = collect_incremental(
                    settings, bootstrap_minutes=args.bootstrap_minutes
                )
                if failures:
                    print(
                        f"Collection failed for: {', '.join(failures)}",
                        file=sys.stderr,
                    )
                    return 3
            elif args.command == "review":
                maintenance(settings)
                print_candidates(settings, args.status)
            elif args.command == "sync-remote":
                sync_remote(settings)
                maintenance(settings)
            elif args.command == "submit":
                actually = bool(args.yes and not args.dry_run)
                errors: list[str] = []
                if args.provider in {"all", "spamhaus"}:
                    try:
                        submit_ready(settings, actually_send=actually, reconcile=True)
                    except SpamhausError as exc:
                        errors.append(f"Spamhaus: {exc}")
                if args.provider in {"all", "abuseipdb"}:
                    if _abuse_enabled(settings):
                        try:
                            submit_abuseipdb_ready(settings, actually_send=actually)
                        except AbuseIPDBError as exc:
                            errors.append(f"AbuseIPDB: {exc}")
                    elif args.provider == "abuseipdb":
                        errors.append("AbuseIPDB backend is disabled")
                if errors:
                    for msg in errors:
                        print(f"ERROR: {msg}", file=sys.stderr)
                    return 2
            elif args.command == "run":
                _, _, failures = collect_incremental(settings)
                print_candidates(settings)
                if failures:
                    print(
                        "Auto-submit suppressed because collection was incomplete.",
                        file=sys.stderr,
                    )
                    return 3
                if args.auto_submit:
                    enabled = bool(
                        get(settings.raw, "classification.auto_submit_enabled", False)
                    )
                    if not enabled:
                        print("Auto-submit requested but disabled in config; nothing sent.")
                    else:
                        backend_errors: list[str] = []
                        try:
                            submit_ready(settings, actually_send=True, reconcile=True)
                        except SpamhausError as exc:
                            backend_errors.append(f"Spamhaus: {exc}")
                            LOG.exception("Spamhaus auto-submit failed: %s", exc)
                        if _abuse_enabled(settings):
                            try:
                                submit_abuseipdb_ready(settings, actually_send=True)
                            except AbuseIPDBError as exc:
                                backend_errors.append(f"AbuseIPDB: {exc}")
                                LOG.exception("AbuseIPDB auto-submit failed: %s", exc)
                        if backend_errors:
                            for msg in backend_errors:
                                print(f"ERROR: {msg}", file=sys.stderr)
                            return 2
            elif args.command == "attempts":
                maintenance(settings)
                print_attempts(settings, args.limit, args.provider)
            elif args.command == "maintenance":
                maintenance(settings, compact=bool(args.compact))
            elif args.command == "health":
                return health_check(settings)
            return 0
    except (
        ConfigError,
        CloudflareError,
        SpamhausError,
        AbuseIPDBError,
        AlreadyRunningError,
        ValueError,
        OSError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
