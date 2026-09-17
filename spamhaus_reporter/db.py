from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import Event


SCHEMA = r"""
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    zone TEXT NOT NULL,
    zone_id TEXT NOT NULL,
    host TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT NOT NULL,
    action TEXT NOT NULL,
    source TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    country TEXT NOT NULL,
    asn INTEGER,
    observed_at TEXT NOT NULL,
    inserted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ip_zone_time ON events(client_ip, zone, observed_at);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(observed_at);

CREATE TABLE IF NOT EXISTS submission_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    claim_token TEXT NOT NULL UNIQUE,
    client_ip TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'claimed','sending','submitted','duplicate','remote_existing',
        'unknown','failed_definitive','abandoned_pre_send'
    )),
    threat_type TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    evidence_first_at TEXT,
    evidence_last_at TEXT,
    claimed_at TEXT NOT NULL,
    sending_at TEXT,
    finished_at TEXT,
    updated_at TEXT NOT NULL,
    cooldown_until TEXT,
    http_status INTEGER,
    spamhaus_submission_id TEXT,
    response_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_attempts_ip_claimed ON submission_attempts(client_ip, claimed_at DESC);
CREATE INDEX IF NOT EXISTS idx_attempts_sending ON submission_attempts(sending_at);
CREATE INDEX IF NOT EXISTS idx_attempts_state_updated ON submission_attempts(state, updated_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_attempt_active_ip
    ON submission_attempts(client_ip)
    WHERE state IN ('claimed','sending');

CREATE TABLE IF NOT EXISTS zone_cursors (
    zone TEXT PRIMARY KEY,
    last_success_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fingerprint_event(e: Event) -> str:
    # Deduplicate our overlapping Cloudflare fetch windows. Conservatively
    # collapsing byte-identical rows can only reduce evidence counts.
    data = "\x1f".join(
        [
            e.zone_id,
            e.host,
            e.client_ip,
            e.observed_at.astimezone(timezone.utc).isoformat(),
            e.path,
            e.query,
            e.action,
            e.source,
            e.user_agent,
        ]
    )
    return hashlib.sha256(data.encode("utf-8", "surrogatepass")).hexdigest()


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new_db = not self.path.exists()
        with self.connect() as con:
            if new_db:
                # Incremental autovacuum must be selected before schema creation.
                con.execute("PRAGMA auto_vacuum=INCREMENTAL")
            con.executescript(SCHEMA)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        self._migrate_legacy_tables()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=15.0, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=15000")
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA wal_autocheckpoint=1000")
        try:
            yield con
        finally:
            con.close()

    @contextmanager
    def immediate(self) -> Iterator[sqlite3.Connection]:
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                yield con
            except Exception:
                con.rollback()
                raise
            else:
                con.commit()

    def _table_exists(self, con: sqlite3.Connection, name: str) -> bool:
        row = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return row is not None

    def _migrate_legacy_tables(self) -> None:
        """Import only recent v0.1/v1.0 history, then clear legacy rows.

        The rolling schema uses bounded retention rather than permanent per-IP
        history. Legacy records are copied into submission_attempts so cooldown
        protection survives an upgrade, but old ledgers are not kept forever.
        """
        now = utcnow()
        cutoff = now - timedelta(days=7)
        with self.immediate() as con:
            # v1.0 permanent ledger.
            if self._table_exists(con, "submission_ledger"):
                rows = con.execute("SELECT * FROM submission_ledger").fetchall()
                for r in rows:
                    t = parse_ts(r["submitted_at"] if "submitted_at" in r.keys() else None) \
                        or parse_ts(r["updated_at"] if "updated_at" in r.keys() else None)
                    if t is None or t < cutoff:
                        continue
                    state = str(r["state"])
                    if state not in {
                        "claimed", "sending", "submitted", "duplicate", "remote_existing",
                        "unknown", "failed_definitive",
                    }:
                        continue
                    token = f"legacy-v10-{r['client_ip']}-{int(t.timestamp())}"
                    con.execute(
                        """
                        INSERT OR IGNORE INTO submission_attempts(
                            claim_token, client_ip, state, threat_type, reason, category,
                            evidence_first_at, evidence_last_at, claimed_at, sending_at,
                            finished_at, updated_at, cooldown_until, http_status,
                            spamhaus_submission_id, response_json
                        ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                        """,
                        (
                            token, str(r["client_ip"]), state,
                            str(r["threat_type"] or ""), str(r["reason"] or ""),
                            str(r["category"] or "legacy"), t.isoformat(), t.isoformat(),
                            t.isoformat() if state in {"sending", "submitted", "duplicate", "remote_existing", "unknown", "failed_definitive"} else None,
                            t.isoformat() if state not in {"claimed", "sending"} else None,
                            t.isoformat(), r["http_status"], r["spamhaus_submission_id"],
                            str(r["response_json"] or "{}"),
                        ),
                    )
                # No permanent history in the rolling schema. The table may remain for rollback,
                # but its contents are intentionally removed after migration.
                con.execute("DELETE FROM submission_ledger")

            # v0.1 append-only submissions table.
            if self._table_exists(con, "submissions"):
                rows = con.execute(
                    "SELECT * FROM submissions ORDER BY submitted_at DESC"
                ).fetchall()
                for r in rows:
                    t = parse_ts(r["submitted_at"])
                    if t is None or t < cutoff:
                        continue
                    old_status = str(r["status"])
                    if old_status not in {"submitted", "duplicate"}:
                        continue
                    state = old_status
                    token = f"legacy-v01-{r['client_ip']}-{int(t.timestamp())}"
                    con.execute(
                        """
                        INSERT OR IGNORE INTO submission_attempts(
                            claim_token, client_ip, state, threat_type, reason, category,
                            evidence_last_at, claimed_at, sending_at, finished_at, updated_at,
                            http_status, spamhaus_submission_id, response_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            token, str(r["client_ip"]), state,
                            str(r["threat_type"] or ""), str(r["reason"] or ""),
                            str(r["category"] or "legacy"), t.isoformat(), t.isoformat(), t.isoformat(),
                            t.isoformat(), t.isoformat(), r["http_status"],
                            r["spamhaus_submission_id"], str(r["response_json"] or "{}"),
                        ),
                    )
                con.execute("DELETE FROM submissions")

    # ---------- Cloudflare events ----------

    def insert_events(self, events: list[Event]) -> tuple[int, int]:
        inserted = 0
        duplicate = 0
        now = utcnow_iso()
        with self.immediate() as con:
            for e in events:
                cur = con.execute(
                    """
                    INSERT OR IGNORE INTO events (
                        fingerprint, zone, zone_id, host, client_ip, path, query,
                        action, source, user_agent, country, asn, observed_at, inserted_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fingerprint_event(e), e.zone, e.zone_id, e.host, e.client_ip,
                        e.path, e.query, e.action, e.source, e.user_agent, e.country,
                        e.asn, e.observed_at.astimezone(timezone.utc).isoformat(), now,
                    ),
                )
                if cur.rowcount == 1:
                    inserted += 1
                else:
                    duplicate += 1
        return inserted, duplicate

    def events_since(self, since_iso: str) -> list[sqlite3.Row]:
        with self.connect() as con:
            return list(
                con.execute(
                    "SELECT * FROM events WHERE observed_at >= ? ORDER BY client_ip, zone, observed_at",
                    (since_iso,),
                )
            )

    def prune_events_before(self, before_iso: str) -> int:
        with self.immediate() as con:
            cur = con.execute("DELETE FROM events WHERE observed_at < ?", (before_iso,))
            return int(cur.rowcount)

    # ---------- Durable Cloudflare cursors ----------

    def get_zone_cursor(self, zone: str) -> str | None:
        with self.connect() as con:
            row = con.execute(
                "SELECT last_success_at FROM zone_cursors WHERE zone=?", (zone,)
            ).fetchone()
            return str(row[0]) if row else None

    def set_zone_cursor(self, zone: str, last_success_at: str) -> None:
        now = utcnow_iso()
        with self.immediate() as con:
            con.execute(
                """
                INSERT INTO zone_cursors(zone, last_success_at, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(zone) DO UPDATE SET
                    last_success_at=excluded.last_success_at,
                    updated_at=excluded.updated_at
                """,
                (zone, last_success_at, now),
            )

    # ---------- Rolling submission state ----------

    def latest_attempt(self, client_ip: str) -> sqlite3.Row | None:
        with self.connect() as con:
            return con.execute(
                """
                SELECT * FROM submission_attempts
                WHERE client_ip=?
                ORDER BY claimed_at DESC, id DESC LIMIT 1
                """,
                (client_ip,),
            ).fetchone()

    @staticmethod
    def _eligibility_from_attempts(
        rows: list[sqlite3.Row],
        *,
        evidence_last: datetime,
        now: datetime,
    ) -> tuple[bool, str]:
        """Evaluate rolling duplicate protection across all retained attempts.

        Looking only at the newest row is not sufficient: a newer pre-send
        abandoned claim must never mask an older remote/submitted cooldown.
        The retained window is intentionally small, so scanning the per-IP rows
        is cheap and substantially safer.
        """
        if not rows:
            return True, "new IP"

        active = next((r for r in rows if r["state"] in {"claimed", "sending"}), None)
        if active is not None:
            return False, f"active {active['state']} attempt"

        cooldowns = [parse_ts(r["cooldown_until"]) for r in rows]
        cooldowns = [t for t in cooldowns if t is not None]
        if cooldowns:
            latest_cooldown = max(cooldowns)
            if now < latest_cooldown:
                return False, f"cooldown until {latest_cooldown.isoformat()}"

        # A pre-send abandoned claim made no network request and must not advance
        # the evidence watermark. All other retained states represent an actual,
        # possible, duplicate, or remote submission decision and do advance it.
        evidence_times = [
            parse_ts(r["evidence_last_at"])
            for r in rows
            if r["state"] != "abandoned_pre_send"
        ]
        evidence_times = [t for t in evidence_times if t is not None]
        if evidence_times and evidence_last <= max(evidence_times):
            return False, "no evidence newer than previous attempt"

        return True, "eligible"

    def can_submit(
        self,
        *,
        client_ip: str,
        evidence_last_at: str,
        now: datetime | None = None,
    ) -> tuple[bool, str]:
        now = (now or utcnow()).astimezone(timezone.utc)
        evidence_last = parse_ts(evidence_last_at)
        if evidence_last is None:
            return False, "invalid evidence timestamp"
        with self.connect() as con:
            rows = list(
                con.execute(
                    """
                    SELECT state, cooldown_until, evidence_last_at
                    FROM submission_attempts
                    WHERE client_ip=?
                    ORDER BY claimed_at DESC, id DESC
                    """,
                    (client_ip,),
                )
            )
        return self._eligibility_from_attempts(rows, evidence_last=evidence_last, now=now)

    def claim_ip(
        self,
        *,
        client_ip: str,
        threat_type: str,
        reason: str,
        category: str,
        evidence_first_at: str,
        evidence_last_at: str,
        cooldown_hours: float,
        now: datetime | None = None,
    ) -> str | None:
        """Atomically reserve one report cycle for an IP.

        The transaction re-evaluates all retained per-IP attempt state so a
        concurrent process, stale pre-send row, or newly reconciled remote row
        cannot bypass cooldown/new-evidence protection.
        """
        now = (now or utcnow()).astimezone(timezone.utc)
        evidence_last = parse_ts(evidence_last_at)
        if evidence_last is None:
            raise ValueError("Invalid evidence_last_at")

        with self.immediate() as con:
            rows = list(
                con.execute(
                    """
                    SELECT state, cooldown_until, evidence_last_at
                    FROM submission_attempts
                    WHERE client_ip=?
                    ORDER BY claimed_at DESC, id DESC
                    """,
                    (client_ip,),
                )
            )
            eligible, _ = self._eligibility_from_attempts(
                rows, evidence_last=evidence_last, now=now
            )
            if not eligible:
                return None

            token = uuid.uuid4().hex
            # We do not set cooldown on claim: a crash before mark_sending means
            # no network submission was made and can be safely recovered.
            try:
                con.execute(
                    """
                    INSERT INTO submission_attempts(
                        claim_token, client_ip, state, threat_type, reason, category,
                        evidence_first_at, evidence_last_at, claimed_at, updated_at
                    ) VALUES (?, ?, 'claimed', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        token, client_ip, threat_type, reason, category,
                        evidence_first_at, evidence_last_at, now.isoformat(), now.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                return None
            return token

    def mark_sending(
        self,
        claim_token: str,
        *,
        cooldown_hours: float,
        now: datetime | None = None,
    ) -> bool:
        now = (now or utcnow()).astimezone(timezone.utc)
        cooldown_until = now + timedelta(hours=float(cooldown_hours))
        with self.immediate() as con:
            cur = con.execute(
                """
                UPDATE submission_attempts
                SET state='sending', sending_at=?, updated_at=?, cooldown_until=?
                WHERE claim_token=? AND state='claimed'
                """,
                (now.isoformat(), now.isoformat(), cooldown_until.isoformat(), claim_token),
            )
            return cur.rowcount == 1

    def finalize_submission(
        self,
        *,
        claim_token: str,
        state: str,
        http_status: int | None,
        submission_id: str | None,
        response: object,
        cooldown_hours: float | None = None,
        submitted_at: str | None = None,
        now: datetime | None = None,
    ) -> None:
        if state not in {
            "submitted", "duplicate", "remote_existing", "unknown", "failed_definitive",
            "abandoned_pre_send",
        }:
            raise ValueError(f"Invalid final state: {state}")
        now = (now or utcnow()).astimezone(timezone.utc)
        base = parse_ts(submitted_at) or now
        cooldown_until = None
        if cooldown_hours is not None and cooldown_hours > 0:
            cooldown_until = (base + timedelta(hours=float(cooldown_hours))).isoformat()
        payload = json.dumps(response, ensure_ascii=False, sort_keys=True)[:40000]
        with self.immediate() as con:
            cur = con.execute(
                """
                UPDATE submission_attempts
                SET state=?, finished_at=?, updated_at=?, cooldown_until=COALESCE(?, cooldown_until),
                    http_status=?, spamhaus_submission_id=?, response_json=?
                WHERE claim_token=?
                """,
                (
                    state, now.isoformat(), now.isoformat(), cooldown_until,
                    http_status, submission_id, payload, claim_token,
                ),
            )
            if cur.rowcount != 1:
                raise RuntimeError(f"No submission attempt for claim token {claim_token}")

    def reconcile_remote_submission(
        self,
        item: dict[str, Any],
        *,
        cooldown_hours: float,
        import_cutoff: datetime,
    ) -> bool:
        """Reconcile a recent Spamhaus history item without storing 30 days.

        Only remote submissions newer than import_cutoff are retained. This is
        sufficient for cooldown/idempotency while bounding local data growth.
        """
        source = item.get("source") if isinstance(item, dict) else None
        ip = str((source or {}).get("object") or "").strip()
        remote_ts = parse_ts(str(item.get("submission_ts") or ""))
        if not ip or remote_ts is None or remote_ts < import_cutoff:
            return False

        now = utcnow()
        sid = str(item.get("id") or "") or None
        threat = str(item.get("threat_type") or "")
        reason = str(item.get("reason") or "")
        payload = json.dumps(item, ensure_ascii=False, sort_keys=True)[:40000]
        cooldown_until = remote_ts + timedelta(hours=float(cooldown_hours))

        with self.immediate() as con:
            # Prefer reconciling an uncertain local POST at approximately the
            # same time rather than inserting a separate remote row.
            local = con.execute(
                """
                SELECT * FROM submission_attempts
                WHERE client_ip=? AND state IN ('sending','unknown')
                ORDER BY claimed_at DESC, id DESC LIMIT 1
                """,
                (ip,),
            ).fetchone()
            if local is not None:
                local_t = parse_ts(local["sending_at"] or local["claimed_at"])
                # Reconcile only a remote submission that is close enough in time
                # to plausibly be the same ambiguous local POST. A much later
                # manual/independent remote submission for the same IP must become
                # its own row instead of rewriting historical ambiguity.
                if local_t is not None and abs(remote_ts - local_t) <= timedelta(minutes=5):
                    con.execute(
                        """
                        UPDATE submission_attempts
                        SET state='remote_existing', threat_type=COALESCE(NULLIF(?,''), threat_type),
                            reason=COALESCE(NULLIF(?,''), reason), finished_at=COALESCE(finished_at, ?),
                            updated_at=?, cooldown_until=?, spamhaus_submission_id=COALESCE(?, spamhaus_submission_id),
                            response_json=?
                        WHERE id=?
                        """,
                        (
                            threat, reason, remote_ts.isoformat(), now.isoformat(),
                            cooldown_until.isoformat(), sid, payload, local["id"],
                        ),
                    )
                    return True

            latest = con.execute(
                """
                SELECT * FROM submission_attempts
                WHERE client_ip=?
                  AND state NOT IN ('claimed','abandoned_pre_send')
                ORDER BY claimed_at DESC, id DESC LIMIT 1
                """,
                (ip,),
            ).fetchone()
            latest_t = parse_ts(latest["claimed_at"]) if latest is not None else None
            # Only rows that represent an actual/possible network submission may
            # suppress an older remote-history item. A later pre-send claim must
            # not mask a valid remote submission and its cooldown.
            if latest_t is not None and latest_t >= remote_ts:
                return False

            token = f"remote-{hashlib.sha256((ip + '|' + remote_ts.isoformat()).encode()).hexdigest()[:32]}"
            con.execute(
                """
                INSERT OR IGNORE INTO submission_attempts(
                    claim_token, client_ip, state, threat_type, reason, category,
                    evidence_first_at, evidence_last_at, claimed_at, sending_at, finished_at, updated_at, cooldown_until,
                    http_status, spamhaus_submission_id, response_json
                ) VALUES (?, ?, 'remote_existing', ?, ?, 'remote', ?, ?, ?, ?, ?, ?, ?, 200, ?, ?)
                """,
                (
                    token, ip, threat, reason, remote_ts.isoformat(), remote_ts.isoformat(),
                    remote_ts.isoformat(), remote_ts.isoformat(), remote_ts.isoformat(), now.isoformat(),
                    cooldown_until.isoformat(), sid, payload,
                ),
            )
            return True

    def recover_stale_attempts(
        self,
        *,
        claimed_stale_minutes: int,
        sending_stale_minutes: int,
        cooldown_hours: float,
        now: datetime | None = None,
    ) -> tuple[int, int]:
        """Recover interrupted processes conservatively.

        A stale 'claimed' row is known to be pre-POST and can be abandoned.
        A stale 'sending' row is ambiguous and becomes 'unknown' with cooldown.
        """
        now = (now or utcnow()).astimezone(timezone.utc)
        claimed_cutoff = now - timedelta(minutes=claimed_stale_minutes)
        sending_cutoff = now - timedelta(minutes=sending_stale_minutes)
        recovered_claimed = 0
        recovered_sending = 0
        with self.immediate() as con:
            cur = con.execute(
                """
                UPDATE submission_attempts
                SET state='abandoned_pre_send', finished_at=?, updated_at=?
                WHERE state='claimed' AND claimed_at < ?
                """,
                (now.isoformat(), now.isoformat(), claimed_cutoff.isoformat()),
            )
            recovered_claimed = int(cur.rowcount)

            rows = con.execute(
                """
                SELECT id, sending_at, claimed_at FROM submission_attempts
                WHERE state='sending' AND COALESCE(sending_at, claimed_at) < ?
                """,
                (sending_cutoff.isoformat(),),
            ).fetchall()
            for r in rows:
                base = parse_ts(r["sending_at"] or r["claimed_at"]) or now
                cooldown_until = base + timedelta(hours=float(cooldown_hours))
                con.execute(
                    """
                    UPDATE submission_attempts
                    SET state='unknown', finished_at=?, updated_at=?, cooldown_until=?
                    WHERE id=? AND state='sending'
                    """,
                    (now.isoformat(), now.isoformat(), cooldown_until.isoformat(), r["id"]),
                )
                recovered_sending += 1
        return recovered_claimed, recovered_sending

    def backfill_missing_cooldowns(
        self, *, cooldown_hours: float, now: datetime | None = None
    ) -> int:
        """Conservatively protect migrated rows that predate the rolling cooldown fields."""
        now = (now or utcnow()).astimezone(timezone.utc)
        updated = 0
        with self.immediate() as con:
            rows = con.execute(
                """
                SELECT id, state, sending_at, finished_at, claimed_at
                FROM submission_attempts
                WHERE cooldown_until IS NULL
                  AND state IN ('sending','submitted','duplicate','remote_existing','unknown','failed_definitive')
                """
            ).fetchall()
            for r in rows:
                base = parse_ts(r["sending_at"] or r["finished_at"] or r["claimed_at"]) or now
                until = base + timedelta(hours=float(cooldown_hours))
                con.execute(
                    "UPDATE submission_attempts SET cooldown_until=?, updated_at=? WHERE id=?",
                    (until.isoformat(), now.isoformat(), r["id"]),
                )
                updated += 1
        return updated

    def count_post_attempts_since(self, since_iso: str) -> int:
        with self.connect() as con:
            row = con.execute(
                """
                SELECT COUNT(*) AS n
                FROM submission_attempts
                WHERE sending_at >= ?
                  AND category <> 'remote'
                """,
                (since_iso,),
            ).fetchone()
            return int(row["n"] if row else 0)

    def attempts(self, limit: int = 100) -> list[sqlite3.Row]:
        with self.connect() as con:
            return list(
                con.execute(
                    "SELECT * FROM submission_attempts ORDER BY claimed_at DESC, id DESC LIMIT ?",
                    (limit,),
                )
            )

    def prune_attempts_before(self, before_iso: str) -> int:
        """Delete only terminal rows. Active/ambiguous rows are never blindly pruned."""
        with self.immediate() as con:
            cur = con.execute(
                """
                DELETE FROM submission_attempts
                WHERE claimed_at < ?
                  AND state IN ('submitted','duplicate','remote_existing','failed_definitive','abandoned_pre_send')
                """,
                (before_iso,),
            )
            return int(cur.rowcount)

    def prune_unknown_before(self, before_iso: str) -> int:
        # Unknown rows are kept longer, but not forever. Once older than the
        # configured retention and far beyond cooldown, they no longer protect
        # against a plausible immediate duplicate.
        with self.immediate() as con:
            cur = con.execute(
                "DELETE FROM submission_attempts WHERE state='unknown' AND claimed_at < ?",
                (before_iso,),
            )
            return int(cur.rowcount)

    def maintenance_checkpoint(self) -> None:
        with self.connect() as con:
            # Bound WAL growth. Database free pages are reused on future inserts,
            # so ordinary operation reaches a steady high-water mark.
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            try:
                con.execute("PRAGMA incremental_vacuum(2000)")
            except sqlite3.DatabaseError:
                pass

    def health_snapshot(self) -> dict[str, Any]:
        with self.connect() as con:
            quick = str(con.execute("PRAGMA quick_check").fetchone()[0])
            event_count = int(con.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            attempt_count = int(con.execute("SELECT COUNT(*) FROM submission_attempts").fetchone()[0])
            states = {
                str(r["state"]): int(r["n"])
                for r in con.execute(
                    "SELECT state, COUNT(*) AS n FROM submission_attempts GROUP BY state"
                ).fetchall()
            }
            cursors = {
                str(r["zone"]): str(r["last_success_at"])
                for r in con.execute("SELECT zone, last_success_at FROM zone_cursors").fetchall()
            }
        return {
            "quick_check": quick,
            "event_count": event_count,
            "attempt_count": attempt_count,
            "states": states,
            "cursors": cursors,
            "db_bytes": self.path.stat().st_size if self.path.exists() else 0,
        }

    def compact(self) -> None:
        with self.connect() as con:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("VACUUM")
