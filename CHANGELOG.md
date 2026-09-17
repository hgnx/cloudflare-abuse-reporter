# Changelog

## 1.2.0

- Hardened the public production deployment layout.
- Moved the recommended production process lock from `/run/spamhaus-reporter` to `/var/lib/spamhaus-reporter/reporter.lock` so manual CLI commands and systemd oneshot runs share a stable writable directory.
- Replaced the old `.env` permission warning with logic that accepts both user-owned `0600` and restricted root-owned/service-group `0640` deployments.
- Replaced the example systemd unit with a dedicated `spamhaus-reporter` service account, strict read-only filesystem protection, bounded writable paths, and a persistent ten-minute timer.
- Added an idempotent-oriented production installer that creates versioned releases under `/opt/spamhaus-reporter/releases/`, installs `setuptools>=68` before package installation, and leaves auto-submit disabled.
- Added separate local and production configuration examples.
- Removed private/example deployment identifiers and public IPs from tests and documentation.
- Removed a redundant double zone-cursor write in incremental collection.
- Made outbound HTTP User-Agent strings use the package version dynamically.
- Added tests for secure `.env` permission modes.
- Tightened remote reconciliation so a much later independent Spamhaus submission cannot be mistaken for an earlier ambiguous local POST.
- Made per-IP READY selection prefer the newest evidence window so already-known newer evidence cannot be recycled after a cooldown.
- Evaluated cooldown and new-evidence eligibility across all retained per-IP attempts so a later abandoned pre-send claim cannot mask an older submitted or remote cooldown.
- Excluded remote-history-only rows from the local 24-hour POST-attempt cap.
- Added validation that the configured remote reconciliation horizon cannot exceed Spamhaus' documented 30-day history window.
- Added GitHub Actions CI, a security policy, and a substantially expanded deployment/operations README.
- Documented the default `actions: [block]` collection semantics and added conservative/optional Cloudflare Custom Rule examples for generating relevant blocked Security Events.

## 1.1.0

- Replaced permanent per-IP submission ledger with bounded rolling attempt history.
- Added configurable re-submission cooldown (24h default) without asserting it is a Spamhaus-guaranteed interval.
- Added a new-evidence invariant so old Cloudflare events cannot be resubmitted after cooldown.
- Added conservative `208` duplicate backoff and no-retry semantics for ambiguous POST outcomes.
- Added recent-only Spamhaus history reconciliation with bounded pagination.
- Added crash-state recovery: stale pre-send claims are retryable; stale sending states become ambiguous/`unknown`.
- Added rolling event/attempt retention, WAL checkpointing, optional explicit compaction, and rotating logs.
- Added high-volume arbitrary directory-enumeration detection; review-only by default.
- Added strict configuration validation, process umask `077`, and owner-only runtime database/log permissions.
- Added Cloudflare read-query retries and input/control-character sanitization.
- Added local health checks and initial systemd templates.
