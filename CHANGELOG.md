# Changelog

## 1.3.0 — AbuseIPDB dual-backend reporting

- Added optional AbuseIPDB API v2 reporting alongside Spamhaus.
- Added `ABUSEIPDB_API_KEY` support and `abuseipdb.enabled` configuration.
- Added conservative AbuseIPDB category mapping. The default mapping uses Web App Attack (`21`) for web reconnaissance and adds Hacking (`15`) only for the more explicit web-shell and traversal/LFI categories.
- Added AbuseIPDB comments generated from the same directly observed Cloudflare evidence, sanitized to printable ASCII and bounded to the provider's 1024-byte limit.
- Added independent AbuseIPDB idempotency state in SQLite with atomic claims, active-IP uniqueness, new-evidence checks, local cooldowns, crash recovery, rolling retention, and no automatic POST retry after ambiguous network failures.
- Added explicit AbuseIPDB handling for HTTP `429`, including `Retry-After` / `X-RateLimit-Reset` backoff where available.
- Added an independent local 24-hour AbuseIPDB POST-attempt cap.
- Added read-only AbuseIPDB API authentication checking during `setup-check`. This does not create a report; reporting privilege is ultimately exercised by the first real REPORT request.
- `submit --provider {all,spamhaus,abuseipdb}` can now preview or manually submit to a selected backend.
- `attempts --provider {all,spamhaus,abuseipdb}` displays provider-specific rolling attempt state.
- Scheduled `run --auto-submit` now submits independently to both enabled backends. Failure of one backend does not prevent the other backend from being attempted after a successful Cloudflare collection.
- Health output now includes separate Spamhaus and AbuseIPDB attempt counts/states.
- Added the `cloudflare-abuse-reporter` console alias while retaining the existing `spamhaus-reporter` command for backward compatibility.
- Updated systemd metadata, production examples, installer guidance, README, security notes, and tests for the dual-backend model.
- Added AbuseIPDB API client tests, comment/category tests, cooldown/rate-limit tests, and dual-backend configuration validation.

## 1.2.0 — Public production-hardened release

- Added the public GitHub-ready repository layout, CI, security documentation, and detailed production deployment instructions.
- Moved the persistent process lock to `/var/lib/spamhaus-reporter/reporter.lock` so manual CLI and systemd oneshot invocations share a stable writable location.
- Corrected `.env` permission checks so restricted `0640` root/service-group deployment is accepted.
- Added explicit `setuptools>=68` installation for Python environments that do not bundle the build backend.
- Hardened rolling duplicate prevention, remote Spamhaus reconciliation, evidence watermarks, crash recovery, retention, and systemd deployment.
- Added Cloudflare Security Rule examples and clarified that a Cloudflare block is evidence input, not an automatic reporting decision.
