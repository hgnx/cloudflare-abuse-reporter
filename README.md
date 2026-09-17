# Cloudflare → Spamhaus Reporter

A conservative automation service that reads blocked Cloudflare Security Events, classifies repeated reconnaissance patterns, and can submit high-confidence source IPs to the Spamhaus Threat Intel Community API.

> **Important:** This project is not affiliated with, endorsed by, or sponsored by Cloudflare or Spamhaus. Automated reporting carries real consequences. Use it only for activity you directly observe on infrastructure you control, review the Spamhaus submission rules, and run in shadow mode before enabling automatic submissions.

Current release: **1.2.0**

## What this project does

The reporter is designed for operators who already block obvious scanning/reconnaissance at Cloudflare and want a repeatable, auditable reporting pipeline.

The default flow is:

```text
Cloudflare Security Events (firewallEventsAdaptive)
        │
        ▼
Incremental collection with durable per-zone cursors
        │
        ▼
SQLite rolling event store + deduplication
        │
        ▼
IP/window aggregation and path classification
        │
        ├── IGNORE
        ├── REVIEW
        └── READY
              │
              ▼
  Spamhaus history reconciliation
              │
              ▼
       local cooldown check
              │
              ▼
       atomic submission claim
              │
              ▼
   exactly one Spamhaus POST attempt
```

The project is deliberately biased toward **false-negative safety over false-positive automation**. A single request to `/wp-login.php` is not enough for an automatic report. Thresholds require repeated or multi-path behavior, and several noisier categories are review-only by default.

## Safety and idempotency model

The submission path has multiple independent safeguards:

1. **Process lock** — scheduled and manual executions cannot run the critical path at the same time.
2. **SQLite `BEGIN IMMEDIATE` claims** — concurrent processes cannot both reserve the same IP for submission.
3. **Active-IP unique index** — only one `claimed`/`sending` attempt may exist per IP.
4. **Local cooldown** — the same IP is not submitted again during the configured cooldown period.
5. **New-evidence requirement** — after cooldown, old Cloudflare evidence cannot be recycled; a later report needs an event newer than the previous attempt. Eligibility is evaluated across **all retained per-IP attempts**, not merely the newest row, so an abandoned pre-send claim cannot hide an older submitted/remote cooldown or evidence watermark. When multiple READY windows exist for one IP, the newest eligible window is preferred so the evidence watermark moves forward.
6. **Remote reconciliation** — before a real POST, recent Spamhaus submission history is fetched and merged into the local cooldown state.
7. **No automatic POST retry** — a submission POST is attempted once. If the network times out after the server may have accepted the request, the state becomes `unknown` instead of retrying blindly.
8. **Spamhaus 208 handling** — an already-reported response is recorded as `duplicate` and backed off.
9. **24-hour POST cap** — a configurable local cap limits the number of outbound report attempts.
10. **Fail-closed collection** — if any configured Cloudflare zone fails to collect in a scheduled run, automatic submission is suppressed for that run.

### About the 24-hour cooldown

The default `resubmit_cooldown_hours: 24` is a **local policy**, not a claim that Spamhaus guarantees resubmission after exactly 24 hours. Spamhaus publicly documents `200` for a successful IP submission, `208` for an already-reported submission, and a 30-day submission-history view. If Spamhaus still returns `208` after the local cooldown, this project records that result and backs off again. Configuration rejects a remote reconciliation horizon longer than that documented 30-day history window.

Official Spamhaus API documentation:

- https://submit.spamhaus.org/api/
- https://submit.spamhaus.org/submit/

## Responsible-use requirements

Spamhaus states that submissions should be based on personal observations of your own network/resources or substantiated open sources, and should be justified, necessary, proportionate, and made in good faith. Do not submit speculative claims or data you are not authorized to share.

Before enabling automatic submission:

- run the reporter in shadow mode;
- inspect your own `READY` and `REVIEW` candidates;
- tune thresholds and allowlists for your applications;
- confirm that the generated reasons describe only what your logs actually show;
- verify that your Cloudflare action filter is appropriate for your environment.

## Data sent to Spamhaus

For an IP submission, the reporter sends only the fields needed by the Spamhaus IP API:

```json
{
  "threat_type": "attack",
  "reason": "...",
  "source": {
    "object": "203.0.113.10"
  }
}
```

The generated reason may contain the target hostname and a short list of requested paths. It is capped at 255 bytes/characters and sanitized to printable ASCII. Review this behavior before use if hostnames or paths in your environment are sensitive.

The reporter does **not** query or transmit request bodies, cookies, authorization headers, or application response bodies.

## Default classification policy

| Category | Typical examples | READY threshold | Auto-submit by default |
| --- | --- | ---: | :---: |
| `wordpress` | `/wp-login.php`, `/xmlrpc.php`, multiple `wp-includes` paths | 4 unique matching paths | Yes |
| `secrets_config` | `/.env`, `/.env.old`, `/key.json`, config/credential files | 3 | Yes |
| `source_control` | `/.git/config`, `/.git/HEAD`, `.svn`, `.hg` | 2 | Yes |
| `db_admin` | `/phpmyadmin/`, `/pma/`, `/adminer.php` | 3 | Yes |
| `backup_dump` | `.sql`, `.bak`, `.zip`, backup/dump directories | 3 | No |
| `cloud_credentials` | `/.aws/credentials`, `service-account.json` | 2 | Yes |
| `api_debug` | `/swagger`, `/openapi.json`, `/actuator`, `/debug` | 4 | No |
| `webshell` | `/wso.php`, `/shell.php`, `/alfa.php` | 2 | Yes |
| `traversal_lfi` | `../`, encoded traversal, `/etc/passwd`, `/proc/self/environ` | 2 | Yes |
| `admin_login` | `/admin`, `/administrator`, `/cpanel`, `/manager/html` | 6 | No |
| `generic_scan` | multiple unrelated suspicious technology families | 15 suspicious paths + additional conditions | Yes |
| `directory_enum` | high-volume arbitrary path enumeration | 30 unique paths / 40 requests / ≤10 min | No |

A path match alone does not prove compromise or intent. The generated wording intentionally says **observed probing/reconnaissance**, not that credentials were stolen or a system was compromised.

## Requirements

- Linux recommended for production; the supplied service files target `systemd`.
- Python **3.10+**.
- SQLite (Python standard library).
- Outbound HTTPS access to Cloudflare and Spamhaus.
- A Cloudflare API token with access to the configured zones.
- A Spamhaus Threat Intel Community API key with submission access.

Runtime Python dependencies are pinned in `requirements.txt`.

## Cloudflare setup

This project queries Cloudflare's GraphQL Analytics API dataset `firewallEventsAdaptive`.

Cloudflare's current documentation recommends an API token for GraphQL Analytics. Create a custom token with:

```text
Permission:
  Account → Account Analytics → Read

Zone Resources:
  Include → Specific zone → <each zone used by this reporter>
```

Use the narrowest zone scope that works for your deployment. Cloudflare documentation:

- Authentication: https://developers.cloudflare.com/analytics/graphql-api/getting-started/authentication/
- Analytics API token: https://developers.cloudflare.com/analytics/graphql-api/getting-started/authentication/api-token-auth/
- Firewall Events query: https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events/
- Security Events limits: https://developers.cloudflare.com/waf/analytics/security-events/
- Sampling: https://developers.cloudflare.com/analytics/graphql-api/sampling/

### Recommended Cloudflare Security Rule

The reporter does **not** require one particular Cloudflare Custom Rule. By default, however, the configuration contains:

```yaml
cloudflare:
  actions: [block]
```

This means the collector asks `firewallEventsAdaptive` for Security Events whose terminating action is `block`. A block can come from a Custom Rule or another Cloudflare security feature. The reporter then applies its own path-based aggregation and classification logic; a Cloudflare block by itself is **not** enough to make an IP `READY`.

For sites that do not intentionally expose the paths below, a dedicated Custom Rule is a useful way to make obvious reconnaissance generate deterministic `block` events. In the Cloudflare dashboard, go to **Security → Security rules → Create rule → Custom rules**, choose **Edit expression**, enter an expression, and set **Then take action → Block**.

A conservative example that is reasonably aligned with the default classifier is:

```text
(http.request.uri.path wildcard "*/.env*") or
(http.request.uri.path wildcard "*/.git*") or
(http.request.uri.path wildcard "*/.svn*") or
(http.request.uri.path wildcard "*/.hg*") or
(http.request.uri.path wildcard "*/.bzr*") or
(http.request.uri.path wildcard "*/xmlrpc.php*") or
(http.request.uri.path wildcard "*/wp-login.php*") or
(http.request.uri.path wildcard "*/wp-admin*") or
(http.request.uri.path wildcard "*/wp-includes*") or
(http.request.uri.path wildcard "*/wp-content*") or
(http.request.uri.path wildcard "*/phpmyadmin*") or
(http.request.uri.path wildcard "*/pma/*") or
(http.request.uri.path wildcard "*/adminer.php*") or
(http.request.uri.path wildcard "*/mysqladmin*") or
(http.request.uri.path wildcard "*/.aws/credentials*") or
(http.request.uri.path wildcard "*/service-account.json*") or
(http.request.uri.path wildcard "*/service_account.json*") or
(http.request.uri.path wildcard "*/amplifyconfiguration.json*") or
(http.request.uri.path wildcard "*/firebase.json*") or
(http.request.uri.path wildcard "*/google-services.json*") or
(http.request.uri.path wildcard "*/id_rsa*") or
(http.request.uri.path wildcard "*/id_dsa*") or
(http.request.uri.path wildcard "*/id_ecdsa*") or
(http.request.uri.path wildcard "*/id_ed25519*") or
(http.request.uri.path wildcard "*/wso.php*") or
(http.request.uri.path wildcard "*/alfa.php*") or
(http.request.uri.path wildcard "*/shell.php*") or
(http.request.uri.path wildcard "*/cmd.php*") or
(http.request.uri.path wildcard "*/c99.php*") or
(http.request.uri.path wildcard "*/r57.php*") or
(http.request.uri.path wildcard "*/b374k.php*") or
(http.request.uri.path wildcard "*/filesman.php*")
```

Cloudflare's `wildcard` operator is case-insensitive and matches the entire field value; leading and trailing `*` characters make the examples above behave like case-insensitive substring matches on `http.request.uri.path`. `http.request.uri.path` does not include the query string.

#### Optional environment-specific extensions

The following paths are often worth blocking on sites that **do not actually use them**, but they have a larger legitimate-use surface. Do not copy them blindly into a shared rule:

```text
(http.request.uri.path wildcard "*/vendor/phpunit*") or
(http.request.uri.path wildcard "*/actuator*") or
(http.request.uri.path wildcard "*/swagger*") or
(http.request.uri.path wildcard "*/api-docs*") or
(http.request.uri.path wildcard "*/openapi.json*") or
(http.request.uri.path wildcard "*/debug*") or
(http.request.uri.path wildcard "*/server-status*") or
(http.request.uri.path wildcard "*/server-info*") or
(http.request.uri.path wildcard "*/phpinfo*") or
(http.request.uri.path wildcard "*/graphql*") or
(http.request.uri.path wildcard "*/.ssh*") or
(http.request.uri.path wildcard "*/config.json*") or
(http.request.uri.path wildcard "*/config.js*") or
(http.request.uri.path wildcard "*/settings.js*")
```

In particular, `/graphql`, `/swagger`, `/openapi.json`, `/config.js`, and `/settings.js` can be normal application endpoints/files. WordPress paths are also normal on a real WordPress site. Only block paths that are invalid for the application you are protecting.

You may separately choose to block unusual HTTP methods on an ordinary website, for example:

```text
http.request.method in {"TRACE" "CONNECT" "TRACK"}
```

That is useful WAF hardening, but **version 1.2.0 does not use the HTTP method itself as a classification signal**. A method-only block therefore does not, by itself, make an IP reportable by this project.

Similarly, some paths in the optional example (for example `vendor/phpunit`, `server-info`, or `phpinfo`) are not dedicated default classifier categories. They may contribute to broader/directory-enumeration evidence, but the Cloudflare rule and the reporter classifier are intentionally not treated as a one-to-one mapping.

If you maintain trusted source IPs, health-check systems, or internal scanners, exclude them in Cloudflare and/or add them to the reporter's `allowlist_cidrs`. Do not rely on User-Agent strings for trust because they are attacker-controlled.

A stricter expression can also be scoped to specific hostnames when one zone contains applications with different route sets. For example:

```text
(http.host eq "www.example.com") and (
  (http.request.uri.path wildcard "*/.env*") or
  (http.request.uri.path wildcard "*/.git*") or
  (http.request.uri.path wildcard "*/xmlrpc.php*")
)
```

The reporter is **not tied to the ID or name of this example rule**. With the default `actions: [block]`, it can ingest any matching Cloudflare Security Event whose action is `block`, and its own thresholds decide whether the source becomes `IGNORE`, `REVIEW`, or `READY`. This is deliberate: existing Managed Rules or other Custom Rules can provide useful evidence too.

Cloudflare documentation for these rule mechanics:

- Custom Rules: https://developers.cloudflare.com/waf/custom-rules/
- Create a Custom Rule: https://developers.cloudflare.com/waf/custom-rules/create-dashboard/
- Rules language operators (`wildcard`, `in`, grouping): https://developers.cloudflare.com/ruleset-engine/rules-language/operators/
- URI path field: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.uri.path/

### Cloudflare retention and sampling

`firewallEventsAdaptive` is an adaptive analytics dataset. Cloudflare documents plan-dependent retention and adaptive sampling under load. A narrower time range can reduce sampling, but this application cannot reconstruct events that Cloudflare did not return. This limitation primarily creates **missed evidence**, not fabricated evidence.

The default `max_catchup_hours: 23` is intentionally conservative for Free/Pro environments with a 24-hour Security Events retention window. Increase it only if your plan and operational requirements support a longer window.

## Spamhaus setup

Create a Spamhaus Threat Intel Community account and API key according to:

- https://submit.spamhaus.org/api/

The key is sent as a Bearer token. Do not commit it to Git.

The reporter resolves `preferred_threat_type` against Spamhaus' live `lookup/threats-types` endpoint during `setup-check` and before submission. The default is `attack`; if that code is not available for IP submissions in your account/API, setup fails rather than guessing.

## Repository layout

```text
.
├── .env.example
├── .github/workflows/ci.yml
├── CHANGELOG.md
├── README.md
├── SECURITY.md
├── config.example.yaml
├── deploy/
│   ├── config.production.yaml.example
│   ├── install.sh
│   └── systemd/
│       ├── spamhaus-reporter.service
│       └── spamhaus-reporter.timer
├── pyproject.toml
├── requirements.txt
├── spamhaus_reporter/
└── tests/
```

## Local/manual quick start

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip 'setuptools>=68' wheel
python -m pip install -r requirements.txt
python -m pip install --no-deps --no-build-isolation .
```

`setuptools>=68` is installed explicitly because some modern Python virtual environments, including Python 3.14 environments, may not include setuptools by default while this project uses the `setuptools.build_meta` build backend.

Create local config files:

```bash
cp config.example.yaml config.yaml
cp .env.example .env
chmod 600 .env
```

Edit `.env`:

```dotenv
SPAMHAUS_API_KEY=<your key>
CLOUDFLARE_API_TOKEN=<your token>
```

Edit `config.yaml`, replace each placeholder zone and Zone ID, and remove unused example zones.

Keep this setting disabled initially:

```yaml
classification:
  auto_submit_enabled: false
```

Run tests:

```bash
python -m pip install '.[dev]'
pytest -q
```

Then validate without submitting anything:

```bash
spamhaus-reporter --config config.yaml setup-check
spamhaus-reporter --config config.yaml collect --bootstrap-minutes 60
spamhaus-reporter --config config.yaml review
spamhaus-reporter --config config.yaml review --status READY
spamhaus-reporter --config config.yaml submit --ready --dry-run
spamhaus-reporter --config config.yaml health
```

`setup-check` contacts Cloudflare and Spamhaus, reconciles recent Spamhaus history, and verifies a short Cloudflare query for each zone. It does **not** submit an IP report.

## Production deployment on Debian/Ubuntu with systemd

The recommended production layout separates code, secrets, state, and logs:

```text
/opt/spamhaus-reporter/
├── current -> releases/<version>
└── releases/<version>/

/etc/spamhaus-reporter/
├── .env
└── config.yaml

/var/lib/spamhaus-reporter/
├── reporter.sqlite3
└── reporter.lock

/var/log/spamhaus-reporter/
└── reporter.log
```

The service runs under a dedicated non-login account named `spamhaus-reporter`.

### 1. Install operating-system prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv ca-certificates sqlite3 git
```

### 2. Clone or unpack this repository

For example:

```bash
git clone <your-repository-url> cloudflare-spamhaus-reporter
cd cloudflare-spamhaus-reporter
```

### 3. Run the production installer

```bash
sudo ./deploy/install.sh
```

The installer:

- creates the dedicated `spamhaus-reporter` service account/group if needed;
- creates a versioned release under `/opt/spamhaus-reporter/releases/`;
- creates a virtual environment;
- explicitly installs `setuptools>=68` before installing the package;
- creates `/opt/spamhaus-reporter/current` as a symlink to the new release;
- creates restricted configuration, state, and log directories;
- installs the supplied systemd service/timer;
- verifies the systemd unit syntax;
- **does not** enable the timer;
- **does not** enable auto-submit;
- **does not** submit any report.

If `systemd-analyze verify` prints warnings for unrelated distribution-supplied units, inspect the unit names. Warnings that reference another service (for example an OS maintenance unit) are not errors in this project's unit files. Any error that names `spamhaus-reporter.service` or `spamhaus-reporter.timer` should be fixed before proceeding.

### 4. Configure secrets

```bash
sudoedit /etc/spamhaus-reporter/.env
```

Set:

```dotenv
SPAMHAUS_API_KEY=<your key>
CLOUDFLARE_API_TOKEN=<your token>
```

The recommended production permissions are:

```text
root:spamhaus-reporter 0640 /etc/spamhaus-reporter/.env
root:spamhaus-reporter 0640 /etc/spamhaus-reporter/config.yaml
root:spamhaus-reporter 0750 /etc/spamhaus-reporter
```

This lets root modify secrets while the service account has read-only access. Version 1.2.0 explicitly treats restricted `0640` as valid; it warns only when group write/execute or any `other` permissions are present. A user-owned `0600` `.env` is also valid for non-systemd/manual deployments.

Reassert permissions if needed:

```bash
sudo chown root:spamhaus-reporter \
  /etc/spamhaus-reporter/.env \
  /etc/spamhaus-reporter/config.yaml
sudo chmod 0640 \
  /etc/spamhaus-reporter/.env \
  /etc/spamhaus-reporter/config.yaml
sudo chmod 0750 /etc/spamhaus-reporter
```

A normal unprivileged shell user may receive `Permission denied` when reading these files. That is expected. Use `sudo` or run read-only checks as the service account.

### 5. Configure zones and production storage

```bash
sudoedit /etc/spamhaus-reporter/config.yaml
```

The installer starts from `deploy/config.production.yaml.example`. Replace all zone placeholders and remove unused example entries.

Production storage should remain:

```yaml
storage:
  sqlite_path: /var/lib/spamhaus-reporter/reporter.sqlite3
  log_path: /var/log/spamhaus-reporter/reporter.log
  lock_path: /var/lib/spamhaus-reporter/reporter.lock
```

The lock intentionally lives under `/var/lib`, not `/run`. This lets scheduled systemd runs and manual CLI commands share the same lock directory even after a oneshot service has exited.

Keep:

```yaml
classification:
  auto_submit_enabled: false
```

for the initial shadow period.

### 6. Validate secrets, APIs, zones, and configuration

```bash
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  setup-check
```

A healthy setup should report:

- accepted Spamhaus authentication and a resolvable IP threat type;
- successful Spamhaus history reconciliation;
- successful Cloudflare access for every configured zone.

### 7. Bootstrap events and inspect classifications

```bash
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  collect --bootstrap-minutes 60
```

Review all candidates:

```bash
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  review
```

Review all READY candidates (note that a READY category may still be excluded from `auto_submit_categories`):

```bash
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  review --status READY
```

Preview exactly what would be submitted:

```bash
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  submit --ready --dry-run
```

### 8. Test the systemd service in shadow mode

Reload units:

```bash
sudo systemctl daemon-reload
```

Verify configuration still disables automatic submission:

```bash
sudo -u spamhaus-reporter \
  grep -n 'auto_submit_enabled' \
  /etc/spamhaus-reporter/config.yaml
```

Run the service once:

```bash
sudo systemctl start spamhaus-reporter.service
```

Check the result:

```bash
sudo systemctl show spamhaus-reporter.service \
  -p Result \
  -p ExecMainCode \
  -p ExecMainStatus
```

Expected:

```text
Result=success
ExecMainCode=0
ExecMainStatus=0
```

Inspect logs:

```bash
sudo journalctl \
  -u spamhaus-reporter.service \
  -n 200 \
  --no-pager
```

When `auto_submit_enabled: false`, a service invocation with `run --auto-submit` still refuses to submit and prints that auto-submit is disabled in configuration.

### 9. Enable the timer in shadow mode

```bash
sudo systemctl enable --now spamhaus-reporter.timer
```

Check:

```bash
systemctl is-enabled spamhaus-reporter.timer
systemctl is-active spamhaus-reporter.timer
systemctl list-timers --all | grep spamhaus-reporter
```

Expected state:

```text
enabled
active
```

At this stage, collection/classification runs automatically every ten minutes, but Spamhaus POSTs remain disabled by configuration.

### 10. Observe shadow mode

Run shadow mode long enough to see representative traffic. Two or three days is a reasonable starting point for many small sites, but high-traffic or unusual applications may need longer.

Useful commands:

```bash
# Recent service activity
sudo journalctl -u spamhaus-reporter.service --since "1 hour ago" --no-pager

# READY candidates
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  review --status READY

# REVIEW candidates
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  review --status REVIEW

# Dry-run outbound payloads
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  submit --ready --dry-run

# Local health
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  health
```

### 11. Enable actual automatic submissions

Stop the timer while changing policy:

```bash
sudo systemctl stop spamhaus-reporter.timer
```

Back up configuration:

```bash
sudo cp -a \
  /etc/spamhaus-reporter/config.yaml \
  "/etc/spamhaus-reporter/config.yaml.backup.$(date +%Y%m%d-%H%M%S)"
```

Edit:

```bash
sudoedit /etc/spamhaus-reporter/config.yaml
```

Change only after reviewing your traffic:

```yaml
classification:
  auto_submit_enabled: true
```

Validate YAML and APIs:

```bash
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/python \
  -c 'import yaml; c=yaml.safe_load(open("/etc/spamhaus-reporter/config.yaml")); assert c["classification"]["auto_submit_enabled"] is True; print("YAML OK / auto-submit enabled")'

sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  setup-check

sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  submit --ready --dry-run
```

If the final dry run is correct, restart only the timer and allow the next scheduled run to perform the first automatic submission:

```bash
sudo systemctl start spamhaus-reporter.timer
```

### 12. Confirm real submission behavior

After a scheduled run:

```bash
sudo journalctl \
  -u spamhaus-reporter.service \
  -n 300 \
  --no-pager
```

Inspect the local attempt ledger:

```bash
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  attempts --limit 100
```

Attempt states:

| State | Meaning |
| --- | --- |
| `claimed` | Reserved locally; POST has not begun yet |
| `sending` | Durable pre-POST transition; request may be in flight |
| `submitted` | Spamhaus accepted the submission |
| `duplicate` | Spamhaus reported it as already submitted (`208`) |
| `remote_existing` | Recent Spamhaus history showed an existing submission |
| `unknown` | Outcome is ambiguous; do not manually retry immediately |
| `failed_definitive` | Spamhaus returned a definitive client/configuration rejection |
| `abandoned_pre_send` | Stale claim recovered; no POST had begun |

If an attempt is `unknown`, do **not** immediately resubmit the same IP manually. The request may have been accepted while the response was lost. Let reconciliation and cooldown logic handle it.

## systemd hardening

The included service runs as an unprivileged account and applies a read-only system view with narrow writable paths.

Key properties include:

```text
User=spamhaus-reporter
Group=spamhaus-reporter
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
```

Writable locations are limited to:

```text
/var/lib/spamhaus-reporter
/var/log/spamhaus-reporter
```

Configuration under `/etc/spamhaus-reporter` and application code under `/opt` are read-only to the service.

## CLI reference

All commands accept `--config <path>` before the subcommand.

### `setup-check`

Validates configuration, checks Spamhaus authentication/threat type, reconciles recent remote history, tests Cloudflare access for each zone, and performs maintenance. It does not submit IPs.

```bash
spamhaus-reporter --config config.yaml setup-check
```

### `collect`

Fetches Cloudflare events incrementally. If no cursor exists, it uses the configured bootstrap window or the command override.

```bash
spamhaus-reporter --config config.yaml collect --bootstrap-minutes 60
```

### `review`

Displays current candidates and submission eligibility.

```bash
spamhaus-reporter --config config.yaml review
spamhaus-reporter --config config.yaml review --status READY
spamhaus-reporter --config config.yaml review --status REVIEW
spamhaus-reporter --config config.yaml review --status IGNORE
```

### `submit`

Dry-run is safe and sends nothing:

```bash
spamhaus-reporter --config config.yaml submit --ready --dry-run
```

A manual real submission requires explicit `--yes`:

```bash
spamhaus-reporter --config config.yaml submit --ready --yes
```

Manual `--yes` is intentionally explicit and does not depend on the scheduled auto-submit switch. Treat it as an operator override.

### `run`

The scheduler entry point:

```bash
spamhaus-reporter --config config.yaml run --auto-submit
```

With `classification.auto_submit_enabled: false`, the command collects and classifies but does not POST to Spamhaus.

### `sync-remote`

Reconciles recent Spamhaus submission history into local rolling state.

```bash
spamhaus-reporter --config config.yaml sync-remote
```

### `attempts`

Displays recent submission-attempt state:

```bash
spamhaus-reporter --config config.yaml attempts --limit 100
```

### `health`

Runs SQLite `quick_check`, shows database size/counts/states, and checks whether all configured zone cursors are reasonably recent.

```bash
spamhaus-reporter --config config.yaml health
```

The command returns non-zero if SQLite is unhealthy or a zone cursor is missing/stale.

### `maintenance`

Prunes rolling data, recovers stale crash states, checkpoints WAL, and optionally compacts the SQLite file.

```bash
spamhaus-reporter --config config.yaml maintenance
spamhaus-reporter --config config.yaml maintenance --compact
```

Do not compact on every ten-minute run. SQLite normally reuses freed pages; explicit compaction is for occasional post-burst maintenance.

## Rolling retention

Production defaults:

```yaml
storage:
  event_retention_hours: 36
  submission_attempt_retention_hours: 72
  unknown_attempt_retention_hours: 72
```

The reporter is not intended to be a permanent threat-intelligence database. Event and attempt history is deliberately bounded.

SQLite may keep reusable free pages after rows are deleted, so the file may remain near a previous high-water mark. Use `maintenance --compact` only when you specifically want to shrink the physical file.

## Cloudflare collection semantics

- Per-zone cursors advance only after the network fetch and durable database insert succeed.
- Each query overlaps the previous cursor by a few minutes to tolerate boundary timing; event fingerprints deduplicate overlapping rows.
- If a query returns exactly the configured page limit, the time range is recursively split instead of silently assuming the page is complete.
- If even a one-second window remains saturated, collection fails instead of silently dropping evidence.
- If any configured zone fails during `run`, automatic submission is suppressed for that run.

## Logging and local files

The application logs both to stderr/journald and to a rotating file configured by `storage.log_path`.

Production defaults retain approximately 15 MB of rotating application logs:

```yaml
log_max_bytes: 5000000
log_backup_count: 3
```

The SQLite database and log file are chmodded to `0600` when possible.

## Allowlisting

CIDR allowlisting is the strongest exclusion mechanism and includes private/special-use networks by default.

You may also configure ASN and User-Agent exclusions. Be careful with User-Agent allowlists: User-Agent strings are attacker-controlled and easily spoofed. Do not use a `Googlebot` string alone as proof that a request came from Google.

## Troubleshooting

### `Permission denied: /etc/spamhaus-reporter/config.yaml`

This is expected for an ordinary shell account when production permissions are `root:spamhaus-reporter 0640`.

Use:

```bash
sudo grep -n 'auto_submit_enabled' /etc/spamhaus-reporter/config.yaml
```

or:

```bash
sudo -u spamhaus-reporter \
  grep -n 'auto_submit_enabled' \
  /etc/spamhaus-reporter/config.yaml
```

Do not make the file world-readable merely to simplify inspection.

### `.env permissions are 640` warning

Version 1.2.0 fixes the older warning logic. Restricted `0640` is valid in the recommended root-owned/service-group deployment. If you still see this warning on 1.2.0, verify the mode with:

```bash
sudo stat -c '%U:%G %a %n' \
  /etc/spamhaus-reporter/.env \
  /etc/spamhaus-reporter/config.yaml
```

### `Permission denied: /run/spamhaus-reporter`

Do not place the persistent process lock under a systemd `RuntimeDirectory` for this deployment. A oneshot service may remove its runtime directory after exit, which can break manual CLI commands run as the unprivileged service account.

Use:

```yaml
storage:
  lock_path: /var/lib/spamhaus-reporter/reporter.lock
```

The production example already uses this path.

### `Cannot import 'setuptools.build_meta'`

Install the build backend into the virtual environment before using `--no-build-isolation`:

```bash
/opt/spamhaus-reporter/current/.venv/bin/python -m pip install 'setuptools>=68' wheel
```

The supplied installer does this automatically.

### Cloudflare HTTP 401 / authentication error

Check:

- the token copied into `/etc/spamhaus-reporter/.env`;
- `Account → Account Analytics → Read` permission;
- the selected zone resources;
- any token IP restrictions;
- that the service account can read `.env`.

Then rerun:

```bash
sudo -u spamhaus-reporter \
  /opt/spamhaus-reporter/current/.venv/bin/spamhaus-reporter \
  --config /etc/spamhaus-reporter/config.yaml \
  setup-check
```

### `NO CURSOR` in health output

The zone has not completed a successful collection. Run `collect`, inspect journald/application logs, and do not enable real automatic submissions until all configured zones collect normally.

### `AlreadyRunningError`

Another reporter process currently owns the process lock. This is intentional protection against manual/scheduled overlap. Wait for the active run to finish. Do not delete the lock file while another reporter process may be running.

## Emergency stop

Disable future scheduled runs immediately:

```bash
sudo systemctl disable --now spamhaus-reporter.timer
```

This cannot undo an HTTP request already sent by a currently running service process, but it prevents future timer executions.

To return the configuration to shadow mode:

```bash
sudoedit /etc/spamhaus-reporter/config.yaml
```

Set:

```yaml
classification:
  auto_submit_enabled: false
```

Then re-enable the timer if desired:

```bash
sudo systemctl enable --now spamhaus-reporter.timer
```

## Upgrading and rollback

The production layout uses immutable versioned releases plus a `current` symlink. The preferred upgrade path is to check out/unpack the new project release and run:

```bash
sudo ./deploy/install.sh
```

The installer refuses to overwrite an existing release directory. If an existing reporter timer is active/enabled, it disables the timer before changing the installed release and deliberately leaves it disabled afterward. Existing `/etc/spamhaus-reporter/config.yaml` and `.env` files are preserved. Re-run `setup-check`, a shadow/systemd oneshot test, and a final dry run before re-enabling the timer.

When upgrading from an older deployment that used `/run/spamhaus-reporter/reporter.lock`, explicitly verify that the preserved configuration now contains:

```yaml
storage:
  lock_path: /var/lib/spamhaus-reporter/reporter.lock
```

For a manual deployment, install the new code into a new directory under:

```text
/opt/spamhaus-reporter/releases/<new-version>
```

Do not overwrite the currently running release in place. After validation, atomically switch the symlink:

```bash
sudo ln -sfnT \
  /opt/spamhaus-reporter/releases/<new-version> \
  /opt/spamhaus-reporter/current
```

Run `setup-check` and a systemd oneshot test before removing older releases.

Rollback is the same operation in reverse:

```bash
sudo systemctl stop spamhaus-reporter.timer
sudo ln -sfnT \
  /opt/spamhaus-reporter/releases/<previous-version> \
  /opt/spamhaus-reporter/current
sudo systemctl start spamhaus-reporter.timer
```

Configuration and SQLite state live outside the release directory and therefore survive code rollback. Database migrations are designed to be conservative, but always review release notes before downgrading across schema changes.

## Tests

Run:

```bash
python -m pip install '.[dev]'
pytest -q
python -m compileall -q spamhaus_reporter
```

The test suite covers classification, reason-length safety, event deduplication, cooldown/new-evidence rules, atomic claims, ambiguous POST behavior, Spamhaus `208` handling, remote reconciliation, crash recovery, retention, Cloudflare retry behavior, configuration validation, and `.env` permission semantics.

GitHub Actions runs the suite across supported Python versions.

## Security notes

- Never commit `.env`.
- Scope Cloudflare access to only the zones needed by this service.
- Keep the Cloudflare token read-only.
- Keep `/etc/spamhaus-reporter` non-world-readable.
- Use a local filesystem for SQLite; do not place the database on NFS or another network filesystem.
- Treat `unknown` POST outcomes as ambiguous and let reconciliation handle them.
- Avoid User-Agent-only trust decisions.
- Start with `auto_submit_enabled: false` on every new environment.

See `SECURITY.md` for vulnerability-reporting guidance.

## License

No license is included in this repository template. If you intend others to copy, modify, or redistribute the project, add an explicit open-source license before publishing.
