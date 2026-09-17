#!/usr/bin/env bash
set -euo pipefail

# Hardened production installer for a Debian/Ubuntu-style systemd host.
# It intentionally does NOT enable auto-submit and does NOT start the timer.

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "ERROR: run this installer as root (for example: sudo ./deploy/install.sh)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
VERSION="$(awk -F'"' '/^version = / {print $2; exit}' "$REPO_ROOT/pyproject.toml")"

if [[ -z "$VERSION" ]]; then
  echo "ERROR: could not determine version from pyproject.toml" >&2
  exit 1
fi

SERVICE_USER="spamhaus-reporter"
SERVICE_GROUP="spamhaus-reporter"
BASE_DIR="/opt/spamhaus-reporter"
RELEASE_DIR="$BASE_DIR/releases/$VERSION"
CURRENT_LINK="$BASE_DIR/current"
CONFIG_DIR="/etc/spamhaus-reporter"
STATE_DIR="/var/lib/spamhaus-reporter"
LOG_DIR="/var/log/spamhaus-reporter"

for cmd in python3 tar systemctl systemd-analyze install awk getent groupadd useradd id grep; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $cmd" >&2
    exit 1
  }
done

python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit(f"ERROR: Python 3.10+ is required; found {sys.version.split()[0]}")
print(f"Python: {sys.version.split()[0]}")
PY

if [[ -e "$RELEASE_DIR" ]]; then
  echo "ERROR: release already exists: $RELEASE_DIR" >&2
  echo "Remove it only if you are certain it is not an active/needed release." >&2
  exit 1
fi

# Upgrades must not race a scheduled reporter run. If an existing timer is
# enabled/active, disable it and require explicit re-enablement after validation.
EXISTING_TIMER_DISABLED=0
if systemctl is-enabled --quiet spamhaus-reporter.timer 2>/dev/null || \
   systemctl is-active --quiet spamhaus-reporter.timer 2>/dev/null; then
  echo "Stopping and disabling existing spamhaus-reporter.timer for safe installation/upgrade..."
  systemctl disable --now spamhaus-reporter.timer || true
  EXISTING_TIMER_DISABLED=1
fi

if ! getent group "$SERVICE_GROUP" >/dev/null; then
  groupadd --system "$SERVICE_GROUP"
fi
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --gid "$SERVICE_GROUP" --home /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# Ensure manual `sudo -u spamhaus-reporter ...` invocations receive the same
# service group used by systemd, even if the account pre-existed.
if ! id -nG "$SERVICE_USER" | grep -Eq "(^| )${SERVICE_GROUP}( |$)"; then
  command -v usermod >/dev/null 2>&1 || {
    echo "ERROR: usermod is required to add $SERVICE_USER to $SERVICE_GROUP" >&2
    exit 1
  }
  usermod -a -G "$SERVICE_GROUP" "$SERVICE_USER"
fi

install -d -o root -g root -m 0755 "$BASE_DIR" "$BASE_DIR/releases"
install -d -o root -g root -m 0755 "$RELEASE_DIR"

# Copy source without local secrets, VCS metadata, runtime state, or virtualenvs.
tar -C "$REPO_ROOT" \
  --exclude='.git' \
  --exclude='.venv' \
  --exclude='.env' \
  --exclude='config.yaml' \
  --exclude='*.sqlite3' \
  --exclude='*.sqlite3-shm' \
  --exclude='*.sqlite3-wal' \
  --exclude='*.log' \
  -cf - . | tar -C "$RELEASE_DIR" -xf -

python3 -m venv "$RELEASE_DIR/.venv"
"$RELEASE_DIR/.venv/bin/python" -m pip install --upgrade pip 'setuptools>=68' wheel
"$RELEASE_DIR/.venv/bin/python" -m pip install --no-cache-dir -r "$RELEASE_DIR/requirements.txt"
"$RELEASE_DIR/.venv/bin/python" -m pip install --no-cache-dir --no-deps --no-build-isolation "$RELEASE_DIR"
"$RELEASE_DIR/.venv/bin/python" -m compileall -q "$RELEASE_DIR/spamhaus_reporter"
rm -rf "$RELEASE_DIR/build" "$RELEASE_DIR"/*.egg-info

chown -R root:root "$RELEASE_DIR"
chmod -R go-w "$RELEASE_DIR"
if [[ -e "$CURRENT_LINK" && ! -L "$CURRENT_LINK" ]]; then
  echo "ERROR: $CURRENT_LINK exists but is not a symlink; refusing to overwrite it" >&2
  exit 1
fi
ln -sfnT "$RELEASE_DIR" "$CURRENT_LINK"

install -d -o root -g "$SERVICE_GROUP" -m 0750 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0700 "$STATE_DIR" "$LOG_DIR"
# Pre-create the persistent lock with service ownership. This prevents an
# operator's later root invocation from accidentally creating a root-owned lock
# that the service account cannot reopen.
install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0600 /dev/null "$STATE_DIR/reporter.lock"

if [[ ! -e "$CONFIG_DIR/config.yaml" ]]; then
  install -o root -g "$SERVICE_GROUP" -m 0640 \
    "$RELEASE_DIR/deploy/config.production.yaml.example" \
    "$CONFIG_DIR/config.yaml"
  echo "Created $CONFIG_DIR/config.yaml from the production example."
else
  echo "Keeping existing $CONFIG_DIR/config.yaml"
fi

if [[ ! -e "$CONFIG_DIR/.env" ]]; then
  install -o root -g "$SERVICE_GROUP" -m 0640 \
    "$RELEASE_DIR/.env.example" \
    "$CONFIG_DIR/.env"
  echo "Created $CONFIG_DIR/.env from .env.example."
else
  echo "Keeping existing $CONFIG_DIR/.env"
fi

# Reassert restrictive ownership/modes even on upgrades.
chown root:"$SERVICE_GROUP" "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/.env"
chmod 0640 "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/.env"
chmod 0750 "$CONFIG_DIR"

install -o root -g root -m 0644 \
  "$RELEASE_DIR/deploy/systemd/spamhaus-reporter.service" \
  /etc/systemd/system/spamhaus-reporter.service
install -o root -g root -m 0644 \
  "$RELEASE_DIR/deploy/systemd/spamhaus-reporter.timer" \
  /etc/systemd/system/spamhaus-reporter.timer

systemctl daemon-reload
systemd-analyze verify \
  /etc/systemd/system/spamhaus-reporter.service \
  /etc/systemd/system/spamhaus-reporter.timer || {
    echo "ERROR: systemd unit verification failed" >&2
    exit 1
  }

cat <<EOF

Installed spamhaus-reporter $VERSION.

The timer was NOT enabled and no report was submitted.
$([[ "$EXISTING_TIMER_DISABLED" -eq 1 ]] && echo "An existing timer was disabled for safety and must be re-enabled after validation." || true)

Next steps:
  1. Edit secrets:
       sudoedit $CONFIG_DIR/.env
  2. Edit zones and review thresholds:
       sudoedit $CONFIG_DIR/config.yaml
  3. Keep classification.auto_submit_enabled: false initially.
  4. Validate:
       sudo -u $SERVICE_USER $CURRENT_LINK/.venv/bin/spamhaus-reporter --config $CONFIG_DIR/config.yaml setup-check
  5. Bootstrap and review shadow-mode data:
       sudo -u $SERVICE_USER $CURRENT_LINK/.venv/bin/spamhaus-reporter --config $CONFIG_DIR/config.yaml collect --bootstrap-minutes 60
       sudo -u $SERVICE_USER $CURRENT_LINK/.venv/bin/spamhaus-reporter --config $CONFIG_DIR/config.yaml review --status READY
       sudo -u $SERVICE_USER $CURRENT_LINK/.venv/bin/spamhaus-reporter --config $CONFIG_DIR/config.yaml submit --ready --dry-run
  6. Enable the timer only after validation:
       sudo systemctl enable --now spamhaus-reporter.timer
EOF
