#!/bin/bash
#
# Session Pro Backend — purge / uninstall the PRIMARY (Phase 1).
#
# DESTRUCTIVE. Tears down the primary so you can redeploy cleanly:
#   - removes the uWSGI Emperor vassal (the Emperor stops the instance)
#   - removes the nginx vhost
#   - drops the dedicated `session_pro` PostgreSQL cluster (ALL its data)
#   - removes the app user, code, config, keys, logs, and the primary's pgBackRest config
#     (the Ed25519 signing key is copied to /root first so a redeploy can reuse it)
#
# It does NOT touch shared packages (postgresql, nginx, pgbackrest) or any OTHER
# clusters/databases on the box.
#
# NOTE: the pgBackRest REPOSITORY host is separate infrastructure and is NOT torn down here.
# To discard the off-host backups, on the repository host run (as the repo user):
#     pgbackrest --stanza=session_pro stanza-delete --force
# and remove its /etc/pgbackrest/session_pro.conf + backup timer.
#
# Usage:
#   ./scripts/purge.sh          # prompts for confirmation
#   ./scripts/purge.sh --yes    # non-interactive
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root." >&2
    exit 1
fi

ASSUME_YES=false
for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=true ;;
        *) echo "unknown argument: $arg" >&2; exit 1 ;;
    esac
done

PRO_USER="pro-backend"
PG_CLUSTER="session_pro"
CODE_DIR="/opt/session-pro-backend"
ETC_DIR="/etc/session-pro-backend"
LOG_DIR="/var/log/pro-backend"
DATA_DIR="/var/lib/pro-backend"
PGBR_CONF="/etc/pgbackrest/session_pro.conf"

log() { printf '\n=== %s ===\n' "$*"; }

if ! $ASSUME_YES; then
    echo "This will PERMANENTLY DESTROY the '$PG_CLUSTER' database and this primary deployment."
    echo "(The pgBackRest repository host, if any, is NOT touched — tear it down separately.)"
    read -r -p "Type 'yes' to proceed: " ans
    [[ "$ans" == "yes" ]] || { echo "Aborted."; exit 1; }
fi

# 1. uWSGI vassal (the Emperor stops the instance when the file disappears)
log "Removing uWSGI vassal"
rm -f /etc/uwsgi-emperor/vassals/pro-backend.ini
rm -f /etc/tmpfiles.d/pro-backend.conf
rm -rf /run/pro-backend

# 2. nginx vhost (reload only if the remaining config still validates)
log "Removing nginx vhost"
rm -f /etc/nginx/sites-enabled/pro-backend /etc/nginx/sites-available/pro-backend
if nginx -t 2>/dev/null; then systemctl reload nginx 2>/dev/null || true; fi

# 3. PostgreSQL cluster (drops the data dir + config, which also removes the ALTER SYSTEM
#    archive settings). The off-host stanza lives on the repo host and is not touched here.
if pg_lsclusters -h | awk '{print $2}' | grep -qx "$PG_CLUSTER"; then
    PG_VERSION="$(pg_lsclusters -h | awk -v c="$PG_CLUSTER" '$2==c {print $1}')"
    log "Dropping cluster ${PG_VERSION}/${PG_CLUSTER}"
    pg_dropcluster "$PG_VERSION" "$PG_CLUSTER" --stop
fi

# 4. Primary's pgBackRest config + archive spool
rm -f "$PGBR_CONF"
rm -rf /var/spool/pgbackrest

# 5. App user + files. The Ed25519 signing key is a credential, not DB state, and cannot be
# recovered if lost. Losing it does NOT invalidate proofs already issued (clients keep verifying
# against the pubkey they hold) — but no new proofs can be signed until a new key is rolled and its
# pubkey shipped to every client app. So preserve a copy (root-only) before wiping, and tell the
# operator how to reuse it on the next deploy.
log "Removing app user and files"
if [[ -f "$ETC_DIR/key_ed25519" ]]; then
    key_backup="/root/session-pro-key_ed25519.$(date +%Y%m%d-%H%M%S).bak"
    cp "$ETC_DIR/key_ed25519" "$key_backup"
    chmod 0400 "$key_backup"
    echo "Preserved the signing key at $key_backup"
    echo "  Reuse it on redeploy:  BACKEND_KEY_SRC=$key_backup bash scripts/deploy.sh"
    echo "  (delete that file if you truly want the key gone)"
fi
rm -rf "$CODE_DIR" "$ETC_DIR" "$LOG_DIR" "$DATA_DIR"
if id "$PRO_USER" &>/dev/null; then
    deluser --quiet "$PRO_USER" 2>/dev/null || userdel "$PRO_USER" 2>/dev/null || true
fi
delgroup --quiet "$PRO_USER" 2>/dev/null || true

cat <<EOF

=======================================================================================
Primary purged. Shared packages and other databases were left untouched.
If a pgBackRest repository host exists, tear it down there separately (stanza-delete +
remove its config/timer). Re-run scripts/deploy.sh for a fresh deployment.
=======================================================================================
EOF
