#!/bin/bash
#
# Session Pro Backend — pgBackRest REPOSITORY-host setup (Option 2, repo-host-initiated).
#
# Run this ON the backup/repository host as root, after reviewing it:
#
#     cp scripts/pgbackrest/repo-host.env.example scripts/pgbackrest/repo-host.env   # edit it
#     ./scripts/pgbackrest/repo-host-setup.sh
#
# It installs pgbackrest, creates the repository, and schedules backups that PULL PGDATA from the
# primary over SSH. It is idempotent: re-run it after you have authorised its SSH key on the
# primary and it will finish the stanza-create/check/enable steps.
#
# Verified end-to-end against a live primary + repo host on pgbackrest 2.58 (continuous WAL
# archiving + a base backup). The SSH keys must be authorised both ways through the forced-command
# wrapper first (scripts/pgbackrest/pgbackrest-ssh-restrict); this script prints its key and stops
# cleanly until the primary trusts it.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVF="$SCRIPT_DIR/repo-host.env"
if [[ ! -f "$ENVF" ]]; then
    echo "error: $ENVF not found — copy repo-host.env.example and fill it in." >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$ENVF"

: "${PRIMARY_HOST:?set PRIMARY_HOST in repo-host.env}"
: "${PRIMARY_SSH_USER:=postgres}"
: "${PRIMARY_PG_DATA_DIR:?set PRIMARY_PG_DATA_DIR}"
: "${PRIMARY_PG_PORT:?set PRIMARY_PG_PORT}"
: "${REPO_USER:=pgbackrest}"
: "${REPO_PATH:=/var/lib/pgbackrest}"
: "${CIPHER_PASS:?set CIPHER_PASS in repo-host.env, matching the primary}"

STANZA=session_pro
CONFIG=/etc/pgbackrest/session_pro.conf
SSH_DIR="$REPO_PATH/.ssh"

log() { printf '\n=== %s ===\n' "$*"; }

# 1. Package + repository user + directories
log "Installing pgbackrest and creating the repository user"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y pgbackrest openssh-client rsync
if ! id "$REPO_USER" &>/dev/null; then
    # A real shell is required: the primary SSHes into this user to run pgbackrest for
    # archive-push, and even a forced command= executes via the login shell. The key itself is
    # restricted to pgbackrest by the forced command in authorized_keys.
    adduser --system --group --home "$REPO_PATH" --shell /bin/bash "$REPO_USER"
fi
install -d -m 0750 -o "$REPO_USER" -g "$REPO_USER" "$REPO_PATH" "$REPO_PATH/dumps" "$SSH_DIR"

# 2. SSH key for repo -> primary (pull). Generated here; you authorise it on the primary.
log "Preparing SSH key ($REPO_USER -> $PRIMARY_SSH_USER@$PRIMARY_HOST)"
if [[ ! -f "$SSH_DIR/id_ed25519" ]]; then
    runuser -u "$REPO_USER" -- ssh-keygen -t ed25519 -N '' -f "$SSH_DIR/id_ed25519" -C "pgbackrest@$(hostname)"
fi
ssh-keyscan -H "$PRIMARY_HOST" >> "$SSH_DIR/known_hosts" 2>/dev/null || true
sort -u "$SSH_DIR/known_hosts" -o "$SSH_DIR/known_hosts" 2>/dev/null || true
chown -R "$REPO_USER:$REPO_USER" "$SSH_DIR"
chmod 0700 "$SSH_DIR"

# 3. pgBackRest config. A dedicated file we own, referenced with --config on every invocation, so
# pgbackrest never reads the packaged /etc/pgbackrest.conf stub (unreadable by this user, and
# carrying a clashing repo1-path). Not under conf.d, so a bare command can't merge it either.
log "Writing pgBackRest config"
install -d -m 0750 -o root -g "$REPO_USER" /etc/pgbackrest
install -d -m 0750 -o "$REPO_USER" -g "$REPO_USER" "$REPO_PATH/log"
sed -e "s|@REPO_PATH@|${REPO_PATH}|g" \
    -e "s|@CIPHER_PASS@|${CIPHER_PASS}|g" \
    -e "s|@PRIMARY_HOST@|${PRIMARY_HOST}|g" \
    -e "s|@PRIMARY_SSH_USER@|${PRIMARY_SSH_USER}|g" \
    -e "s|@PRIMARY_PG_DATA_DIR@|${PRIMARY_PG_DATA_DIR}|g" \
    -e "s|@PRIMARY_PG_PORT@|${PRIMARY_PG_PORT}|g" \
    "$SCRIPT_DIR/repo-host.conf.example" > "$CONFIG"
chown root:"$REPO_USER" "$CONFIG"
chmod 0640 "$CONFIG"

# 4. Backup runner + daily timer (installed now; enabled once SSH works, below)
install -m 0755 "$SCRIPT_DIR/repo-backup.sh" /usr/local/bin/pro-backend-repo-backup
install -m 0644 "$SCRIPT_DIR/../systemd/pro-backend-backup.service" /etc/systemd/system/pro-backend-backup.service
install -m 0644 "$SCRIPT_DIR/../systemd/pro-backend-backup.timer"   /etc/systemd/system/pro-backend-backup.timer
systemctl daemon-reload

# 5. Finish, IF SSH to the primary already works; otherwise print instructions and stop cleanly.
# The probe runs `pgbackrest version` (not `true`): the forced-command wrapper on the primary
# only permits pgbackrest invocations, so a plain command would be (correctly) denied.
PUBKEY="$(cat "$SSH_DIR/id_ed25519.pub")"
if runuser -u "$REPO_USER" -- ssh -o BatchMode=yes -o ConnectTimeout=10 \
        "${PRIMARY_SSH_USER}@${PRIMARY_HOST}" pgbackrest version >/dev/null 2>&1; then
    log "SSH to the primary works — creating and checking the stanza"
    runuser -u "$REPO_USER" -- pgbackrest --config="$CONFIG" --stanza="$STANZA" stanza-create
    runuser -u "$REPO_USER" -- pgbackrest --config="$CONFIG" --stanza="$STANZA" check
    systemctl enable --now pro-backend-backup.timer
    echo "Repository host configured; daily backups scheduled."
else
    cat <<EOF

=======================================================================================
Almost done. Authorise this host's key on the PRIMARY, then re-run this script.

On the primary, add to ${PRIMARY_SSH_USER}'s ~/.ssh/authorized_keys (ideally RESTRICTED to
the pgbackrest remote command via a forced command= wrapper — confirm the exact wrapper
against the pgBackRest docs during verification):

$PUBKEY

You will also need the primary's archive-push key authorised HERE (repo user "$REPO_USER").
Re-run this script once SSH ${REPO_USER}@$(hostname) -> ${PRIMARY_SSH_USER}@${PRIMARY_HOST}
succeeds; it will then run stanza-create/check and enable the timer.
=======================================================================================
EOF
fi
