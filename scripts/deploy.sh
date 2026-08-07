#!/bin/bash
#
# Session Pro Backend — deployment installer.
#
# Run this ON the target host (Debian) as root, from a checkout of this repo:
#
#     cp scripts/deploy.env.example deploy.env   # then edit it
#     ./scripts/deploy.sh          # as root (these servers ship without sudo)
#
# It is idempotent: safe to re-run to update code/config/vassal. It provisions everything
# under a dedicated non-root system user, in a DEDICATED PostgreSQL cluster (leaving other
# clusters/databases on the box untouched), serves the app as a vassal of the pre-existing
# uWSGI tyrant Emperor, and configures off-host pgBackRest durability. TLS is intentionally
# NOT configured — see the note printed at the end.
#
# Prerequisites (this script does NOT set these up — they are shared fleet infrastructure):
#   - a running uWSGI Emperor with `emperor-tyrant = true` and `cap = setgid,setuid`
#   - PostgreSQL installed (any Debian-shipped version)
#   - for backups: SSH from this host's postgres user to the pgBackRest repo host
#
# See docs/deploy.md for the full guide and disaster-recovery runbook.
set -euo pipefail

# --------------------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# Load deploy.env (from the repo root or the scripts dir), then apply defaults.
for envf in "$REPO_DIR/deploy.env" "$SCRIPT_DIR/deploy.env"; do
    if [[ -f "$envf" ]]; then
        # shellcheck disable=SC1090
        source "$envf"
        echo "Loaded configuration from $envf"
        break
    fi
done

GIT_REPO="${GIT_REPO:-https://github.com/session-foundation/session-pro-backend}"
GIT_REF="${GIT_REF:-main}"
PRO_DOMAIN="${PRO_DOMAIN:-pro.example.org}"
WITH_PROVIDER_APP_STORE="${WITH_PROVIDER_APP_STORE:-false}"
WITH_PROVIDER_GOOGLE_PLAY="${WITH_PROVIDER_GOOGLE_PLAY:-false}"
PGBACKREST_REPO_HOST="${PGBACKREST_REPO_HOST:-}"
PGBACKREST_REPO_HOST_USER="${PGBACKREST_REPO_HOST_USER:-pgbackrest}"
PGBACKREST_REPO_PATH="${PGBACKREST_REPO_PATH:-/var/lib/pgbackrest}"
PGBACKREST_CIPHER_PASS="${PGBACKREST_CIPHER_PASS:-}"
PG_ARCHIVE_TIMEOUT="${PG_ARCHIVE_TIMEOUT:-30}"

# Fixed layout.
PRO_USER="pro-backend"
CODE_DIR="/opt/session-pro-backend"
VENV_DIR="$CODE_DIR/.venv"
ETC_DIR="/etc/session-pro-backend"
CONFIG_INI="$ETC_DIR/config.ini"
KEYS_DIR="$ETC_DIR/keys"
BACKEND_KEY_FILE="$ETC_DIR/key_ed25519"
LOG_DIR="/var/log/pro-backend"
VASSAL="/etc/uwsgi-emperor/vassals/pro-backend.ini"
EMPEROR_INI="/etc/uwsgi-emperor/emperor.ini"
PG_CLUSTER="session_pro"
PG_DB="session_pro"

log() { printf '\n=== %s ===\n' "$*"; }

# --------------------------------------------------------------------------------------
# 1. Packages
# --------------------------------------------------------------------------------------
# Prefer Debian-shipped libraries (leaner, security-updated, no compiler needed). flask, pynacl,
# pendulum, psycopg and uWSGI come from apt; only the deps Debian lacks go in the venv.
log "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update

# Two extra apt repositories must already be configured on this host — they are system-wide apt
# config that the operator owns, not something this script edits (see docs/deploy.md, "Prerequisite
# apt repositories"):
#   * PGDG -> pgbackrest, pinned. Its version must match the repo host; the distro version differs
#             across Debian releases (bookworm vs trixie) and would break remote backups.
#   * oxen -> python3-session-util (the Session onion-request binding; pulls its own runtime lib).
# Verify they actually provide what we need, and stop with instructions if not — rather than
# installing a mismatched pgbackrest or dying cryptically half-way through.
repo_error=0
pgbackrest_candidate="$(apt-cache policy pgbackrest 2>/dev/null | awk '/Candidate:/ {print $2}')"
if [[ "$pgbackrest_candidate" != *pgdg* ]]; then
    echo "error: pgbackrest is not available from PGDG (candidate: ${pgbackrest_candidate:-none})." >&2
    echo "       pgBackRest must match the repo host's version. Configure the PGDG apt repo + pin as" >&2
    echo "       described in docs/deploy.md, run 'apt-get update', then re-run this script." >&2
    repo_error=1
fi
session_util_candidate="$(apt-cache policy python3-session-util 2>/dev/null | awk '/Candidate:/ {print $2}')"
if [[ -z "$session_util_candidate" || "$session_util_candidate" == "(none)" ]]; then
    echo "error: python3-session-util is not available. Configure the oxen apt repo as described in" >&2
    echo "       docs/deploy.md, run 'apt-get update', then re-run this script." >&2
    repo_error=1
fi
[[ "$repo_error" -eq 0 ]] || exit 1

apt-get install -y \
    ca-certificates curl git gnupg lsb-release rsync \
    python3 python3-venv python3-pip \
    python3-coloredlogs python3-flask python3-nacl python3-pendulum python3-psycopg python3-psycopg-c python3-psycopg-pool \
    uwsgi-emperor uwsgi-plugin-python3 \
    postgresql postgresql-contrib pgbackrest \
    python3-session-util \
    nginx

# --------------------------------------------------------------------------------------
# 2. Dedicated non-root system user
# --------------------------------------------------------------------------------------
log "Creating system user '$PRO_USER'"
if ! id "$PRO_USER" &>/dev/null; then
    adduser --system --group --no-create-home --home "$CODE_DIR" \
            --shell /usr/sbin/nologin "$PRO_USER"
fi
# nginx (www-data) needs to reach the uWSGI socket owned by the pro-backend group.
usermod -aG "$PRO_USER" www-data

# --------------------------------------------------------------------------------------
# 3. Directories
# --------------------------------------------------------------------------------------
log "Creating directories"
install -d -m 0755 -o "$PRO_USER" -g "$PRO_USER" "$CODE_DIR"
install -d -m 0750 -o root -g "$PRO_USER" "$ETC_DIR"
install -d -m 0750 -o "$PRO_USER" -g "$PRO_USER" "$KEYS_DIR"
install -d -m 0750 -o "$PRO_USER" -g "$PRO_USER" "$LOG_DIR"

# --------------------------------------------------------------------------------------
# 4. Application code
# --------------------------------------------------------------------------------------
# Prefer the commit currently checked out where deploy.sh is being run (handles unpushed
# commits and avoids hard-coding origin/main). Fall back to GIT_REPO/GIT_REF only when deploy.sh
# is not inside a git checkout.
if git -C "$REPO_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    src_commit="$(git -C "$REPO_DIR" rev-parse HEAD)"
    src_remote="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || true)"
    # A dev checkout's origin is usually git@... (SSH) which won't clone on the target; record
    # the https form so the deployed tree can fetch updates later.
    src_remote="$(printf '%s' "$src_remote" | sed -E 's#^git@([^:]+):#https://\1/#; s#^ssh://git@([^/]+)/#https://\1/#')"
    log "Fetching application code (commit ${src_commit} from $REPO_DIR; remote: ${src_remote:-none})"
    rm -rf "$CODE_DIR"
    git clone --no-hardlinks --quiet "$REPO_DIR" "$CODE_DIR"
    git -C "$CODE_DIR" checkout --quiet --detach "$src_commit"
    [[ -n "$src_remote" ]] && git -C "$CODE_DIR" remote set-url origin "$src_remote"
    chown -R "$PRO_USER:$PRO_USER" "$CODE_DIR"
else
    log "Fetching application code (${GIT_REPO} @ ${GIT_REF})"
    if [[ -d "$CODE_DIR/.git" ]]; then
        runuser -u "$PRO_USER" -- git -C "$CODE_DIR" remote set-url origin "$GIT_REPO"
        runuser -u "$PRO_USER" -- git -C "$CODE_DIR" fetch --prune origin
        runuser -u "$PRO_USER" -- git -C "$CODE_DIR" checkout "$GIT_REF"
        runuser -u "$PRO_USER" -- git -C "$CODE_DIR" reset --hard "origin/$GIT_REF"
    else
        runuser -u "$PRO_USER" -- git clone --branch "$GIT_REF" "$GIT_REPO" "$CODE_DIR"
    fi
fi

# --------------------------------------------------------------------------------------
# 5. Python virtualenv — ONLY the deps Debian does not ship adequately
# --------------------------------------------------------------------------------------
# --system-site-packages so the apt-installed flask/pynacl/psycopg2/session_util are visible.
# uWSGI comes from the Emperor; sqlalchemy is temporary (apt ships 1.4, the code uses the 2.0
# API) and is removed in the Phase 2 refactor.
log "Setting up virtualenv"
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    runuser -u "$PRO_USER" -- python3 -m venv --system-site-packages "$VENV_DIR"
fi
runuser -u "$PRO_USER" -- "$VENV_DIR/bin/pip" install --upgrade pip
# requirements.txt is the single source of truth (no dep list duplicated here). Because the venv
# is --system-site-packages, pip reports the apt-installed flask/pynacl/psycopg2 as already
# satisfied and installs ONLY what Debian lacks: sqlalchemy (2.0.x) + the Apple/Google SDKs.
runuser -u "$PRO_USER" -- "$VENV_DIR/bin/pip" install -r "$CODE_DIR/requirements.txt"

# --------------------------------------------------------------------------------------
# 6. PostgreSQL: dedicated cluster + role + database (peer auth over the socket)
# --------------------------------------------------------------------------------------
log "Configuring PostgreSQL"
PG_VERSION="$(ls /usr/lib/postgresql/ | sort -V | tail -1)"
echo "Using installed PostgreSQL major version: $PG_VERSION"

if ! pg_lsclusters -h | awk '{print $2}' | grep -qx "$PG_CLUSTER"; then
    echo "Creating dedicated cluster $PG_VERSION/$PG_CLUSTER (auto-assigned port)"
    pg_createcluster "$PG_VERSION" "$PG_CLUSTER" -- --auth-local=peer
fi
systemctl enable --now "postgresql@${PG_VERSION}-${PG_CLUSTER}.service"

# Discover the auto-assigned port + data dir by cluster name (never hardcoded).
PG_PORT="$(pg_lsclusters -h | awk -v c="$PG_CLUSTER" '$2==c {print $3}')"
PG_DATA_DIR="$(pg_lsclusters -h | awk -v c="$PG_CLUSTER" '$2==c {print $6}')"
echo "Cluster $PG_CLUSTER is on port $PG_PORT (data: $PG_DATA_DIR)"

psql_admin() { runuser -u postgres -- psql --port="$PG_PORT" -v ON_ERROR_STOP=1 "$@"; }

if [[ "$(psql_admin -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PRO_USER}'")" != "1" ]]; then
    echo "Creating role $PRO_USER"
    psql_admin -c "CREATE ROLE \"${PRO_USER}\" LOGIN;"
fi
if [[ "$(psql_admin -tAc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'")" != "1" ]]; then
    echo "Creating database $PG_DB"
    psql_admin -c "CREATE DATABASE \"${PG_DB}\" OWNER \"${PRO_USER}\";"
fi

# --------------------------------------------------------------------------------------
# 6b. Backend signing key (Ed25519). Loaded from disk by the app and NEVER stored in the DB, so it
# is never in a DB backup. Root-owned + group-readable: the app reads it but its user cannot
# overwrite its own signing key. deploy never generates a key: provide one via BACKEND_KEY_SRC=<file>
# (make one with `session-router-config -k <file>`); an existing key is kept on re-runs, else deploy fails.
# --------------------------------------------------------------------------------------
log "Configuring backend signing key"
if [[ -n "${BACKEND_KEY_SRC:-}" ]]; then
    echo "Installing provided signing key from $BACKEND_KEY_SRC"
    key_hex="$(tr -d '[:space:]' < "$BACKEND_KEY_SRC")"
    if ! [[ "$key_hex" =~ ^[0-9a-fA-F]{128}$ ]]; then
        echo "error: $BACKEND_KEY_SRC must contain 128 hex chars (a 64-byte libsodium ed25519 secret key)" >&2
        exit 1
    fi
    printf '%s\n' "$key_hex" > "$BACKEND_KEY_FILE"
elif [[ -f "$BACKEND_KEY_FILE" ]]; then
    echo "Keeping existing signing key ($BACKEND_KEY_FILE)"
else
    echo "error: no signing key at $BACKEND_KEY_FILE and BACKEND_KEY_SRC is not set." >&2
    echo "  Generate one with:  session-router-config -k <file>" >&2
    echo "  then re-run with:   BACKEND_KEY_SRC=<file> $0" >&2
    exit 1
fi
chown root:"$PRO_USER" "$BACKEND_KEY_FILE"
chmod 0440 "$BACKEND_KEY_FILE"

# --------------------------------------------------------------------------------------
# 7. Application config (config.ini): install if absent, always fix db_url + provider toggles
# --------------------------------------------------------------------------------------
log "Writing application config"
if [[ ! -f "$CONFIG_INI" ]]; then
    install -m 0640 -o "$PRO_USER" -g "$PRO_USER" "$SCRIPT_DIR/config.ini.example" "$CONFIG_INI"
    echo "Installed fresh $CONFIG_INI (fill in [apple]/[google] secrets as needed)"
fi
DB_URL="postgresql:///${PG_DB}?host=/var/run/postgresql&port=${PG_PORT}&user=${PRO_USER}"
DB_URL_ESC="${DB_URL//&/\\&}"
sed -i \
    -e "s|^db_url .*|db_url                 = ${DB_URL_ESC}|" \
    -e "s|^backend_key_path .*|backend_key_path       = ${BACKEND_KEY_FILE}|" \
    -e "s|^with_provider_app_store .*|with_provider_app_store    = ${WITH_PROVIDER_APP_STORE}|" \
    -e "s|^with_provider_google_play .*|with_provider_google_play   = ${WITH_PROVIDER_GOOGLE_PLAY}|" \
    "$CONFIG_INI"

# Apple root certificates, vendored in the repo (scripts/apple-certs/). The app-store-server-library
# verifies Apple's signed payloads against these explicitly — they are NOT in the OS trust store —
# so they must be present whenever Apple is enabled. Installed unconditionally: they are public,
# static (they rotate about once a decade), and harmless when Apple is disabled. The .p8 key and
# Google JSON, being secrets, are placed into $KEYS_DIR by the operator, not here.
install -m 0644 -o "$PRO_USER" -g "$PRO_USER" "$SCRIPT_DIR"/apple-certs/*.cer "$KEYS_DIR/"

# --------------------------------------------------------------------------------------
# 8. uWSGI Emperor vassal (the Emperor itself is pre-existing shared infrastructure)
# --------------------------------------------------------------------------------------
log "Installing uWSGI Emperor vassal"
# Refuse to install into a non-tyrant Emperor — the vassal must run as the unprivileged
# pro-backend user; without tyrant it would run as root.
if ! grep -qE '^\s*emperor-tyrant\s*=\s*true' "$EMPEROR_INI" 2>/dev/null; then
    echo "error: uWSGI Emperor is not configured with 'emperor-tyrant = true' in $EMPEROR_INI." >&2
    echo "       This vassal must run as '$PRO_USER'; refusing to install into a non-tyrant" >&2
    echo "       Emperor (it would run as root). Configure the shared Emperor first." >&2
    exit 1
fi

# Socket directory (no systemd RuntimeDirectory now): owned by the vassal user, group-owned by
# www-data so nginx can traverse it; recreated on boot by systemd-tmpfiles.
echo 'd /run/pro-backend 0750 pro-backend www-data -' > /etc/tmpfiles.d/pro-backend.conf
systemd-tmpfiles --create /etc/tmpfiles.d/pro-backend.conf

# Vassal owned by pro-backend so emperor-tyrant runs it as that user.
install -d -m 0755 /etc/uwsgi-emperor/vassals
install -m 0644 -o "$PRO_USER" -g "$PRO_USER" "$SCRIPT_DIR/uwsgi/pro-backend.ini" "$VASSAL"

systemctl enable --now uwsgi-emperor
touch "$VASSAL"   # nudge the Emperor to (re)load the vassal

# --------------------------------------------------------------------------------------
# 9. nginx (HTTP reverse proxy only; TLS is the admin's job)
# --------------------------------------------------------------------------------------
log "Installing nginx vhost"
sed "s|@PRO_DOMAIN@|${PRO_DOMAIN}|g" "$SCRIPT_DIR/nginx/pro-backend.conf.example" \
    > /etc/nginx/sites-available/pro-backend
ln -sf /etc/nginx/sites-available/pro-backend /etc/nginx/sites-enabled/pro-backend
nginx -t
# restart (not reload): picks up www-data's new pro-backend group membership so workers can
# reach the socket — a reload does not re-run initgroups for the worker processes.
systemctl restart nginx

# --------------------------------------------------------------------------------------
# 10. WAL archiving to the pgBackRest repository host — skipped if no repo host configured
# --------------------------------------------------------------------------------------
# Option 2 (repo-host-initiated): this primary ONLY archives WAL to the remote repository.
# Backups (stanza-create/backup/check) are initiated ON THE REPO host — see repo-host-setup.sh.
if [[ -n "$PGBACKREST_REPO_HOST" ]]; then
    log "Configuring WAL archiving to the pgBackRest repository host"

    # Cipher passphrase (MUST match the repo host's): reuse existing, else deploy.env, else
    # generate + record. archive-push writes encrypted WAL, so the primary needs it too.
    CIPHER_FILE="$ETC_DIR/pgbackrest-cipher.pass"
    if [[ -n "$PGBACKREST_CIPHER_PASS" ]]; then
        echo -n "$PGBACKREST_CIPHER_PASS" > "$CIPHER_FILE"
    elif [[ ! -f "$CIPHER_FILE" ]]; then
        openssl rand -hex 32 > "$CIPHER_FILE"
        echo "Generated pgBackRest repo cipher pass at $CIPHER_FILE — BACK THIS UP."
    fi
    chmod 0600 "$CIPHER_FILE"
    CIPHER_PASS="$(cat "$CIPHER_FILE")"

    # Our config is a dedicated file we own, referenced explicitly with --config on every
    # invocation, so pgbackrest never reads the packaged /etc/pgbackrest.conf stub (whose
    # repo1-path would clash). repo1-host-config inside it points the repo host's remote helper
    # back at this same path. Not placed under conf.d, so a bare pgbackrest command can't merge it.
    install -d -m 0750 -o root -g postgres /etc/pgbackrest
    install -d -m 0750 -o postgres -g postgres /var/spool/pgbackrest /var/log/pgbackrest
    sed -e "s|@REPO_HOST@|${PGBACKREST_REPO_HOST}|g" \
        -e "s|@REPO_HOST_USER@|${PGBACKREST_REPO_HOST_USER}|g" \
        -e "s|@REPO_PATH@|${PGBACKREST_REPO_PATH}|g" \
        -e "s|@CIPHER_PASS@|${CIPHER_PASS}|g" \
        -e "s|@PG_DATA_DIR@|${PG_DATA_DIR}|g" \
        -e "s|@PG_PORT@|${PG_PORT}|g" \
        "$SCRIPT_DIR/pgbackrest/primary.conf.example" > /etc/pgbackrest/session_pro.conf
    chown root:postgres /etc/pgbackrest/session_pro.conf
    chmod 0640 /etc/pgbackrest/session_pro.conf

    # Enable WAL archiving (ALTER SYSTEM → postgresql.auto.conf). archive-push runs as postgres
    # and pushes to the repo host over SSH; until the repo host's stanza exists, pushes fail and
    # WAL is retained — self-heals once repo-host-setup.sh has run stanza-create.
    psql_admin -c "ALTER SYSTEM SET archive_mode = 'on';"
    psql_admin -c "ALTER SYSTEM SET archive_command = 'pgbackrest --config=/etc/pgbackrest/session_pro.conf --stanza=${PG_CLUSTER} archive-push %p';"
    psql_admin -c "ALTER SYSTEM SET archive_timeout = '${PG_ARCHIVE_TIMEOUT}s';"
    systemctl restart "postgresql@${PG_VERSION}-${PG_CLUSTER}.service"

    # SSH key for archive-push (postgres -> repo host). You authorise it on the repo host.
    PG_HOME="$(getent passwd postgres | cut -d: -f6)"
    install -d -m 0700 -o postgres -g postgres "$PG_HOME/.ssh"
    if [[ ! -f "$PG_HOME/.ssh/id_ed25519" ]]; then
        runuser -u postgres -- ssh-keygen -t ed25519 -N '' -f "$PG_HOME/.ssh/id_ed25519" -C "pgbackrest-archive@$(hostname)"
    fi
    ssh-keyscan -H "$PGBACKREST_REPO_HOST" >> "$PG_HOME/.ssh/known_hosts" 2>/dev/null || true
    chown -R postgres:postgres "$PG_HOME/.ssh"

    cat <<EOF

--- pgBackRest repository-host handoff -------------------------------------------------
Backups are initiated ON THE REPOSITORY HOST. On ${PGBACKREST_REPO_HOST}, fill
scripts/pgbackrest/repo-host.env with:

  PRIMARY_HOST="$(hostname -f 2>/dev/null || hostname)"
  PRIMARY_SSH_USER="postgres"
  PRIMARY_PG_DATA_DIR="${PG_DATA_DIR}"
  PRIMARY_PG_PORT="${PG_PORT}"
  CIPHER_PASS=   # copy from ${CIPHER_FILE} securely (do NOT paste it into logs)

...then run scripts/pgbackrest/repo-host-setup.sh there. Authorise THIS host's archive-push
key on the repo host (user ${PGBACKREST_REPO_HOST_USER}):

$(cat "$PG_HOME/.ssh/id_ed25519.pub")
----------------------------------------------------------------------------------------
EOF
else
    log "pgBackRest skipped (PGBACKREST_REPO_HOST not set) — NO off-host WAL archiving configured"
fi

# --------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------
cat <<EOF

=======================================================================================
Session Pro Backend deployed.

  Code:      $CODE_DIR   (user: $PRO_USER)
  Config:    $CONFIG_INI
  Signing key: $BACKEND_KEY_FILE  (on disk only — NOT in the DB or its backups; back it up separately!)
  Cluster:   ${PG_VERSION}/${PG_CLUSTER}  port ${PG_PORT}  (dedicated; other clusters untouched)
  Vassal:    $VASSAL  (Emperor tyrant → runs as $PRO_USER)
  Logs:      $LOG_DIR/backend.log   (also: journalctl -u uwsgi-emperor)
  Backups:   $([[ -n "$PGBACKREST_REPO_HOST" ]] && echo "WAL → ${PGBACKREST_REPO_HOST}; run repo-host-setup.sh THERE to schedule backups" || echo "NONE (set PGBACKREST_REPO_HOST)")

NEXT STEPS
  * TLS is NOT configured. Obtain a certificate, e.g.:
        certbot --nginx -d ${PRO_DOMAIN}
  * If a provider is enabled, place its secrets in ${KEYS_DIR}, fill [apple]/[google]
    in ${CONFIG_INI}, then reload the vassal: touch $VASSAL
  * Smoke test (once DNS/TLS are up):
        curl -X POST https://${PRO_DOMAIN}/get_pro_revocations \\
             -H 'Content-Type: application/json' -d '{"version":0,"ticket":0}'
=======================================================================================
EOF
