#!/bin/bash
# Init-then-serve entrypoint for the containerised Session Pro Backend.
#
# Runs as root (uwsgi needs root to bind :80, then drops to the `pro-backend` user via uid/gid in the
# ini). Everything that touches the database is done as `pro-backend` via runuser.
#
# Order matters: config.ini has to exist before anything reads it, the schema has to exist before the
# vouchers are applied, and the pubkey banner is printed last so it is the final thing in the logs
# when the process comes up.
set -euo pipefail

APP_DIR=/home/pro-backend/app
ETC_DIR=/etc/session-pro-backend
CONFIG_INI=$ETC_DIR/config.ini
KEY_FILE=$ETC_DIR/key_ed25519
UWSGI_INI=$ETC_DIR/uwsgi-pro.ini

cd "$APP_DIR"

DB_URL="${SESH_PRO_BACKEND_DB_URL:?SESH_PRO_BACKEND_DB_URL is required (see docker/docker-compose.yml)}"
PROVIDER_DRY_RUN="${SESH_PRO_BACKEND_PROVIDER_DRY_RUN:-1}"
DEV_ENDPOINTS="${SESH_PRO_BACKEND_DEV_ENDPOINTS:-1}"
VOUCHERS_FILE="${PRO_VOUCHERS_FILE:-$ETC_DIR/vouchers.tsv}"

# ---------------------------------------------------------------------------------------------
# 1. Render config.ini
# ---------------------------------------------------------------------------------------------
# Written at runtime rather than baked into the image: the db_url is a compose concern, and cli.py
# *requires* --config <ini> (env vars alone don't satisfy it), so the file has to exist regardless.
#
# unsafe_logging is on because this is a throwaway instance where readable logs beat PII scrubbing,
# and provider_testing_env is on because the modified-duration timestamp handling is what a testing
# deployment wants. Neither is appropriate for a real instance.
#
# Both providers are pinned off and there is no [apple]/[google] section: this container exists to mint
# payments locally, never to talk to a store. Enabling one would need real credentials, which is what
# scripts/deploy.sh is for. Note that pinning them off is NOT what keeps Apple/Google egress away —
# provider_dry_run is; the redeem path for a minted google_play payment is reached via the payment's
# own provider, not via these toggles.
{
    echo '[base]'
    echo "db_url                    = $DB_URL"
    echo "backend_key_path          = $KEY_FILE"
    echo "provider_dry_run          = $PROVIDER_DRY_RUN"
    echo "dev_endpoints             = $DEV_ENDPOINTS"
    echo 'unsafe_logging            = true'
    echo 'provider_testing_env      = true'
    echo 'with_provider_app_store   = false'
    echo 'with_provider_google_play = false'
} > "$CONFIG_INI"

chown root:pro-backend "$CONFIG_INI"
chmod 0640 "$CONFIG_INI"

# ---------------------------------------------------------------------------------------------
# 2. Wait for PostgreSQL
# ---------------------------------------------------------------------------------------------
# docker-compose gates startup on the database's healthcheck already, but main.py hard-exits on a
# failed connect instead of retrying, so a few seconds of drift would turn into a crash loop.
#
# Bounded on purpose. The healthcheck proves the db *container* is serving, NOT that this URL is
# usable, so a wrong database name / user / password arrives here looking healthy — and an unbounded
# wait would then hang forever, printing the same line once a second, never exiting for anything to
# notice (`restart: unless-stopped` cannot help a process that does not exit).
DB_WAIT_ATTEMPTS="${PRO_DB_WAIT_ATTEMPTS:-60}"  # ~1s each; compose has already waited for the healthcheck
attempt=0
until psql "$DB_URL" -c '\q' >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$DB_WAIT_ATTEMPTS" ]; then
        echo "pro-backend entrypoint: postgres still unreachable after $DB_WAIT_ATTEMPTS attempts; giving up." >&2
        echo "  Check SESH_PRO_BACKEND_DB_URL (host, database, user, password) and that the db container is up." >&2
        # Surface psql's own diagnosis — this is what distinguishes "not up yet" from "wrong password".
        psql "$DB_URL" -c '\q' 2>&1 | sed 's/^/  psql: /' >&2 || true
        exit 1
    fi
    echo "pro-backend entrypoint: waiting for postgres…"
    sleep 1
done
echo "pro-backend entrypoint: postgres is up"

# ---------------------------------------------------------------------------------------------
# 3. Apply the schema
# ---------------------------------------------------------------------------------------------
# main.py migrates on startup too and migrations are ledger-tracked (so re-running is a no-op), but
# the vouchers below need the tables to exist *now*.
runuser -u pro-backend -- python3 - "$DB_URL" <<'PY'
import sys
import backend
import db

with db.connect_one(sys.argv[1]) as conn:
    backend.migrate_schema(conn)
print('pro-backend entrypoint: schema is up to date')
PY

# ---------------------------------------------------------------------------------------------
# 4. Apply the declarative vouchers
# ---------------------------------------------------------------------------------------------
# Each row grants one account a subscription: `master_pkey  provider  plan  [duration_s]`.
#
# `voucher` is NOT idempotent — every call mints a fresh payment — so each row is guarded on the
# account not already having an unexpired subscription. That check is against the DATABASE rather than
# a marker file on disk, so it stays correct when the db container is recreated (fresh DB) while this
# container is only restarted, and vice versa.
#
# The loop reads on fd 3 so that psql/cli.py inside the body cannot swallow the remaining rows.
if [ -f "$VOUCHERS_FILE" ]; then
    while read -r pkey provider plan duration <&3 || [ -n "$pkey" ]; do
        case "$pkey" in '' | '#'*) continue ;; esac

        # Validated before it reaches the SQL below, and because a typo'd key would otherwise be
        # granted a subscription nobody can use.
        if ! [[ "$pkey" =~ ^[0-9a-fA-F]{64}$ ]]; then
            echo "pro-backend entrypoint: skipping voucher row, not a 64-hex master pkey: $pkey" >&2
            continue
        fi
        if [ -z "$provider" ] || [ -z "$plan" ]; then
            echo "pro-backend entrypoint: skipping voucher row for ${pkey:0:8}…, missing provider or plan" >&2
            continue
        fi

        already=$(psql "$DB_URL" -tAc \
            "SELECT 1 FROM users WHERE master_pkey = decode('$pkey', 'hex') AND expiry_at > now()" \
            2>/dev/null || true)
        if [ "$already" = "1" ]; then
            echo "pro-backend entrypoint: voucher skipped, ${pkey:0:8}… already has an active subscription"
            continue
        fi

        echo "pro-backend entrypoint: granting ${pkey:0:8}… a $plan $provider subscription"
        # $duration unquoted on purpose: empty means "omit the flag entirely".
        runuser -u pro-backend -- python3 cli.py --config "$CONFIG_INI" voucher \
            --master-pkey "$pkey" --provider "$provider" --plan "$plan" \
            ${duration:+--duration "$duration"}
    done 3< "$VOUCHERS_FILE"
fi

# ---------------------------------------------------------------------------------------------
# 5. Surface the (deterministic) pubkeys
# ---------------------------------------------------------------------------------------------
# Same reasoning as the file server logging its pubkey and the SOGS logging its community link: the
# values a client has to be configured with should be readable straight out of `docker compose logs`.
runuser -u pro-backend -- python3 - "$KEY_FILE" <<'PY'
import sys
import backend
import base

skey = backend.load_backend_signing_key(sys.argv[1])
print('=' * 78)
print(f'Session Pro Backend v{base.BACKEND_VERSION}')
print(f'  Ed25519 signing pubkey : {bytes(skey.verify_key).hex()}')
print(f'  X25519 onion pubkey    : {bytes(skey.to_curve25519_private_key().public_key).hex()}')
print('  Proofs are signed by the Ed25519 key; onion requests to /oxen/v4/lsrpc are encrypted to the')
print('  X25519 key. Both derive from the same key file, so they always move together.')
print('=' * 78)
PY

if [ "$DEV_ENDPOINTS" = "1" ]; then
    echo "pro-backend entrypoint: /dev/add_payment is ENABLED — anyone who can reach this instance can mint Pro"
fi

echo "pro-backend entrypoint: starting uwsgi…"
exec uwsgi --ini "$UWSGI_INI"
