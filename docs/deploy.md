# Session Pro Backend — Deploy Guide

Provisions the backend on a single Debian host with clean bash, a uWSGI Emperor vassal, and systemd: a dedicated
non-root user, a **dedicated PostgreSQL cluster** (leaving any other clusters/databases on
the box untouched), nginx as an HTTP reverse proxy, and off-host [pgBackRest](https://pgbackrest.org)
durability with point-in-time recovery. TLS is deliberately left to the operator.

> Scope: deploying the current code. Broader design/maintainability cleanup and an
> application-logic audit are separate efforts, out of scope here.

## Layout

| Path | Purpose |
|------|---------|
| `/opt/session-pro-backend` | code checkout + `.venv` (owned by `pro-backend`) |
| `/etc/session-pro-backend/config.ini` | app config (`db_url` + platform toggles managed by the installer) |
| `/etc/session-pro-backend/keys/` | Apple `.p8`, Google ADC JSON, Apple root certs |
| `/etc/uwsgi-emperor/vassals/pro-backend.ini` | uWSGI Emperor vassal (owned by `pro-backend`; tyrant runs it as that user) |
| `/run/pro-backend/pro-backend.sock` | uWSGI socket (dir created via `tmpfiles.d`) |
| `/var/log/pro-backend/` | application log |
| PostgreSQL cluster `session_pro` | dedicated cluster, auto-assigned port, referenced by name |

## Prerequisites

- A Debian target host with root access (these servers ship without `sudo` — `deploy.sh` runs
  directly as root, and every command it invokes as another user uses `runuser`, not `sudo`).
- A DNS name pointing at the host (for nginx `server_name` and, later, TLS).
- **The PGDG and oxen apt repositories configured first** (see "Prerequisite apt repositories"
  below). `deploy.sh` *checks* for them and refuses to run otherwise; it does not edit apt config.
- **A running uWSGI tyrant Emperor** (`emperor-tyrant = true` + `cap = setgid,setuid`) — shared
  fleet infrastructure this script does *not* manage. It only drops a vassal in, and refuses to
  install if the Emperor isn't tyrant (the vassal must run unprivileged, not as root).
- **For off-host backups (repo-host-initiated, "Option 2"):** a separate repository host that does
  **not** run PostgreSQL. You configure it *after* the primary deploy by running
  `scripts/pgbackrest/repo-host-setup.sh` there — it installs pgbackrest, creates the repository,
  and schedules backups that **pull** PGDATA from the primary over SSH. SSH is **bidirectional**:
  the primary pushes WAL to the repo host, the repo host pulls backups from the primary.
  `deploy.sh` prints the repo-host handoff values and the archive-push key to authorise. This path
  is verified end-to-end (continuous WAL archiving + a base backup) against a live primary + repo
  host on pgbackrest 2.58.
- **For live platforms (optional at first):** Apple in-app-purchase key (`.p8`) + IDs, and/or
  a Google Cloud service-account JSON authorised to the Pub/Sub subscription. You can deploy
  with platforms disabled and add these later.

### Prerequisite apt repositories

`deploy.sh` installs `pgbackrest` from **PGDG** (pinned, so its version matches the repo host — the
distro version drifts across Debian releases and mismatched versions break remote backups) and
`python3-session-util` from the **oxen** repo. It does **not** create these repositories — they are
system apt config you own — it only checks they provide those packages and stops with instructions
if not. Set them up once per host (`$(lsb_release -sc)` fills in the codename — `bookworm`, `trixie`, …):

```bash
install -d -m 0755 /etc/apt/keyrings

# PGDG — pinned so ONLY pgbackrest is taken from it (everything else stays on the distro):
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /etc/apt/keyrings/pgdg.asc
echo "deb [signed-by=/etc/apt/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -sc)-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
cat > /etc/apt/preferences.d/pgdg.pref <<'EOF'
Package: *
Pin: origin apt.postgresql.org
Pin-Priority: 1

Package: pgbackrest
Pin: origin apt.postgresql.org
Pin-Priority: 600
EOF

# oxen — python3-session-util (the Session onion-request binding):
curl -fsSL https://deb.oxen.io/pub.gpg -o /etc/apt/keyrings/oxen.gpg
echo "deb [signed-by=/etc/apt/keyrings/oxen.gpg] https://deb.oxen.io $(lsb_release -sc) main" \
    > /etc/apt/sources.list.d/oxen.list

apt-get update
apt-cache policy pgbackrest python3-session-util   # pgbackrest's candidate version must contain 'pgdg'
```

Both the primary and the repo host need PGDG (so pgbackrest versions match); only the primary needs oxen.

## Deploy

```bash
git clone https://github.com/session-foundation/session-pro-backend
cd session-pro-backend
cp scripts/deploy.env.example deploy.env
$EDITOR deploy.env            # set PRO_DOMAIN, PGBACKREST_REPO_HOST, platform toggles, ...
./scripts/deploy.sh
```

The installer is **idempotent** — re-run it to pull new code, refresh config/units, and
restart the service. It never clobbers your `[apple]`/`[google]` secrets in `config.ini`
(it only manages `db_url` and the platform toggles).

### After the first deploy

1. **TLS** (not done by the installer):
   ```bash
   certbot --nginx -d <your-domain>
   ```
   certbot rewrites the vhost in place, adding the `443` server and HTTP→HTTPS redirect.
2. **Platform credentials** (if enabling Apple/Google): place secrets under
   `/etc/session-pro-backend/keys/`, fill the `[apple]`/`[google]` sections of
   `/etc/session-pro-backend/config.ini`, set `WITH_PLATFORM_*=true` in `deploy.env`
   (re-run `deploy.sh`) or edit the toggles directly, then reload the vassal:
   `touch /etc/uwsgi-emperor/vassals/pro-backend.ini`.
3. **Google Pub/Sub subscription settings** (if enabling Google) — see below. These are not optional and
   are not visible to any test.
4. **Smoke test** an unauthenticated endpoint:
   ```bash
   curl -X POST https://<your-domain>/get_pro_revocations \
        -H 'Content-Type: application/json' -d '{"version":0,"ticket":0}'
   ```

### Google Pub/Sub subscription settings

The backend consumes RTDNs through the client library's streaming subscriber, which means **three
behaviours that used to be application code are now subscription configuration.** They are invisible to the
test suite — nothing here can observe them — so they have to be checked by hand, once, per environment.

1. **Retry policy — set an exponential backoff.** This is the one that matters. The handler paces a failing
   message by `nack()`ing it, and `nack()` has no backoff of its own: with no retry policy on the
   subscription, Pub/Sub redelivers as fast as it can, and one persistently failing message becomes a hot
   loop against the database. The code this replaced carried its own 1 s → 600 s backoff, and that
   responsibility moved here rather than disappearing.
   ```bash
   gcloud pubsub subscriptions update <subscription> \
       --min-retry-delay=10s --max-retry-delay=600s
   ```
2. **Exactly-once delivery — leave it OFF.** The backend already provides the guarantee itself, by
   recording every message id before handling it and treating an already-handled id as a no-op, so enabling
   it buys nothing. It also makes plain `ack()` unreliable: under exactly-once an ack can fail and must be
   confirmed via `ack_with_response()`, which this code does not do. (If it is already enabled — the
   `EXACTLY_ONCE_ACKID_FAILURE` handling in the code this replaced suggests it may be — either turn it off
   or the ack path needs changing first.)
3. **Ack deadline — the default (10 s) is fine.** The library extends the lease automatically for as long
   as a callback runs, which the hand-rolled loop never did; a message parked in its retry queue past the
   deadline was silently redelivered while still held. Nothing needs setting here, but do not raise it in
   the belief that the handler needs the time.

A **dead-letter topic** is worth configuring but is not required: a message that can never be handled is
retained in `google_notification_history` and replayed at every subscriber start, so it is recoverable
without one. Setting `max_delivery_attempts` moves that from "retried forever" to "parked somewhere an
operator can see it".

## Operations

```bash
systemctl status uwsgi-emperor          # Emperor state (manages the vassal)
journalctl -u uwsgi-emperor -f          # app logs (also /var/log/pro-backend/backend.log)
touch /etc/uwsgi-emperor/vassals/pro-backend.ini   # reload the app after config changes
runuser -u postgres -- psql --cluster <ver>/session_pro -d session_pro   # DB shell (peer auth)
```

`<ver>` is the installed PostgreSQL major version; `pg_lsclusters` shows it and the
auto-assigned port. The app connects via the cluster's unix socket with **peer auth**, so
there is no database password anywhere.

## Backups

Backups use pgBackRest's repo-host-initiated model:

- The **primary** (configured by `deploy.sh`) continuously **archives WAL** to the repository
  host (`archive_timeout` → worst-case RPO, default 30 s).
- The **repository host** (configured by `scripts/pgbackrest/repo-host-setup.sh`) runs the base
  backups: `stanza-create`/`check` once, then a daily `pro-backend-backup.timer` (full Sundays,
  differential otherwise) that **pulls** PGDATA from the primary over SSH.

Inspect on the **repository host** (as the repo user):

```bash
pgbackrest --stanza=session_pro info     # backup inventory
pgbackrest --stanza=session_pro check    # verify archiving + connectivity
systemctl list-timers pro-backend-backup.timer
```

The repository is AES-256 encrypted; the passphrase is on the primary at
`/etc/session-pro-backend/pgbackrest-cipher.pass` (and must match the repo host's config) —
**back it up**, or you cannot restore. (Phase 1 keeps the signing key in the database, so it
rides along in these backups; the encryption protects it off-host.)

> A portable single-database `pg_dump` is **not** automated in this version — run it manually if
> you want a cross-version snapshot; it can be wired back as a primary-side timer later.

## Disaster recovery

Physical restores need PostgreSQL binaries of the **same major version** that produced the
backup (minor differences are fine). The repo host itself needs no PostgreSQL. After a major
version upgrade, take a fresh full base backup and keep the old binaries available to restore
pre-upgrade backups.

### Restore from pgBackRest (point-in-time)

```bash
mv /etc/uwsgi-emperor/vassals/pro-backend.ini /root/   # Emperor stops just this app
systemctl stop postgresql@<ver>-session_pro

# Latest state:
runuser -u postgres -- pgbackrest --stanza=session_pro --delta restore
# ...or to a specific instant (PITR):
runuser -u postgres -- pgbackrest --stanza=session_pro --delta \
     --type=time --target="2026-07-13 14:23:00+00" restore

systemctl start postgresql@<ver>-session_pro   # replays WAL to the target
mv /root/pro-backend.ini /etc/uwsgi-emperor/vassals/   # Emperor restarts the app
```

### Restore from the portable dump (cross-version fallback)

```bash
runuser -u postgres -- pg_restore --cluster <ver>/session_pro -d session_pro \
     --clean --if-exists /path/to/session_pro_YYYYMMDD_HHMMSS.dump
```

### After ANY restore: advance the revocation ticket

A restore rewinds the `revocation_ticket` (a plain monotonic counter in `globals`). Clients poll
`/get_pro_revocations` with their last-seen ticket and treat "my ticket == the server's" as "nothing
changed", so a client holding a ticket **higher** than the rewound value silently stops fetching the
list — and worse, new post-restore revocations reuse ticket numbers it has already passed, so it never
sees them. After any restore, bump the ticket past anything that could have been issued in the lost
window so every client re-fetches the list once:

```bash
# from the app's install dir, as the app user:
python cli.py --config <config.ini> revoke bump-ticket 1000000
```

(Generation ids and revocation tokens need no such fixup: a recovered generation id just mints a fresh
random token when reused, and the wire revocation tag is that token — never the id — so nothing a client
cached can collide. This replaces the old `gen_index` counter fixup, which the random-token design
retired.)

## Wipe and start over

`scripts/purge.sh` tears down the **primary** so you can redeploy cleanly. It is **destructive**:
it drops the `session_pro` cluster (all its data) and removes the app user/files/services and the
primary's pgBackRest config. Shared packages and other clusters/databases are left untouched.

```bash
./scripts/purge.sh          # prompts for confirmation
./scripts/purge.sh --yes    # non-interactive
```

The **repository host is not touched.** To discard the off-host backups, on the repo host run
`pgbackrest --stanza=session_pro stanza-delete --force` and remove its config + timer — needed
before re-deploying, since a fresh primary cluster gets a new PostgreSQL system identifier.

## Why this shape

The dedicated cluster isolates Session Pro's WAL/PITR from the co-tenant databases on the shared
server; pgBackRest (chosen over Barman) gives encrypted off-host backups at minutes-level RPO; and
there is no live replica because the payment pipeline tolerates downtime — the goal is durability,
not availability.
