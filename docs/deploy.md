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
3. **Smoke test** an unauthenticated endpoint:
   ```bash
   curl -X POST https://<your-domain>/get_pro_revocations \
        -H 'Content-Type: application/json' -d '{"version":0,"ticket":0}'
   ```

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

### After ANY restore: advance the generation counter

A restore rewinds `runtime.gen_index`. Because that counter is baked (hashed) into issued
proofs and keyed for revocations, reuse could collide a recovered index with one already held
by a client. Advance it past anything that could have been issued in the lost window (this is
invisible to clients — they only ever see the salted hash):

```bash
runuser -u postgres -- psql --cluster <ver>/session_pro -d session_pro \
     -c "UPDATE runtime SET gen_index = gen_index + 1000000;"
```

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
