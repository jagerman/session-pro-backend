'''
Maintenance mule for the Session Pro Backend. Run as a uWSGI mule (`mule = mule:run` in the vassal ini)
so the singleton background work runs in exactly ONE process — off the request workers — instead of
duplicated in every worker (which used to race N daily-expiry threads and N subscribers pulling the same
subscription). It hosts:

  - the Google Pub/Sub notification subscriber (a single consumer), and
  - the periodic DB prune (expired revocations / orphaned users / expired notification history).

The prune runs on uWSGI's own timer/signal loop — no sleeping thread — once immediately on startup, then
every PRUNE_INTERVAL_S. Because the prune is pure idempotent housekeeping (expiry is derived on read and
every consuming query self-guards on expiry), the exact cadence doesn't matter.

`run()` executes in the mule *post-fork*, so all Google/gRPC state is constructed here, never at module
import in the master.
'''

import atexit
import logging
import sys
import time

import psycopg_pool
import uwsgi

import base
import backend
import config
import db

log = logging.getLogger('PRO')

CLEANUP_SIGNAL = 17  # uWSGI user signal that drives the periodic prune
PRUNE_INTERVAL_S = 600  # ~10 min; a no-op prune is a cheap indexed empty scan


def _mark(msg: str) -> None:
    # TEMP segfault instrumentation — raw stderr (uWSGI funnels it into the vassal log), bypasses logging.
    sys.stderr.write(f'MULE-DEBUG: {msg}\n')
    sys.stderr.flush()


_mark('module imported')


def _cleanup(pool: psycopg_pool.ConnectionPool) -> None:
    # Wrapped so a transient DB error logs and is retried on the next tick rather than killing the mule.
    try:
        now = base.datetime_from_unix_ms(int(time.time() * 1000))
        with db.connection(pool) as conn:
            result = backend.expire_payments_revocations_and_users(conn=conn, now=now)
        if result.success:
            log.info(
                'Pruned expired rows (revocations/users/apple/google={}/{}/{}/{})'.format(
                    result.revocations,
                    result.users,
                    result.apple_notification_uuid_history,
                    result.google_notification_history,
                )
            )
        else:
            log.error('DB prune failed')
    except Exception as e:
        log.error(f'DB prune raised: {e}')


def run() -> None:
    _mark('run() entered')
    # The mule is its own process, so wire up console logging (uWSGI captures it into the vassal log).
    handler = logging.StreamHandler()
    handler.setFormatter(base.LogFormatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    for logger in (log, backend.log):
        logger.addHandler(handler)

    try:
        parsed = config.parse_args()
    except config.ConfigError as e:
        log.error(f'Maintenance mule failed to start, invalid configuration:\n  {e}')
        sys.exit(1)
    base.UNSAFE_LOGGING = parsed.unsafe_logging
    base.DB_URL = parsed.db_url
    base.PROVIDER_TESTING_ENV = parsed.provider_testing_env
    base.PROVIDER_DRY_RUN = parsed.provider_dry_run
    _mark('config parsed + globals set')

    pool = db.get_pool(parsed.db_url)
    _mark('pool created')

    # Google Pub/Sub subscriber — a single consumer. gRPC state is built here (post-fork, in the mule).
    if parsed.with_provider_google_play:
        # Import the Google provider only when enabled — disabled means nothing of it loads (keeps
        # grpcio out of the mule entirely). DO NOT hoist to module scope.
        from providers import google_play

        google_play.log.addHandler(handler)
        if base.PROVIDER_TESTING_ENV:
            base.DEFAULT_GOOGLE_GRACE_PERIOD = base.timedelta_from_ms(google_play.api.testing_grace_period_duration_ms)
        context = google_play.start_subscriber(
            cloud_project_id=parsed.google_cloud_project_id,
            package_name=parsed.google_package_name,
            cloud_subscription_name=parsed.google_cloud_subscription_name,
            subscription_product_id=parsed.google_subscription_product_id,
            app_credentials_path=parsed.google_cloud_app_credentials_path,
        )
        # Graceful teardown on mule shutdown: cancel the pull loop + drain gRPC. (Correctness does not
        # depend on this — Pub/Sub redelivers unacked messages and handlers are idempotent — it just
        # keeps reloads clean.)
        atexit.register(google_play.stop_subscriber, context)
        log.info('Maintenance mule: Google subscriber started')

    # Prune once immediately (so a frequently-reloading box still gets cleaned each start), then let
    # uWSGI's timer drive it — event-driven, no sleeping thread.
    _mark('about to run first prune')
    _cleanup(pool)
    _mark('first prune returned')
    uwsgi.register_signal(CLEANUP_SIGNAL, 'mule1', lambda _signum: _cleanup(pool))
    uwsgi.add_timer(CLEANUP_SIGNAL, PRUNE_INTERVAL_S)
    log.info(f'Maintenance mule started; pruning every {PRUNE_INTERVAL_S}s')

    while True:
        uwsgi.signal_wait()
