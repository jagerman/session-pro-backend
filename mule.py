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
import platform_google
import platform_google_api

log = logging.getLogger('PRO')

CLEANUP_SIGNAL   = 17          # uWSGI user signal that drives the periodic prune
PRUNE_INTERVAL_S = 600         # ~10 min; a no-op prune is a cheap indexed empty scan

def _cleanup(pool: psycopg_pool.ConnectionPool) -> None:
    # Wrapped so a transient DB error logs and is retried on the next tick rather than killing the mule.
    try:
        now = base.datetime_from_unix_ms(int(time.time() * 1000))
        with db.connection(pool) as conn:
            result = backend.expire_payments_revocations_and_users(conn=conn, now=now)
        if result.success:
            log.info('Pruned expired rows (revocations/users/apple/google={}/{}/{}/{})'.format(
                result.revocations, result.users, result.apple_notification_uuid_history, result.google_notification_history))
        else:
            log.error('DB prune failed')
    except Exception as e:
        log.error(f'DB prune raised: {e}')

def run() -> None:
    # The mule is its own process, so wire up console logging (uWSGI captures it into the vassal log).
    handler = logging.StreamHandler()
    handler.setFormatter(base.LogFormatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    for logger in (log, backend.log, platform_google.log):
        logger.addHandler(handler)

    err                       = base.ErrorSink()
    parsed                    = config.parse_args(err)
    base.UNSAFE_LOGGING       = parsed.unsafe_logging
    base.DEV_BACKEND_MODE     = parsed.dev
    base.DB_URL               = parsed.db_url
    base.PLATFORM_TESTING_ENV = parsed.platform_testing_env
    base.PROVIDER_DRY_RUN     = parsed.provider_dry_run
    if err.has():
        log.error('Maintenance mule failed to start, invalid configuration:\n  ' + '\n  '.join(err.msg_list))
        sys.exit(1)

    pool = db.get_pool(parsed.db_url)

    # Google Pub/Sub subscriber — a single consumer. gRPC state is built here (post-fork, in the mule).
    if parsed.with_platform_google:
        if base.PLATFORM_TESTING_ENV:
            base.DEFAULT_GOOGLE_GRACE_PERIOD = base.timedelta_from_ms(platform_google_api.testing_grace_period_duration_ms)
        context = platform_google.start_subscriber(cloud_project_id        = parsed.google_cloud_project_id,
                                                   package_name            = parsed.google_package_name,
                                                   cloud_subscription_name = parsed.google_cloud_subscription_name,
                                                   subscription_product_id = parsed.google_subscription_product_id,
                                                   app_credentials_path    = parsed.google_cloud_app_credentials_path)
        # Graceful teardown on mule shutdown: cancel the pull loop + drain gRPC. (Correctness does not
        # depend on this — Pub/Sub redelivers unacked messages and handlers are idempotent — it just
        # keeps reloads clean.)
        atexit.register(platform_google.stop_subscriber, context)
        log.info('Maintenance mule: Google subscriber started')

    # Prune once immediately (so a frequently-reloading box still gets cleaned each start), then let
    # uWSGI's timer drive it — event-driven, no sleeping thread.
    _cleanup(pool)
    uwsgi.register_signal(CLEANUP_SIGNAL, 'mule1', lambda _signum: _cleanup(pool))
    uwsgi.add_timer(CLEANUP_SIGNAL, PRUNE_INTERVAL_S)
    log.info(f'Maintenance mule started; pruning every {PRUNE_INTERVAL_S}s')

    while True:
        uwsgi.signal_wait()
