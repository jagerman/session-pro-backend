'''
Maintenance mule for the Session Pro Backend. Run as a uWSGI mule (`mule = mule:run` in the vassal ini)
so the Google Pub/Sub notification subscriber runs in exactly ONE process — a single consumer, off the
request workers.

The periodic DB prune is NOT here: a mule cannot register uWSGI signals/timers, so it runs on worker 1
via a `@timer(target='worker1')` in main.py instead.

`run()` executes in the mule *post-fork*, so all Google/gRPC state is constructed here, never at module
import in the master.
'''

import atexit
import logging
import sys
import threading

import base
import backend
import config

log = logging.getLogger('PRO')


def run() -> None:
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

    if not parsed.with_provider_google_play:
        # The mule's only job is the Google subscriber; with Google disabled it has nothing to do. Park
        # (rather than return, which uWSGI would treat as a dead mule and respawn-loop). No sleep loop.
        log.info('Maintenance mule: Google disabled, nothing to run; idle')
        threading.Event().wait()
        return

    # Import the Google provider only when enabled — disabled means nothing of it loads (keeps grpcio
    # out of the mule until here, post-fork). DO NOT hoist to module scope.
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
    atexit.register(google_play.stop_subscriber, context)
    log.info('Maintenance mule: Google subscriber started')

    # Keep the mule alive by blocking on the subscriber thread — no sleep loop. If that thread ever
    # exits, run() returns and uWSGI respawns the mule, which restarts the subscriber.
    assert context.thread is not None
    context.thread.join()
