'''
Subscriber mule for the Google Play provider. Run as a uWSGI mule
(`mule = providers.google_play.mule:run` in the vassal ini) so the Google Pub/Sub notification
subscriber runs in exactly ONE process — a single consumer, off the request workers. This mule is
deliberately Google-specific: another provider that needs a background consumer gets its OWN mule
(uWSGI supports any number), so a stall in one provider's subscriber can't hold up another's.

Periodic housekeeping (the DB prune, the Apple catch-up) is NOT here either: it lives in its own
maintenance mule (maintenance.py), for the same reason — a wedged subscriber must not stop the prune.

`run()` executes in the mule *post-fork*. gRPC's fork-hostile background threads are still constructed
lazily inside the subscriber thread (see notifications.thread_entry_point), never at import in the master.
'''

import atexit
import logging
import sys
import threading

import base
import db
import backend
import config

from . import api, notifications

log = logging.getLogger('PRO')


def run() -> None:
    # The mule forks from the uWSGI master *after* main.entry_point() ran, so the shared backend (and
    # later google) loggers arrive with the master's handlers already attached. Clear them before
    # installing the mule's own, otherwise every mule log line is emitted once per inherited handler.
    # uWSGI's `logto` captures this StreamHandler's stderr into the vassal log, same as the workers.
    handler = logging.StreamHandler()
    handler.setFormatter(base.LogFormatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    for logger in (log, backend.log):
        logger.handlers.clear()
        logger.addHandler(handler)

    try:
        parsed = config.parse_args()
    except config.ConfigError as e:
        log.error(f'Maintenance mule failed to start, invalid configuration:\n  {e}')
        sys.exit(1)
    base.UNSAFE_LOGGING = parsed.unsafe_logging
    db.set_dsn(parsed.db_url)
    base.PROVIDER_TESTING_ENV = parsed.provider_testing_env
    base.PROVIDER_DRY_RUN = parsed.provider_dry_run

    if not parsed.with_provider_google_play:
        # The mule's only job is the Google subscriber; with Google disabled it has nothing to do. Park
        # (rather than return, which uWSGI would treat as a dead mule and respawn-loop). No sleep loop.
        log.info('Maintenance mule: Google disabled, nothing to run; idle')
        threading.Event().wait()
        return

    notifications.log.handlers.clear()
    notifications.log.addHandler(handler)
    if base.PROVIDER_TESTING_ENV:
        base.RENEWAL_LATENCY_ALLOWANCE = base.duration_from_ms(api.testing_renewal_latency_allowance_ms)
    context = notifications.start_subscriber(
        cloud_project_id=parsed.google_cloud_project_id,
        package_name=parsed.google_package_name,
        cloud_subscription_name=parsed.google_cloud_subscription_name,
        subscription_product_id=parsed.google_subscription_product_id,
        app_credentials_path=parsed.google_cloud_app_credentials_path,
    )
    atexit.register(notifications.stop_subscriber, context)
    log.info('Maintenance mule: Google subscriber started')

    # Keep the mule alive by blocking on the subscriber thread — no sleep loop. If that thread ever
    # exits, run() returns and uWSGI respawns the mule, which restarts the subscriber.
    assert context.thread is not None
    context.thread.join()
