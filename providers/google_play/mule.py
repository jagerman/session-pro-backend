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
import config

from . import notifications

log = logging.getLogger('pro')


def run() -> None:
    # The mule forks from the uWSGI master *after* main.entry_point() ran, so the shared loggers arrive with
    # the master's handlers already attached; `configure_logging` clears them, otherwise every line is
    # emitted once per inherited handler. uWSGI's `logto` captures this process's stderr into the vassal
    # log, same as the workers. Bootstrap first so a config failure has somewhere to go.
    base.bootstrap_logging()

    try:
        parsed = config.parse_args()
    except config.ConfigError as e:
        log.error(f'Google mule failed to start, invalid configuration:\n  {e}')
        sys.exit(1)
    base.configure_logging(parsed.log_level, parsed.log_levels)
    base.UNSAFE_LOGGING = parsed.unsafe_logging
    db.set_dsn(parsed.db_url)
    # Every global the coverage arithmetic reads has to be set in EVERY entry point: this process converges
    # payments and judges revocations, so one it leaves at the module default is one it silently disagrees
    # with the workers about.
    base.RENEWAL_LATENCY_ALLOWANCE = parsed.renewal_latency_allowance
    base.PROVIDER_DRY_RUN = parsed.provider_dry_run

    if not parsed.with_provider_google_play:
        # The mule's only job is the Google subscriber; with Google disabled it has nothing to do. Park
        # (rather than return, which uWSGI would treat as a dead mule and respawn-loop). No sleep loop.
        log.info('Maintenance mule: Google disabled, nothing to run; idle')
        threading.Event().wait()
        return

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
