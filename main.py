'''
Main entry point for the Session Pro Backend. This runs the necessary setup code like initialising
the DB and responding startup arguments before handing over control-flow to Flask.

For database operations (user errors, revocations, reports, etc.), use the cli.py tool instead.
'''

import flask
import flask.logging
import time
import datetime
import nacl.signing
import logging
import sys

try:
    from uwsgidecorators import timer
except ModuleNotFoundError:
    # uwsgidecorators does `import uwsgi`, which only exists inside a uWSGI runtime. Outside it
    # (`flask --app main run`, tests, tooling, a bare `import main`) fall back to a no-op decorator:
    # the periodic prune is a uWSGI worker-1 concern and simply doesn't run in those contexts.
    def timer(*_args, **_kwargs):  # type: ignore[no-redef]
        def _decorator(fn):
            return fn

        return _decorator


import base
import backend
import config
import db
import server

log = logging.Logger('PRO')
webhook_loggers: list[base.AsyncSessionWebhookLogHandler] = []

PRUNE_INTERVAL_S = 600  # ~10 min; a no-op prune is a cheap indexed empty scan


@timer(PRUNE_INTERVAL_S, target='worker1')
def _periodic_cleanup(signum: int) -> None:
    # Periodic DB prune (expired revocations / orphaned users / expired notification history). uWSGI
    # targets this signal at worker 1 ONLY, so exactly one process prunes — no N-worker race, and no
    # dedicated mule (a mule can't register uWSGI signals). A busy worker just defers the tick; the
    # prune is idempotent, non-urgent housekeeping, so a delay is harmless.
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        with db.connection(db.get_pool(base.DB_URL)) as conn:
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


def entry_point() -> flask.Flask:
    log_formatter = base.LogFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    console_logger = logging.StreamHandler()
    console_logger.setFormatter(log_formatter)
    # NOTE: Setup console logger
    log.addHandler(console_logger)
    backend.log.addHandler(console_logger)

    # NOTE: Parse arguments from .INI if present and environment variables, then setup global variables
    try:
        parsed_args: config.ParsedArgs = config.parse_args()
    except config.ConfigError as e:
        log.error(f'Failed to startup, invalid configuration options:\n  {e}')
        sys.exit(1)
    base.UNSAFE_LOGGING = parsed_args.unsafe_logging
    base.DB_URL = parsed_args.db_url
    base.PROVIDER_TESTING_ENV = parsed_args.provider_testing_env
    base.PROVIDER_DRY_RUN = parsed_args.provider_dry_run

    # NOTE: log_path is deliberately ignored here. Under uWSGI the vassal's `logto` already captures
    # this process's stdout/stderr into the log file and rotates it (log-maxsize/log-backupname); a
    # second app-managed RotatingFileHandler on the same path would double-write, and it isn't
    # rotation-safe across the multiple workers + mule anyway. log_path stays a config option only
    # for non-uWSGI/CLI use (see cli.py) — it does nothing in the Flask/uWSGI process.

    # NOTE: Equip the session webhook URL if it's configured
    for it in parsed_args.session_webhooks:
        if it.enabled:
            webhook_logger = base.AsyncSessionWebhookLogHandler(url=it.url, name=it.name)
            webhook_logger.setLevel(logging.WARNING)
            webhook_logger.setFormatter(log_formatter)
            webhook_loggers.append(webhook_logger)

            # NOTE: Setup loggers (main, backend, google, apple)
            log.addHandler(webhook_logger)
            backend.log.addHandler(webhook_logger)

    # NOTE: Import the Google provider only if enabled — a disabled provider loads nothing at all (this
    # is what keeps grpcio out of the process). Logging is wired here; its runtime work lives in the mule.
    if parsed_args.with_provider_google_play:
        from providers import google_play

        google_play.log.addHandler(console_logger)
        for handler in webhook_loggers:
            google_play.log.addHandler(handler)

    # NOTE: Load the backend Ed25519 signing key from disk. It is NEVER stored in the DB. The app does
    # not (and its user should not be able to) write this file — deployment creates it — so a
    # missing/unreadable key is a hard startup error rather than a silent regeneration that would
    # invalidate every proof already issued. Tests/dev supply an ephemeral key via the same path.
    if not parsed_args.backend_key_path:
        log.error('No backend signing key configured: set [base] backend_key_path (or SESH_PRO_BACKEND_KEY_PATH)')
        sys.exit(1)
    try:
        backend_key: nacl.signing.SigningKey = backend.load_backend_signing_key(parsed_args.backend_key_path)
    except Exception as e:
        log.error(f'Failed to load backend signing key from "{parsed_args.backend_key_path}": {e}')
        sys.exit(1)

    # NOTE: entry_point runs in the uWSGI master, BEFORE it forks the workers and mule. Everything it
    # does with the DB is one-shot startup work (schema migration, the startup-log read, Apple's
    # missed-notification catch-up), so it runs on a single throwaway connection, NEVER a pool: a
    # ConnectionPool opened here would spawn background worker threads, and forking a multi-threaded
    # process corrupts the children's thread state — a hard segfault when the pool is closed at reload
    # (Python 3.13). Each worker/mule builds its own pool lazily, post-fork (server.get_db -> get_pool).
    try:
        conn = db.connect_one(parsed_args.db_url)
    except Exception as e:
        log.error(f'Failed to open/connect to DB at {parsed_args.db_url}: {e}', exc_info=True)
        sys.exit(1)

    with conn:
        try:
            backend.migrate_schema(conn)
        except Exception as e:
            log.error(f'{e}', exc_info=True)
            sys.exit(1)

        startup_log = '\n'
        startup_log += 'Session Pro Backend\n'
        startup_log += '  Features:\n'
        if len(parsed_args.ini_path) > 0:
            startup_log += f'    Config .INI file loaded: {parsed_args.ini_path}\n'
        startup_log += f'    DB loaded from: {parsed_args.db_url}\n'
        if len(parsed_args.log_path):
            startup_log += '    log_path is set but ignored under uWSGI (the vassal `logto` owns the log file)\n'
        if parsed_args.unsafe_logging:
            startup_log += '    Unsafe logging enabled (this must NOT be used in production)\n'
        if parsed_args.provider_testing_env:
            startup_log += (
                '    Platform testing environment enabled (special behaviour for rounding timestamps to EOD)\n'
            )
        if parsed_args.provider_dry_run:
            startup_log += '    provider_dry_run ENABLED: all payment-provider egress is stubbed (NO FOR PRODUCTION)\n'
        if parsed_args.dev_endpoints:
            startup_log += (
                '    dev_endpoints ENABLED: /dev/* routes are live and will mint Pro subscriptions for'
                ' ANY unauthenticated caller (NOT FOR PRODUCTION)\n'
            )
        if parsed_args.with_provider_app_store:
            label = 'Sandbox' if parsed_args.apple_sandbox_env else 'Production'
            startup_log += f'    Platform: {label} Apple iOS App Store notification handling enabled\n'
        if parsed_args.with_provider_google_play:
            startup_log += '    Platform: Google Play Store notification handling enabled\n'
        for it in parsed_args.session_webhooks:
            if it.enabled:
                startup_log += f'    Webhook Logger: Enabled (display name: {it.name})\n'

        log.info(startup_log)
        for handler in webhook_loggers:
            handler.emit_text(f'Starting up instance: {startup_log}')

        # NOTE: Add flask to our global logger
        result: flask.Flask = server.init(
            testing_mode=False,
            database_url=parsed_args.db_url,
            backend_key=backend_key,
            dev_endpoints=parsed_args.dev_endpoints,
        )
        # Flask lazily attaches its own default_handler to app.logger the first time it's accessed
        # (the addHandler below triggers that); remove it so app records aren't emitted twice — once
        # in Flask's format and once in ours.
        result.logger.addHandler(console_logger)
        result.logger.removeHandler(flask.logging.default_handler)
        for handler in webhook_loggers:
            result.logger.addHandler(handler)

        # NOTE: Enable Apple iOS App Store notifications routes on the server if enabled. Apple will
        # contact the endpoint when a notification is generated.
        if parsed_args.with_provider_app_store:
            # Import the Apple provider only if enabled — zero footprint when disabled.
            from providers import app_store

            app_store.log.addHandler(console_logger)
            for handler in webhook_loggers:
                app_store.log.addHandler(handler)
            core: app_store.Core = app_store.init(
                key_id=parsed_args.apple_key_id,
                issuer_id=parsed_args.apple_issuer_id,
                bundle_id=parsed_args.apple_bundle_id,
                app_id=None if parsed_args.apple_sandbox_env else parsed_args.apple_app_id,
                key_bytes=parsed_args.apple_key,
                root_certs=parsed_args.apple_root_certs,
                sandbox_env=parsed_args.apple_sandbox_env,
            )
            app_store.equip_flask_routes(core, result)

            # NOTE: Offset by 10s to account for clock drift between backend and the Apple servers
            end_unix_ts_ms = int((time.time() - 10) * 1000)
            app_store.catchup_on_missed_notifications(core=core, sql_conn=conn, end_unix_ts_ms=end_unix_ts_ms)

        # NOTE: The Google Pub/Sub subscriber is singleton background work — it runs once in the
        # maintenance mule (providers/google_play/mule.py), not per-worker here. (The periodic DB prune is
        # also singleton but runs on worker 1 via an @timer, since a mule can't register uWSGI signals.)
        # The Apple notification route is registered above because it's an HTTP endpoint the workers serve;
        # only Apple's startup catch-up remains per-worker for now (a one-shot — a follow-up could move
        # it to the mule too).
    return result


# Flask entry point
flask_app: flask.Flask = entry_point()
