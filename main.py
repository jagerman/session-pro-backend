'''
Main entry point for the Session Pro Backend. This runs the necessary setup code like initialising
the DB and responding startup arguments before handing over control-flow to Flask.

For database operations (user errors, revocations, reports, etc.), use the cli.py tool instead.
'''

import flask
import time
import nacl.signing
import logging
import logging.handlers
import sys
import psycopg_pool

import base
import backend
import config
import db
import server
from providers import app_store
from providers import google_play

log = logging.Logger('PRO')
webhook_loggers: list[base.AsyncSessionWebhookLogHandler] = []


def entry_point() -> flask.Flask:
    log_formatter = base.LogFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    console_logger = logging.StreamHandler()
    console_logger.setFormatter(log_formatter)
    # NOTE: Setup console logger
    log.addHandler(console_logger)
    backend.log.addHandler(console_logger)
    google_play.log.addHandler(console_logger)
    app_store.log.addHandler(console_logger)

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

    # NOTE: Setup file logger
    file_logger: logging.handlers.RotatingFileHandler | None = None
    if len(parsed_args.log_path) > 0:
        file_logger = logging.handlers.RotatingFileHandler(
            filename=parsed_args.log_path, maxBytes=64 * 1024 * 1024, backupCount=2, encoding='utf-8'
        )
        file_logger.setFormatter(log_formatter)
        log.addHandler(file_logger)
        backend.log.addHandler(file_logger)
        google_play.log.addHandler(file_logger)
        app_store.log.addHandler(file_logger)

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
            google_play.log.addHandler(webhook_logger)
            app_store.log.addHandler(webhook_logger)

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

    # NOTE: Open the DB (create tables if necessary)
    try:
        engine: psycopg_pool.ConnectionPool = backend.bootstrap_db(database_url=parsed_args.db_url)
    except Exception as e:
        log.error(f'{e}', exc_info=True)
        sys.exit(1)

    with db.connection(engine) as conn:
        startup_log = '\n'
        startup_log += 'Session Pro Backend\n'
        startup_log += '  Features:\n'
        if len(parsed_args.ini_path) > 0:
            startup_log += f'    Config .INI file loaded: {parsed_args.ini_path}\n'
        startup_log += f'    DB loaded from: {parsed_args.db_url}\n'
        if len(parsed_args.log_path):
            startup_log += f'    Logging to: {parsed_args.log_path}\n'
        else:
            startup_log += '    Logging to disk disabled (no log_path specified in .INI file)\n'
        if parsed_args.unsafe_logging:
            startup_log += '    Unsafe logging enabled (this must NOT be used in production)\n'
        if parsed_args.provider_testing_env:
            startup_log += (
                '    Platform testing environment enabled (special behaviour for rounding timestamps to EOD)\n'
            )
        if parsed_args.provider_dry_run:
            startup_log += '    provider_dry_run ENABLED: all payment-provider egress is stubbed (NO FOR PRODUCTION)\n'
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
        result: flask.Flask = server.init(testing_mode=False, database_url=parsed_args.db_url, backend_key=backend_key)
        result.logger.addHandler(console_logger)
        if file_logger:
            result.logger.addHandler(file_logger)
        for handler in webhook_loggers:
            result.logger.addHandler(handler)

        # NOTE: Enable Apple iOS App Store notifications routes on the server if enabled. Apple will
        # contact the endpoint when a notification is generated.
        if parsed_args.with_provider_app_store:
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

        # NOTE: The Google Pub/Sub subscriber and the periodic DB prune are singleton background work —
        # they run once in the maintenance mule (mule.py, `mule = mule:run`), not per-worker here. The
        # Apple notification route is registered above because it's an HTTP endpoint the workers serve;
        # only Apple's startup catch-up remains per-worker for now (a one-shot — a follow-up could move
        # it to the mule too).
    return result


# Flask entry point
flask_app: flask.Flask = entry_point()
