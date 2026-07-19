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
import platform_apple
import platform_google
import platform_google_api

log                                                       = logging.Logger('PRO')
webhook_loggers: list[base.AsyncSessionWebhookLogHandler] = []

def entry_point() -> flask.Flask:
    log_formatter  = base.LogFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    console_logger = logging.StreamHandler()
    console_logger.setFormatter(log_formatter)
    # NOTE: Setup console logger
    if 1:
        log.addHandler(console_logger)
        backend.log.addHandler(console_logger)
        platform_google.log.addHandler(console_logger)
        platform_apple.log.addHandler(console_logger)

    # NOTE: Parse arguments from .INI if present and environment variables, then setup global variables
    err = base.ErrorSink()
    parsed_args: config.ParsedArgs = config.parse_args(err)
    base.UNSAFE_LOGGING       = parsed_args.unsafe_logging
    base.DEV_BACKEND_MODE     = parsed_args.dev
    base.DB_URL               = parsed_args.db_url
    base.PLATFORM_TESTING_ENV = parsed_args.platform_testing_env
    if err.has():
        log.error(f'Failed to startup, invalid configuration options:\n  ' + '\n  '.join(err.msg_list))
        sys.exit(1)

    # NOTE: Setup file logger
    file_logger: logging.handlers.RotatingFileHandler | None = None
    if len(parsed_args.log_path) > 0:
        file_logger = logging.handlers.RotatingFileHandler(filename=parsed_args.log_path, maxBytes=64 * 1024 * 1024, backupCount=2, encoding='utf-8')
        file_logger.setFormatter(log_formatter)
        log.addHandler(file_logger)
        backend.log.addHandler(file_logger)
        platform_google.log.addHandler(file_logger)
        platform_apple.log.addHandler(file_logger)

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
            platform_google.log.addHandler(webhook_logger)
            platform_apple.log.addHandler(webhook_logger)

    # NOTE: Load the backend Ed25519 signing key. Dev mode uses a deterministic key; otherwise it is
    # loaded from disk and NEVER stored in the DB. The app does not (and its user should not be able
    # to) write this file — deployment creates it — so a missing/unreadable key is a hard startup
    # error rather than a silent regeneration that would invalidate every proof already issued.
    if parsed_args.dev:
        backend_key: nacl.signing.SigningKey = nacl.signing.SigningKey(base.DEV_BACKEND_DETERMINISTIC_SKEY)
    else:
        if not parsed_args.backend_key_path:
            log.error('No backend signing key configured: set [base] backend_key_path (or SESH_PRO_BACKEND_KEY_PATH)')
            sys.exit(1)
        try:
            backend_key = backend.load_backend_signing_key(parsed_args.backend_key_path)
        except Exception as e:
            log.error(f'Failed to load backend signing key from "{parsed_args.backend_key_path}": {e}')
            sys.exit(1)

    # NOTE: Open the DB (create tables if necessary)
    engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=parsed_args.db_url, err=err)
    if err.has():
        log.error(err.build())
        sys.exit(1)
    assert engine

    with db.connection(engine) as conn:
        # NOTE: Sanity check dev mode
        if base.DEV_BACKEND_MODE:
            backend.assert_backend_is_in_dev_mode(backend_key)

        # NOTE: Dump some startup diagnostics
        info_string: str = backend.db_info_string(conn=conn, db_url=parsed_args.db_url, backend_pkey=backend_key.verify_key, err=err)
        if len(err.msg_list) > 0:
            log.error(f"{err.msg_list}")
            sys.exit(1)

        startup_log = '\n'
        if parsed_args.dev:
            startup_log += "######################################\n"
            startup_log += "###                                ###\n"
            startup_log += "###        Dev Mode Enabled        ###\n"
            startup_log += "###                                ###\n"
            startup_log += "######################################\n"

        startup_log += f'Session Pro Backend\n{info_string}\n'
        startup_log += f'  Features:\n'
        if len(parsed_args.ini_path) > 0:
            startup_log += f'    Config .INI file loaded: {parsed_args.ini_path}\n'
        startup_log += f'    DB loaded from: {parsed_args.db_url}\n'
        if len(parsed_args.log_path):
            startup_log += f'    Logging to: {parsed_args.log_path}\n'
        else:
            startup_log += f'    Logging to disk disabled (no log_path specified in .INI file)\n'
        if parsed_args.unsafe_logging:
            startup_log += f'    Unsafe logging enabled (this must NOT be used in production)\n'
        if parsed_args.platform_testing_env:
            startup_log += f'    Platform testing environment enabled (special behaviour for rounding timestamps to EOD)\n'
        if parsed_args.with_platform_apple:
            label = 'Sandbox' if parsed_args.apple_sandbox_env else 'Production'
            startup_log += f'    Platform: {label} Apple iOS App Store notification handling enabled\n'
        if parsed_args.with_platform_google:
            startup_log += f'    Platform: Google Play Store notification handling enabled\n'
        for it in parsed_args.session_webhooks:
            if it.enabled:
                startup_log += f'    Webhook Logger: Enabled (display name: {it.name})\n'

        if parsed_args.dev:
            startup_log += "######################################\n"
            startup_log += "###                                ###\n"
            startup_log += "###        Dev Mode Enabled        ###\n"
            startup_log += "###                                ###\n"
            startup_log += "######################################\n"

        log.info(startup_log)
        for it in webhook_loggers:
            it.emit_text(f'Starting up instance: {startup_log}')


        # NOTE: Add flask to our global logger
        result: flask.Flask = server.init(testing_mode=False, database_url=parsed_args.db_url, backend_key=backend_key)
        if 1:
            _ = result.logger.addHandler(console_logger)
            if file_logger:
                _ = result.logger.addHandler(file_logger)
            for it in webhook_loggers:
                _ = result.logger.addHandler(it)

        # NOTE: Enable Apple iOS App Store notifications routes on the server if enabled. Apple will
        # contact the endpoint when a notification is generated.
        if parsed_args.with_platform_apple:
            core: platform_apple.Core = platform_apple.init(key_id      = parsed_args.apple_key_id,
                                                            issuer_id   = parsed_args.apple_issuer_id,
                                                            bundle_id   = parsed_args.apple_bundle_id,
                                                            app_id      = None if parsed_args.apple_sandbox_env else parsed_args.apple_app_id,
                                                            key_bytes   = parsed_args.apple_key,
                                                            root_certs  = parsed_args.apple_root_certs,
                                                            sandbox_env = parsed_args.apple_sandbox_env)
            platform_apple.equip_flask_routes(core, result)

            # NOTE: Offset by 10s to account for clock drift between backend and the Apple servers
            end_unix_ts_ms = int((time.time() - 10) * 1000)
            platform_apple.catchup_on_missed_notifications(core=core, sql_conn=conn, end_unix_ts_ms=end_unix_ts_ms)

        # NOTE: The Google Pub/Sub subscriber and the periodic DB prune are singleton background work —
        # they run once in the maintenance mule (mule.py, `mule = mule:run`), not per-worker here. The
        # Apple notification route is registered above because it's an HTTP endpoint the workers serve;
        # only Apple's startup catch-up remains per-worker for now (a one-shot — a follow-up could move
        # it to the mule too).
    return result

# Flask entry point
flask_app: flask.Flask = entry_point()
