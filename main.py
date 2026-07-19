'''
Main entry point for the Session Pro Backend. This runs the necessary setup code like initialising
the DB and responding startup arguments before handing over control-flow to Flask.

For database operations (user errors, revocations, reports, etc.), use the cli.py tool instead.
'''

import pathlib
import os
import flask
import threading
import time
import datetime
import signal
import types
import nacl.signing
import logging
import logging.handlers
import configparser
import sys
import dataclasses
import psycopg_pool

import base
import backend
import db
import server
import platform_apple
import platform_google
import platform_google_api

log                                                       = logging.Logger('PRO')
google_thread_context                                     = platform_google.ThreadContext()
webhook_loggers: list[base.AsyncSessionWebhookLogHandler] = []

@dataclasses.dataclass
class SessionWebhook:
    enabled: bool = False
    url:     str  = ''
    name:    str  = ''

@dataclasses.dataclass
class ParsedArgs:
    ini_path:                                  str                             = ''
    db_url:                                    str                             = ''
    backend_key_path:                          str                             = ''
    log_path:                                  str                             = ''
    dev:                                       bool                            = False
    unsafe_logging:                            bool                            = False

    with_platform_apple:                       bool                            = False
    with_platform_google:                      bool                            = False

    platform_testing_env:                      bool                            = False

    session_webhooks:                          list[SessionWebhook]            = dataclasses.field(default_factory=list)

    apple_key_id:                              str                             = ''
    apple_issuer_id:                           str                             = ''
    apple_bundle_id:                           str                             = ''
    apple_key_path:                            str                             = ''
    apple_root_cert_path:                      str                             = ''
    apple_root_cert_ca_g2_path:                str                             = ''
    apple_root_cert_ca_g3_path:                str                             = ''
    apple_key:                                 bytes                           = b''
    apple_root_certs:                          list[bytes]                     = dataclasses.field(default_factory=list)
    apple_sandbox_env:                         bool                            = False
    apple_app_id:                   int | None                      = None

    google_package_name:                       str                             = ''
    google_cloud_app_credentials_path: str                             = ''
    google_cloud_project_id:                   str                             = ''
    google_cloud_subscription_name:            str                             = ''
    google_subscription_product_id:            str                             = ''

def signal_handler(sig: int, _frame: types.FrameType | None):
    global stop_maintenance_thread

    # NOTE: Wake up the thread and set the flag to terminate it
    stop_maintenance_thread = True
    proof_expiry_thread_event.set()

    # NOTE: Also kill the google-thread if there's one was initiated. The google thread is sleeping
    # on a condition that has a timeout that we trigger.
    google_thread_context.kill_thread = True
    google_thread_context.sleep_event.set()

    # NOTE: Unregister handler and resume the default handler by re-raising it
    _ = signal.signal(sig, signal.SIG_DFL)
    signal.raise_signal(sig)

def backend_maintenance_thread_entry_point(db_url: str):
    global stop_maintenance_thread
    while not stop_maintenance_thread:
        start_unix_ts_s:    float = time.time()
        next_day_unix_ts_s: float = base.round_datetime_to_next_day(base.datetime_from_unix_ms(int(start_unix_ts_s * 1000))).timestamp()
        sleep_time_s:       float = next_day_unix_ts_s - start_unix_ts_s

        next_day_date:      datetime.datetime = datetime.datetime.fromtimestamp(next_day_unix_ts_s)
        next_day_str:       str               = next_day_date.strftime('%Y-%m-%d')

        # Sleep on CV until sleep time has elapsed, or, we get woken up by SIG handler.
        while int(sleep_time_s) > 0 and not stop_maintenance_thread:
            assert sleep_time_s <= base.SECONDS_IN_DAY
            log.info(f'Sleeping for {base.format_seconds(sleep_time_s)} to expire DB entries at UTC {next_day_str}')
            _ = proof_expiry_thread_event.wait(timeout=sleep_time_s)
            sleep_time_s = next_day_unix_ts_s - int(time.time())

        # We only reach here if the sleep time has elapsed OR woken up. If sleep time has elapsed,
        # then we can go and expire the records from the DB
        if not stop_maintenance_thread:

            # NOTE: Expire rows from the database
            if 1:
                expire_result = backend.ExpireResult()
                with db.open_database(db_url) as engine:
                    with db.connection(engine) as conn:
                        expire_result = backend.expire_payments_revocations_and_users(conn=conn,
                                                                                      now=base.datetime_from_unix_ms(int(next_day_unix_ts_s * 1000)))

                yesterday_str: str = datetime.datetime.fromtimestamp(next_day_unix_ts_s - base.SECONDS_IN_DAY).strftime('%Y-%m-%d')
                today_str: str     = datetime.datetime.fromtimestamp(next_day_unix_ts_s).strftime('%m-%d')
                if expire_result.success:
                    log_line: str = ('Daily pruning for {} completed on {}. Pruned revocations/users/apple notifs={}/{}/{}'.format(yesterday_str,
                                                                                                                                    today_str,
                                                                                                                                    expire_result.revocations,
                                                                                                                                    expire_result.users,
                                                                                                                                    expire_result.apple_notification_uuid_history))
                    log.info(log_line)
                    for it in webhook_loggers:
                        it.emit_text(log_line)
                else:
                    log.error(f'Daily pruning for {yesterday_str} failed due to an unknown DB error')

            # TODO: Backups now run out-of-process via pgBackRest, and the periodic report
            # generation + webhook dispatch that used to live here was gated behind the SQLite
            # backup path (so it never ran on Postgres). Re-wire PG report generation here as a
            # deliberate follow-up rather than carrying the dead SQLite code.

def parse_args(err: base.ErrorSink) -> ParsedArgs:
    # NOTE: Parse .INI file if present and get arguments for it
    result          = ParsedArgs()
    result.ini_path = os.getenv('SESH_PRO_BACKEND_INI_PATH', '')
    if len(result.ini_path) > 0:
        if not pathlib.Path(result.ini_path).exists():
            log.error(f'.INI config file "{result.ini_path}", was specified but does not exist/is not readable')
            sys.exit(1)

        ini_parser                                 = configparser.ConfigParser()
        _                                          = ini_parser.read(filenames=result.ini_path)

        base_section: configparser.SectionProxy    = ini_parser['base']
        result.db_url                              = base_section.get(option='db_url',                      fallback='')
        result.backend_key_path                    = base_section.get(option='backend_key_path',            fallback='')
        result.log_path                            = base_section.get(option='log_path',                    fallback='')
        result.dev                                 = base_section.getboolean(option='dev',                  fallback=False)
        result.unsafe_logging                      = base_section.getboolean(option='unsafe_logging',       fallback=False)

        result.with_platform_apple                 = base_section.getboolean(option='with_platform_apple',  fallback=False)
        result.with_platform_google                = base_section.getboolean(option='with_platform_google', fallback=False)

        result.platform_testing_env                = base_section.getboolean(option='platform_testing_env', fallback=False)

        webhook_index = 0
        while True:
            webhook_label: str = f'session_webhook.{webhook_index}'
            if not ini_parser.has_section(webhook_label):
                break

            webhook_section: configparser.SectionProxy = ini_parser[webhook_label]
            webhook_enabled: bool | None               = webhook_section.getboolean('enabled')
            webhook_url:     str | None                = webhook_section.get('url')
            webhook_name:    str | None                = webhook_section.get('name')

            if webhook_name == None:
                log.error(f"Failed to parse webhook section {webhook_label}, missing \'name\'")
                sys.exit(1)

            if webhook_url == None:
                log.error(f"Failed to parse webhook section {webhook_label}, missing \'url\'")
                sys.exit(1)

            if webhook_enabled == None:
                log.error(f"Failed to parse webhook section {webhook_label}, missing \'enabled\'")
                sys.exit(1)

            webhook_index += 1
            result.session_webhooks.append(SessionWebhook(name=webhook_name, url=webhook_url, enabled=webhook_enabled))

        if result.with_platform_apple:
            if 'apple' in ini_parser:
                apple_section: configparser.SectionProxy   = ini_parser['apple']
                result.apple_app_id                        = apple_section.getint(option='app_id')
                result.apple_bundle_id                     = apple_section.get(option='bundle_id',                     fallback='')
                result.apple_issuer_id                     = apple_section.get(option='issuer_id',                     fallback='')
                result.apple_key_id                        = apple_section.get(option='key_id',                        fallback='')
                result.apple_key_path                      = apple_section.get(option='key_path',                      fallback='')
                result.apple_root_cert_ca_g2_path          = apple_section.get(option='root_cert_ca_g2_path',          fallback='')
                result.apple_root_cert_ca_g3_path          = apple_section.get(option='root_cert_ca_g3_path',          fallback='')
                result.apple_root_cert_path                = apple_section.get(option='root_cert_path',                fallback='')
                result.apple_sandbox_env                   = apple_section.getboolean(option='sandbox_env',            fallback=False)
            else:
                err.msg_list.append('Platform Apple was enabled but [apple] section is missing')

        if result.with_platform_google:
            if 'google' in ini_parser:
                google_section: configparser.SectionProxy = ini_parser['google']
                result.google_cloud_app_credentials_path  = google_section.get(option='cloud_app_credentials_path', fallback='')
                result.google_cloud_project_id            = google_section.get(option='cloud_project_id',                   fallback='')
                result.google_cloud_subscription_name     = google_section.get(option='cloud_subscription_name',            fallback='')
                result.google_package_name                = google_section.get(option='package_name',                       fallback='')
                result.google_subscription_product_id     = google_section.get(option='subscription_product_id',            fallback='')
            else:
                err.msg_list.append('Platform Google was enabled but [google] section is missing')

    # NOTE: Get arguments from environment, they override .INI values if specified
    result.db_url                         = os.getenv('SESH_PRO_BACKEND_DB_URL',                             result.db_url)
    result.backend_key_path               = os.getenv('SESH_PRO_BACKEND_KEY_PATH',                           result.backend_key_path)
    result.log_path                       = os.getenv('SESH_PRO_BACKEND_LOG_PATH',                           result.log_path)
    result.dev                            = base.os_get_boolean_env('SESH_PRO_BACKEND_DEV',                  result.dev)
    result.with_platform_apple            = base.os_get_boolean_env('SESH_PRO_BACKEND_WITH_PLATFORM_APPLE',  result.with_platform_apple)
    result.with_platform_google           = base.os_get_boolean_env('SESH_PRO_BACKEND_WITH_PLATFORM_GOOGLE', result.with_platform_google)
    result.with_platform_google           = base.os_get_boolean_env('SESH_PRO_BACKEND_PLATFORM_TESTING_ENV', result.with_platform_google)

    if result.with_platform_apple:
        if len(result.apple_key_id) == 0:
            err.msg_list.append('Platform Apple was enabled but key_id was not specified')
        if len(result.apple_issuer_id) == 0:
            err.msg_list.append('Platform Apple was enabled but issuer_id was not specified')
        if len(result.apple_bundle_id) == 0:
            err.msg_list.append('Platform Apple was enabled but bundle_id was not specified')
        if len(result.apple_key_path) == 0:
            err.msg_list.append('Platform Apple was enabled but key_path was not specified')
        if len(result.apple_root_cert_path) == 0:
            err.msg_list.append('Platform Apple was enabled but root_cert_path was not specified')
        if len(result.apple_root_cert_ca_g2_path) == 0:
            err.msg_list.append('Platform Apple was enabled but root_cert_ca_g2_path was not specified')
        if len(result.apple_root_cert_ca_g3_path) == 0:
            err.msg_list.append('Platform Apple was enabled but root_cert_ca_g3_path was not specified')

        if not result.apple_sandbox_env:
            if result.apple_app_id is None:
                err.msg_list.append('Platform Apple was enabled in production mode (e.g. not sandbox mode) but the production_app_id was not specified')

        if result.apple_sandbox_env:
            if result.platform_testing_env == False:
                log.warning('Platform Apple was enabled in sandbox mode but platform_testing_env was not set to true. You want to set this to true, overriding the flag to true')
                result.platform_testing_env = True

        if not err.has():
            try:
                result.apple_key = pathlib.Path(result.apple_key_path).read_bytes()
                result.apple_root_certs = [
                    pathlib.Path(result.apple_root_cert_path).read_bytes(),
                    pathlib.Path(result.apple_root_cert_ca_g2_path).read_bytes(),
                    pathlib.Path(result.apple_root_cert_ca_g3_path).read_bytes(),
                ]
            except Exception as e:
                err.msg_list.append(f'Platform Apple was enabled but we are unable to read the path: {e}');

    if result.with_platform_google:
        if len(result.google_package_name) == 0:
            err.msg_list.append('Platform Google was enabled but package_name was not specified')
        if len(result.google_cloud_project_id) == 0:
            err.msg_list.append('Platform Google was enabled but cloud_project_id was not specified')
        if len(result.google_cloud_subscription_name) == 0:
            err.msg_list.append('Platform Google was enabled but cloud_subscription_name was not specified')
        if len(result.google_cloud_app_credentials_path) == 0:
            err.msg_list.append('Platform Google was enabled but cloud_application_credentials_path was not specified')
        if len(result.google_subscription_product_id) == 0:
            err.msg_list.append('Platform Google was enabled but subscription_product_id was not specified')

    return result


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
    parsed_args: ParsedArgs   = parse_args(err);
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

        # NOTE: Running the application just in Flask (e.g. local development) we
        # need a way to signal to the long-running payment expiry thread to
        # terminate itself, we do this using a cv+mutex combo otherwise the
        # application hangs on exit, forever as the thread is never terminated.
        #
        # In UWSGI we want to use the same code to catch the signal and terminate,
        # but, by default UWSGI hijacks the signal handler and so our thread
        # termination code doesn't run. However, you can override this on UWSGI by
        # passing the flag `py-call-osafterfork` which makes the UWSGI process
        # respect our custom signal handlers.
        #
        # This option however is not present on older UWSGI version like 2.0.21. For
        # those versions setting these signal handlers do not solve the hang-on-exit
        # issue and instead the user should set `--worker-reload-mercy` to a short
        # value to get UWSGI to terminate the process for you.
        #
        # TODO: Find a better solution to this
        _ = signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
        _ = signal.signal(signal.SIGTERM, signal_handler) # Terminate
        _ = signal.signal(signal.SIGQUIT, signal_handler) # Quit

        # Dispatch a long-running "thread" that wakes up every 00:00 UTC to expire
        # entries in the DB. This thread has program-lifetime and hence should exit
        # when the Flask app exits.
        #
        # In UWSGI mode, we launch multiple processes, so we actually have multiple
        # of these threads running. I considered separating this into a separate app
        # that you have to run, or, some smart way to detect that only one process
        # out of the set should be running this thread to clean the DB.
        #
        # But this complicates the architecture _alot_ trying to get UWSGI to
        # intelligently handle this, either by defining a custom hook, or
        # _multiple_ UWSGI instances, or running them under UWSGI emperor so that
        # you can then run 2 apps (100% more setup than 1 app!) for the backend.
        #
        # The trade-off in choosing that is unacceptable for managing Session Pro
        # subscriptions which on paper is a very simple CRUD application.
        # Instead, I've embedded the periodic cleaning of the DB into the app
        # itself so that the entire stack is self-contained and hence monolithic.
        #
        # By running the app, either in flask, UWSGI w/ multiple processes or
        # whatever, that is in itself self-sufficient to maintain a valid Session
        # Pro database without any additional configuration. Just launch the app and
        # it "just works". This avoids the need for external frameworks like UWSGI
        # needing to know about internal details (i.e. leaky abstractions) to run
        # the application.
        #
        # The trade-off for this is that all processes running the app will attempt
        # to clean the DB and race at UTC 00:00 to do so. We just make sure to do
        # that operation over an atomic transaction and allow exactly one process
        # out of the N available to actually clean the DB. The rest will no-op.
        thread = threading.Thread(target=backend_maintenance_thread_entry_point, args=(parsed_args.db_url,))
        thread.start()

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

        # NOTE: Enable Google Play Store notification handling, this is a blocking call so it's delegated
        # to a thread. We use Google's asynchronous streaming pull client which spawns a thread pool
        # (10 threads by default) to process messages.
        if parsed_args.with_platform_google:
            if base.PLATFORM_TESTING_ENV:
                base.DEFAULT_GOOGLE_GRACE_PERIOD = base.timedelta_from_ms(platform_google_api.testing_grace_period_duration_ms)
            global google_thread_context
            google_thread_context = platform_google.init(cloud_project_id                  = parsed_args.google_cloud_project_id,
                                                          package_name                      = parsed_args.google_package_name,
                                                          cloud_subscription_name           = parsed_args.google_cloud_subscription_name,
                                                          subscription_product_id           = parsed_args.google_subscription_product_id,
                                                          app_credentials_path              = parsed_args.google_cloud_app_credentials_path)
            assert google_thread_context.thread
            google_thread_context.thread.start()
    return result

# Flask entry point
stop_maintenance_thread   = False
proof_expiry_thread_event = threading.Event()
flask_app: flask.Flask    = entry_point()
