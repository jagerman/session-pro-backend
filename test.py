'''
Testing module for the Session Pro Backend, testing internal and public APIs.

The backend tests call the DB APIs directly to test the outcome on the tables in the database.
Each test (and each TestingContext) runs against a fresh, throwaway PostgreSQL database minted by
the `pg_database` fixture on an ephemeral cluster (see conftest.py).

The server tests spins up a local Flask instance as per
(https://flask.palletsprojects.com/en/stable/testing/#sending-requests-with-the-test-client) and
sends a request using the test client and we vet the request and response produced by hitting said
endpoint.
'''

import argparse
import collections.abc
import contextlib
import pprint
import flask
import json
import nacl.signing
import nacl.bindings
import nacl.public
import os
import pathlib
import pytest
import re
import time
import werkzeug
import dataclasses
import typing
import enum
import psycopg
import psycopg_pool
import traceback
import datetime

from providers import google_play
from providers.google_play.types import GoogleDuration, SubscriptionProductDetails
from vendor import onion_req
import backend
import base
import cli
import config
import migrations
import server
from providers import app_store
import db

from appstoreserverlibrary.models.ResponseBodyV2DecodedPayload import (
    ResponseBodyV2DecodedPayload as AppleResponseBodyV2DecodedPayload,
)
from appstoreserverlibrary.models.JWSTransactionDecodedPayload import (
    JWSTransactionDecodedPayload as AppleJWSTransactionDecodedPayload,
)
from appstoreserverlibrary.models.JWSRenewalInfoDecodedPayload import (
    JWSRenewalInfoDecodedPayload as AppleJWSRenewalInfoDecodedPayload,
)
from appstoreserverlibrary.models.Data import Data as AppleData
from appstoreserverlibrary.models.Environment import Environment as AppleEnvironment
from appstoreserverlibrary.models.TransactionReason import TransactionReason as AppleTransactionReason
from appstoreserverlibrary.models.Type import Type as AppleType
from appstoreserverlibrary.models.Subtype import Subtype as AppleSubtype
from appstoreserverlibrary.models.Status import Status as AppleStatus
from appstoreserverlibrary.models.NotificationTypeV2 import NotificationTypeV2 as AppleNotificationTypeV2
from appstoreserverlibrary.models.InAppOwnershipType import InAppOwnershipType as AppleInAppOwnershipType
from appstoreserverlibrary.models.RevocationReason import RevocationReason as AppleRevocationReason
from appstoreserverlibrary.models.AutoRenewStatus import AutoRenewStatus as AppleAutoRenewStatus
from appstoreserverlibrary.models.ConsumptionRequestReason import (
    ConsumptionRequestReason as AppleConsumptionRequestReason,
)


def pk_hex(pk: bytes | nacl.signing.VerifyKey | None) -> str:
    return 'None' if pk is None else bytes(pk).hex()


def derived_status(payment: backend.PaymentRow, at: datetime.datetime | None = None) -> base.PaymentStatus:
    """A payment's status is derived from its timestamps, not stored (see backend.derive_payment_status).

    These assertions check the *latched* facts — redeemed / revoked / unredeemed — which do not depend
    on the observation time (revoked short-circuits; purchase is always before expiry), so by default we
    observe at the payment's purchase instant. Pass `at` to probe the one time-relative boundary,
    expiry, explicitly (e.g. `payment.expires_at` to assert Expired)."""
    return backend.derive_payment_status(payment, payment.purchased_at if at is None else at)


@dataclasses.dataclass
class TestingContext:
    """
    Sets up a database with the necessary tables and flask instance that you can simulate HTTP
    requests to, to target the Session Pro Backend routes. This class is designed to be used in a
    `with` context such that the DB is closed on scope exit.
    Tests have a fresh DB to work with for each `with` context and each chunk of tests to execute.
    """

    # `Test*` name would trip pytest collection; un-annotated so the dataclass doesn't make it a field.
    __test__ = False

    db_engine: psycopg_pool.ConnectionPool
    flask_app: flask.Flask
    flask_client: werkzeug.Client
    provider_testing_env: bool = False
    db_url_factory: typing.Callable[[], str] | None = None

    def __init__(self, db_url_factory: typing.Callable[[], str], provider_testing_env: bool = False):
        self.db_url_factory = db_url_factory
        self.provider_testing_env = provider_testing_env

    def __enter__(self):
        base.PROVIDER_TESTING_ENV = self.provider_testing_env
        if base.PROVIDER_TESTING_ENV:
            base.DEFAULT_GOOGLE_GRACE_PERIOD = base.timedelta_from_ms(google_play.api.testing_grace_period_duration_ms)

        # Mint a fresh database on the ephemeral PostgreSQL cluster
        assert self.db_url_factory is not None
        database_url = self.db_url_factory()

        # Bootstrap DB
        engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=database_url)
        assert engine

        # Generate the backend signing key for this instance. The app loads its key externally now
        # (never from the DB); expose it as self.backend_key for tests that verify signatures.
        self.db_engine = engine
        self.backend_key = nacl.signing.SigningKey.generate()

        # Setup flask
        self.flask_app = server.init(testing_mode=True, database_url=database_url, backend_key=self.backend_key)
        self.flask_client = self.flask_app.test_client()
        return self

    def __exit__(
        self, exc_type: object | None, exc_value: object | None, traceback: traceback.TracebackException | None
    ):
        self.db_engine.close()
        base.PROVIDER_TESTING_ENV = False
        base.DEFAULT_GOOGLE_GRACE_PERIOD = base.DEFAULT_APPLE_GRACE_PERIOD
        return False

    @contextlib.contextmanager
    def connection(self) -> collections.abc.Iterator[psycopg.Connection]:
        with db.connection(self.db_engine) as conn:
            yield conn


def test_dry_run_backup_rotation():
    now = datetime.datetime(2025, 6, 1, 12, 0, 0)
    files = [
        "/b/2025-05-30_100000_a.sql",
        "/b/2025-01-01_000000_b.sql",
        "/b/2024-12-15_235959_c.sql",
        "/b/2024-12-01_000000_d.sql",
        "/b/2024-12-30_235959_e.sql",
        "/b/2024-11-05_080000_f.sql",
        "/b/2024-11-20_150000_g.sql",
        "/b/2025-01-10_090000_h.sql",
        "/b/2025-01-20_100000_i.sql",
        "invalid.txt",
        "/b/2024-11-01_000000_j.sql",
        "/b/2024-11-15_000000_k.sql",
    ]
    result = base.backup_rotation_from_dated_files_dry_run(files, now)
    keep = {p.name for p in result.to_keep}
    delete = {p.name for p in result.to_delete}
    assert keep == {
        # NOTE: Earliest of each month after the 180 day cutoff
        "2024-11-01_000000_j.sql",
        "2024-12-01_000000_d.sql",
        # NOTE: Because within the last 180 days
        "2024-12-15_235959_c.sql",
        "2024-12-30_235959_e.sql",
        "2025-01-01_000000_b.sql",
        "2025-01-10_090000_h.sql",
        "2025-01-20_100000_i.sql",
        "2025-05-30_100000_a.sql",
    }
    assert delete == {"2024-11-05_080000_f.sql", "2024-11-20_150000_g.sql", "2024-11-15_000000_k.sql"}
    assert len(result.to_keep) == 8 and len(result.to_delete) == 3


def test_cli_parse_helpers():
    # The CLI arg parsers raise ValueError on malformed input (no ErrorSink); command handlers catch it,
    # print "Failed to parse arguments", and exit 1. Here we pin the parse contract directly.

    # parse_set_user_error_arg: "<provider>:<payment_id>=[true|false]", comma-separated.
    assert cli.parse_set_user_error_arg('') == []
    assert cli.parse_set_user_error_arg('google_play:tok1=true, app_store:otx2=false') == [
        (base.PaymentProvider.GooglePlayStore, 'tok1', True),
        (base.PaymentProvider.iOSAppStore, 'otx2', False),
    ]
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('google_play-tok1-true')  # no ':' / '='
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('notaprovider:tok=true')  # bad provider (was swallowed into the sink)
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('google_play:tok=maybe')  # bad flag
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('nil:tok=true')  # Nil provider rejected
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('rangeproof:tok=true')  # Rangeproof has no errors

    # parse_payment_id_list: "<provider>:<payment_id>", comma-separated.
    assert cli.parse_payment_id_list('') == []
    assert cli.parse_payment_id_list('google_play:tok1, rangeproof:ord2') == [
        (base.PaymentProvider.GooglePlayStore, 'tok1'),
        (base.PaymentProvider.Rangeproof, 'ord2'),
    ]
    with pytest.raises(ValueError):
        cli.parse_payment_id_list('missing-colon')
    with pytest.raises(ValueError):
        cli.parse_payment_id_list('notaprovider:tok')

    # parse_message_id_list: opaque strings, taken verbatim.
    assert cli.parse_message_id_list('') == []
    assert cli.parse_message_id_list('a, b ,c') == ['a', 'b', 'c']
    with pytest.raises(ValueError):
        cli.parse_message_id_list('a,,b')  # empty entry

    # parse_master_pkey: 64 hex chars (optionally 0x-prefixed), returns a VerifyKey (never None).
    good_hex = '00' * 32
    assert isinstance(cli.parse_master_pkey(good_hex), nacl.signing.VerifyKey)
    assert isinstance(cli.parse_master_pkey('0x' + good_hex), nacl.signing.VerifyKey)
    with pytest.raises(ValueError):
        cli.parse_master_pkey('abcd')  # too short
    with pytest.raises(ValueError):
        cli.parse_master_pkey('zz' * 32)  # right length, not hex


def test_cli_require_config(tmp_path, monkeypatch):
    # require_config resolves the [base] config or exits(1) with a clear message — no ErrorSink, and (the
    # bug the sink hid) a missing file now exits instead of silently returning an empty config. Env
    # overrides are cleared so the file alone drives the result.
    monkeypatch.delenv('SESH_PRO_BACKEND_DB_URL', raising=False)
    monkeypatch.delenv('SESH_PRO_BACKEND_KEY_PATH', raising=False)

    def ns(config):
        return argparse.Namespace(config=config)

    with pytest.raises(SystemExit):
        cli.require_config(ns(None))  # no --config

    with pytest.raises(SystemExit):
        cli.require_config(ns(str(tmp_path / 'nope.ini')))  # nonexistent file (was a silent empty config)

    no_base = tmp_path / 'no_base.ini'
    no_base.write_text('[other]\nx = 1\n')
    with pytest.raises(SystemExit):
        cli.require_config(ns(str(no_base)))  # missing [base]

    no_url = tmp_path / 'no_url.ini'
    no_url.write_text('[base]\nlog_path = /var/log/x\n')
    with pytest.raises(SystemExit):
        cli.require_config(ns(str(no_url)))  # [base] but no db_url

    good = tmp_path / 'good.ini'
    good.write_text('[base]\ndb_url = postgresql:///x\nbackend_key_path = /k\nlog_path = /l\n')
    cfg = cli.require_config(ns(str(good)))
    assert cfg.db_url == 'postgresql:///x' and cfg.backend_key_path == '/k' and cfg.log_path == '/l'


def test_config_parse_args(monkeypatch):
    # parse_args accumulates field problems and raises them together as a ConfigError (an is-a ValueError)
    # rather than threading an ErrorSink. Clear the ambient SESH_PRO_BACKEND_* so the env alone drives it.
    for k in list(os.environ):
        if k.startswith('SESH_PRO_BACKEND_'):
            monkeypatch.delenv(k, raising=False)

    # Nothing enabled -> clean parse, no raise.
    parsed = config.parse_args()
    assert isinstance(parsed, config.ParsedArgs)
    assert parsed.with_provider_app_store is False and parsed.with_provider_google_play is False

    # Enable Apple with no [apple] config -> every missing field is reported at once in one ConfigError.
    monkeypatch.setenv('SESH_PRO_BACKEND_WITH_PROVIDER_APP_STORE', '1')
    with pytest.raises(config.ConfigError) as excinfo:
        config.parse_args()
    assert isinstance(excinfo.value, ValueError)  # ConfigError is-a ValueError
    assert len(excinfo.value.errors) >= 5  # accumulates ALL problems, not just the first
    assert all('app_store' in m for m in excinfo.value.errors)


def test_google_handle_parsed_notification_fetch_failure(monkeypatch, pg_database):
    # CHARACTERIZATION (pre-ErrorSink-rewrite safety net). Pins the CURRENT control-flow contract of the
    # Google subscription path so the exception rewrite can't silently change it:
    #   a failed fetch_subscription_v2_details -> handle_parsed_notification returns handled=False (so the
    #   pull loop does NOT ack -> Google redelivers), err is populated, and -- the subtle part -- the tx is
    #   NOT cancelled on this early-return path (nothing was written yet, so it commits). Contrast a failure
    #   inside handle_subscription_notification, which DOES set tx.cancel. If the rewrite changes either,
    #   this test must fail loudly and the change be made deliberately.
    with TestingContext(pg_database) as ctx:

        def boom_fetch(*args, **kwargs):
            args[2].msg_list.append('injected fetch failure')  # (package_name, purchase_token, err)
            return None

        monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', boom_fetch)

        parse = google_play.ParsedNotification(
            payload_type=google_play.ParsedNotificationPayloadType.Subscription,
            purchase_token='tok-xyz',
            package_name='pkg',
            event_time_ms=1,
        )
        err = base.ErrorSink()
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                handled = google_play.handle_parsed_notification(tx, parse, err)
                assert handled is False
                assert err.has()
                assert tx.cancel is False  # fetch-fail early-return does NOT cancel (current behavior)


def _google_subscription_parse(monkeypatch):
    # Shared setup for the two below: fetch succeeds (returns a non-None sentinel), reaching the parse step.
    monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', lambda *a, **k: object())
    return google_play.ParsedNotification(
        payload_type=google_play.ParsedNotificationPayloadType.Subscription,
        purchase_token='tok-xyz',
        package_name='pkg',
        event_time_ms=1,
    )


def test_google_handle_parsed_notification_parse_failure(monkeypatch, pg_database):
    # CHARACTERIZATION: a failure while PARSING fetched subscription details is the same early-return
    # asymmetry as the fetch failure -- handled=False, err populated, tx NOT cancelled.
    with TestingContext(pg_database) as ctx:
        parse = _google_subscription_parse(monkeypatch)
        monkeypatch.setattr(
            'providers.google_play.api.parse_subscription_purchase_tx',
            lambda *a, **k: (k['err'].msg_list.append('injected parse failure'), object())[1],
        )
        monkeypatch.setattr('providers.google_play.api.parse_subscription_plan_event_tx', lambda *a, **k: object())
        err = base.ErrorSink()
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                handled = google_play.handle_parsed_notification(tx, parse, err)
                assert handled is False
                assert err.has()
                assert tx.cancel is False  # parse-fail early-return also does NOT cancel


def test_google_handle_parsed_notification_deep_failure_cancels(monkeypatch, pg_database):
    # CHARACTERIZATION (the CONTRASTING side of the asymmetry): a failure INSIDE
    # handle_subscription_notification reaches the function tail, which requires tx.cancel to have been set
    # -> handled=False, err populated, and tx IS cancelled (so the transaction rolls back). This is the case
    # the fetch/parse early-returns skip.
    with TestingContext(pg_database) as ctx:
        parse = _google_subscription_parse(monkeypatch)
        monkeypatch.setattr('providers.google_play.api.parse_subscription_purchase_tx', lambda *a, **k: object())
        monkeypatch.setattr('providers.google_play.api.parse_subscription_plan_event_tx', lambda *a, **k: object())

        def deep_boom(**k):
            k['err'].msg_list.append('injected deep failure')
            k['tx'].cancel = True

        monkeypatch.setattr('providers.google_play.notifications.handle_subscription_notification', deep_boom)
        err = base.ErrorSink()
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                handled = google_play.handle_parsed_notification(tx, parse, err)
                assert handled is False
                assert err.has()
                assert tx.cancel is True  # deep failure DOES cancel (reaches the tail assert)


def test_google_process_notification_message(monkeypatch, pg_database):
    # CHARACTERIZATION of _process_notification_message (the per-message tx block extracted from the pull
    # loop in 91ad5fe). Pins the control flow the ErrorSink rewrite must preserve, INCLUDING the
    # present+unhandled+no-prior-error FAILURE branch that records a poison user_error -- add_user_error was
    # fixed here (string-code provider + at= datetime; it was int()/unix_ts_ms= broken, refactor-introduced).
    # Seeds prior user_errors via direct SQL to stay independent of the writer under test.
    now_s = 1_600_000_000.0
    expiry = base.datetime_from_unix_ms(int(now_s * 1000) + base.MILLISECONDS_IN_DAY)
    seeded_at = base.datetime_from_unix_ms(int(now_s * 1000))

    def make_msg(message_id, token):
        return google_play.SortedMessage(
            message_id=message_id,
            parse=google_play.ParsedNotification(
                payload_type=google_play.ParsedNotificationPayloadType.Subscription,
                purchase_token=token,
                package_name='pkg',
                event_time_ms=int(now_s * 1000),
            ),
        )

    def seed_user_error(conn, token):
        with db.transaction(conn) as tx:
            db.query(
                tx.conn,
                'INSERT INTO user_errors (payment_provider, payment_id, errored_at) VALUES (%s, %s, %s)',
                base.PaymentProvider.GooglePlayStore.value,
                token,
                seeded_at,
            )

    def is_handled(conn, message_id):
        # Read-only lookup: wrap conn in a bare SQLTransaction (no BEGIN needed on the autocommit pool).
        return backend.google_notification_message_id_is_in_db(db.SQLTransaction(conn=conn), message_id).handled

    with TestingContext(pg_database) as ctx:
        # (A) message not in the DB -> handled=True (skip; someone may have deleted it out-of-band).
        with ctx.connection() as conn:
            assert (
                google_play.notifications._process_notification_message(
                    conn, make_msg('m-absent', 'tok-a'), base.ErrorSink(), now_s
                )
                is True
            )

        # (B) message present + already handled -> handled=True (no reprocessing).
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_add_notification_id(tx, 'm-handled', expiry, '')
                backend.google_set_notification_handled(tx, message_id='m-handled', delete=False)
            assert (
                google_play.notifications._process_notification_message(
                    conn, make_msg('m-handled', 'tok-b'), base.ErrorSink(), now_s
                )
                is True
            )

        # (C) present + unhandled + SUCCESS -> handled=True, the notification is marked handled, and a prior
        #     user_error for the token is cleared -- all committed in the one transaction.
        monkeypatch.setattr(
            'providers.google_play.notifications.handle_parsed_notification', lambda tx, parse, err: True
        )
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_add_notification_id(tx, 'm-ok', expiry, '')
            seed_user_error(conn, 'tok-c')
            assert (
                google_play.notifications._process_notification_message(
                    conn, make_msg('m-ok', 'tok-c'), base.ErrorSink(), now_s
                )
                is True
            )
            assert is_handled(conn, 'm-ok') is True
            assert backend.has_user_error(conn, base.PaymentProvider.GooglePlayStore, 'tok-c') is False

        # (D) present + unhandled + FAILURE (no tx.cancel) WITH a prior user_error -> handled=False, the
        #     notification stays unhandled, and the prior error is left intact (the failure branch neither
        #     clears nor re-adds while already in error state -- so it never reaches the broken add path).
        monkeypatch.setattr(
            'providers.google_play.notifications.handle_parsed_notification', lambda tx, parse, err: False
        )
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_add_notification_id(tx, 'm-fail', expiry, '')
            seed_user_error(conn, 'tok-d')
            assert (
                google_play.notifications._process_notification_message(
                    conn, make_msg('m-fail', 'tok-d'), base.ErrorSink(), now_s
                )
                is False
            )
            assert is_handled(conn, 'm-fail') is False
            assert backend.has_user_error(conn, base.PaymentProvider.GooglePlayStore, 'tok-d') is True

        # (E) present + unhandled + FAILURE (no tx.cancel) + NO prior error -> RECORDS a poison user_error
        #     (add_user_error, now fixed: string-code provider + at= datetime). Returns False, notification
        #     stays unhandled, the token is now flagged. The poison ride the same tx, and this failure did
        #     not cancel, so it commits. (This branch used to raise TypeError before the add_user_error fix.)
        monkeypatch.setattr(
            'providers.google_play.notifications.handle_parsed_notification', lambda tx, parse, err: False
        )  # self-contained (not relying on (D))
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_add_notification_id(tx, 'm-poison', expiry, '')
            assert backend.has_user_error(conn, base.PaymentProvider.GooglePlayStore, 'tok-e') is False
            assert (
                google_play.notifications._process_notification_message(
                    conn, make_msg('m-poison', 'tok-e'), base.ErrorSink(), now_s
                )
                is False
            )
            assert is_handled(conn, 'm-poison') is False
            assert backend.has_user_error(conn, base.PaymentProvider.GooglePlayStore, 'tok-e') is True


def test_google_ack_sweep(monkeypatch, pg_database):
    # The mule's needs_ack sweep is the SOLE Google purchase-acker (notification handling only records the
    # obligation). Cover its three outcomes: a clean ack clears the flag; an ack that FAILS but that Google
    # already considers acknowledged (we acked then crashed before clearing) clears via the authoritative
    # acknowledgement_state; a genuinely failing ack leaves the flag set to retry next sweep.
    dsn = pg_database()
    monkeypatch.setattr(base, 'DB_URL', dsn)  # the sweep opens its own connection via base.DB_URL
    pool = backend.bootstrap_db(database_url=dsn)
    assert pool

    class _AckedDetails:
        acknowledgement_state = google_play.types.SubscriptionsV2AcknowledgementState.ACKNOWLEDGED

    def seed(conn, token, needs_ack):
        tx = base.PaymentProviderTransaction()
        tx.provider = base.PaymentProvider.GooglePlayStore
        tx.google_payment_token = token
        tx.google_order_id = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        err = base.ErrorSink()
        backend.add_unredeemed_payment(
            conn,
            payment_tx=tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=base.EPOCH,
            expires_at=base.EPOCH,
            platform_refund_expires_at=base.EPOCH,
            platform_obfuscated_account_id=os.urandom(32),
            err=err,
            needs_ack=needs_ack,
        )
        assert not err.msg_list, err.msg_list

    def flag(conn, token):
        return db.query_one(conn, 'SELECT needs_ack FROM google_play_payment_details WHERE payment_token = %s', token)[
            0
        ]

    tok_ok = os.urandom(32).hex()
    tok_crashed = os.urandom(32).hex()
    tok_fail = os.urandom(32).hex()
    tok_already = os.urandom(32).hex()

    with db.connection(pool) as conn:
        # Each case seeds its token TRUE just before running the sweep, so the sweep (which processes all
        # currently-TRUE tokens) only sees this case's token — no cross-case interference, no re-seeding.

        # (1) Ack succeeds -> flag cleared. A FALSE row (already acknowledged at registration) is never
        #     even selected by the sweep.
        seed(conn, tok_already, needs_ack=False)
        seed(conn, tok_ok, needs_ack=True)
        monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda purchase_token, err: None)
        google_play.notifications._sweep_pending_acks()
        assert flag(conn, tok_ok) is False
        assert flag(conn, tok_already) is False

        # (2) Ack FAILS but Google reports it already ACKNOWLEDGED (acked-then-crashed) -> cleared via the
        #     authoritative acknowledgement_state fetch.
        seed(conn, tok_crashed, needs_ack=True)
        monkeypatch.setattr(
            'providers.google_play.api.subscription_v1_acknowledge',
            lambda purchase_token, err: err.msg_list.append('ack boom'),
        )
        monkeypatch.setattr(
            'providers.google_play.api.fetch_subscription_v2_details', lambda pkg, token, err: _AckedDetails()
        )
        google_play.notifications._sweep_pending_acks()
        assert flag(conn, tok_crashed) is False

        # (3) Ack FAILS and Google does NOT confirm acknowledged (fetch returns nothing) -> flag stays set
        #     for the next sweep. (ack stub from case 2 still in effect.)
        seed(conn, tok_fail, needs_ack=True)
        monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', lambda pkg, token, err: None)
        google_play.notifications._sweep_pending_acks()
        assert flag(conn, tok_fail) is True
    pool.close()


def test_migrations_bootstrap_and_idempotency(pg_database):
    # bootstrap_db runs the schema/ migrations; every migration file should be recorded, the globals
    # rows seeded exactly once, and a second pass must be a clean no-op (nothing re-run or duplicated).
    schema_dir = pathlib.Path(migrations.__file__).parent / 'schema'
    expected = {p.name for p in schema_dir.iterdir() if re.match(r'^\d+_.*\.(sql|py)$', p.name)}
    assert expected, 'expected some migration files to exist'

    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool

    with db.connection(pool) as conn:
        applied = {row[0] for row in db.query(conn, 'SELECT name FROM migrations_applied')}
        assert applied == expected
        assert db.query_scalar(conn, 'SELECT COUNT(*) FROM globals') == 2

        # Idempotent: re-running applies nothing new and does not duplicate the globals seed.
        migrations.apply_migrations(conn)
        assert {row[0] for row in db.query(conn, 'SELECT name FROM migrations_applied')} == expected
        assert db.query_scalar(conn, 'SELECT COUNT(*) FROM globals') == 2
    pool.close()


def test_migrations_reject_duplicate_basename(tmp_path, monkeypatch):
    (tmp_path / '005_foo.sql').write_text('SELECT 1;')
    (tmp_path / '005_foo.py').write_text('def apply_005_foo(conn): pass\n')
    monkeypatch.setattr(migrations, 'SCHEMA_DIR', tmp_path)
    with pytest.raises(RuntimeError):
        migrations._migration_files()


def test_status_endpoint(pg_database):
    # /status is reachable BOTH directly (a plain GET, for monitors) and over the v4 onion transport,
    # and reports the backend version + server time + signing pubkey (so a caller can fetch the key to
    # verify proofs instead of hard-coding it). No auth, no request body, no DB access.
    with TestingContext(db_url_factory=pg_database) as ctx:
        expected_pubkey = bytes(ctx.backend_key.verify_key).hex()

        def check(result: dict):
            assert result['version'] == base.BACKEND_VERSION, result
            assert result['signing_pubkey'] == expected_pubkey, result
            assert isinstance(result['timestamp'], int), result

        # (a) Direct GET
        response = ctx.flask_client.get('/status')
        assert response.status_code == 200
        body = response.get_json()
        assert body['status'] == 'ok', body
        check(body['result'])

        # (b) Through the v4 onion transport (make_request_v4 sends POST; /status accepts GET+POST)
        server_x25519_skey = ctx.backend_key.to_curve25519_private_key()
        our_x25519_skey = nacl.public.PrivateKey.generate()
        shared_key = onion_req.make_shared_key(
            our_x25519_skey=our_x25519_skey, server_x25519_pkey=server_x25519_skey.public_key
        )
        onion_request = onion_req.make_request_v4(
            our_x25519_pkey=our_x25519_skey.public_key, shared_key=shared_key, endpoint='/status', request_body={}
        )
        response = ctx.flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success
        body = json.loads(onion_response.body)
        assert body['status'] == 'ok', body
        check(body['result'])


def test_stale_revocation_is_not_served(pg_database):
    # Revocation is terminal (a set revoked_at is always in effect — there is no per-entry expiry now),
    # so relevance is governed by the server's list-level retention window: a generation revoked longer
    # ago than RETAIN_FOR drops out of the served list, independent of whether the prune sweep has run.
    # Filtering by the window (rather than depending on a prune) keeps the served answer independent of
    # housekeeping timing. This mirrors the guard in server.get_pro_revocations.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool

    RETAIN_FOR = base.SECONDS_IN_MONTH
    now = base.datetime_from_unix_seconds(1_700_000_000)
    master_pkey = nacl.signing.SigningKey.generate().verify_key
    with db.connection(pool) as conn:
        # A user with two generations: one revoked recently (still inside the window) and one revoked
        # long ago (past the window). Neither prune has run, so both rows are still present.
        with db.transaction(conn) as tx:
            user_id, gen_recent, token_recent, _created = backend.get_or_create_user_and_generation(
                tx, master_pkey, now
            )
            gen_stale, token_stale = backend.mint_generation(tx, user_id, now)
        with db.transaction(conn) as tx:
            db.query(
                tx.conn,
                "UPDATE generations SET revoked_at = %s WHERE id = %s",
                now - datetime.timedelta(seconds=1),
                gen_recent,
            )
            db.query(
                tx.conn,
                "UPDATE generations SET revoked_at = %s WHERE id = %s",
                now - datetime.timedelta(seconds=RETAIN_FOR + 1),
                gen_stale,
            )

        # Both are terminally revoked regardless of `now` (revocation has no per-entry expiry).
        assert backend.is_generation_revoked(conn, gen_recent, now) is True
        assert backend.is_generation_revoked(conn, gen_stale, now) is True

        # The served list applies the retention window: recent is in, stale is filtered out.
        retain_cutoff = now - datetime.timedelta(seconds=RETAIN_FOR)
        with db.transaction(conn) as tx:
            served = {
                bytes(row[0])
                for row in db.query(
                    tx.conn,
                    "SELECT token FROM generations WHERE revoked_at IS NOT NULL AND revoked_at > %s",
                    retain_cutoff,
                )
            }
        assert bytes(token_recent) in served
        assert bytes(token_stale) not in served
    pool.close()


def test_provider_dry_run_redeems_google_without_egress(monkeypatch, pg_database):
    # With provider_dry_run on, a Google payment redeems to a signed proof with NO call to Google: the
    # in-function stubs (synthetic already-acknowledged fetch + no-op acknowledge) stand in for the
    # egress. Deliberately NOT monkeypatching google_play.api here — exercising the real stubs is
    # the point. (Contrast test_backend_same_user_stacks_... which monkeypatches those calls instead.)
    monkeypatch.setattr(base, 'PROVIDER_DRY_RUN', True)

    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = datetime.datetime.now(datetime.timezone.utc)
    redeemed_at = base.round_datetime_to_next_day(now)

    db_conn = db_engine.getconn()
    try:
        # Seed a witnessed-unredeemed Google payment (as if a purchase notification had been received).
        seed_tx = base.PaymentProviderTransaction()
        seed_tx.provider = base.PaymentProvider.GooglePlayStore
        seed_tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        seed_tx.google_order_id = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=seed_tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=now,
            expires_at=redeemed_at + datetime.timedelta(days=30),
            platform_refund_expires_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_key.verify_key),
            err=err,
        )
        assert not err.msg_list, f'{err.msg_list}'

        # Client redeems it with a real add_pro_payment (no dev_* fields, no DEV. id, no monkeypatch).
        user_tx = backend.UserPaymentTransaction()
        user_tx.provider = base.PaymentProvider.GooglePlayStore
        user_tx.google_payment_token = seed_tx.google_payment_token
        user_tx.google_order_id = seed_tx.google_order_id
        add_payment_hash = backend.make_add_pro_payment_message(
            master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, payment_tx=user_tx
        )
        redeemed = backend.verify_and_add_pro_payment(
            conn=db_conn,
            signing_key=backend_key,
            request_at=now,
            redeemed_at=redeemed_at,
            master_pkey=master_key.verify_key,
            rotating_pkey=rotating_key.verify_key,
            payment_tx=user_tx,
            master_sig=master_key.sign(add_payment_hash).signature,
            rotating_sig=rotating_key.sign(add_payment_hash).signature,
        )

        assert redeemed.status == backend.RedeemPaymentStatus.Success
        assert redeemed.proof is not None
        assert not backend.get_unredeemed_payments_list(db_conn)
    finally:
        db_engine.putconn(db_conn)
        db_engine.close()


def test_backend_same_user_stacks_subscription_and_auto_redeem(monkeypatch, pg_database):
    monkeypatch.setattr("providers.google_play.api.subscription_v1_acknowledge", lambda *args, **kwargs: None)

    dummy_sub_v2_data = google_play.types.SubscriptionV2Data()
    monkeypatch.setattr(
        "providers.google_play.api.fetch_subscription_v2_details", lambda *args, **kwargs: dummy_sub_v2_data
    )

    # Test that the user's subscription stacks if they purchase two subscription with different
    # payment tokens.

    # Setup DB
    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    # Setup scenarios, single user who stacks a subscription
    backend_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    master_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    rotating_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    now: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)
    redeemed_at: datetime.datetime = base.round_datetime_to_next_day(now)

    @dataclasses.dataclass
    class Scenario:
        google_payment_token: str = ''
        google_order_id: str = ''
        plan: base.ProPlan = base.ProPlan.Nil
        proof: backend.ProSubscriptionProof = dataclasses.field(default_factory=backend.ProSubscriptionProof)
        payment_provider: base.PaymentProvider = base.PaymentProvider.Nil
        expires_at: datetime.datetime = base.EPOCH
        grace_period: datetime.timedelta = datetime.timedelta(0)

    scenarios: list[Scenario] = [
        Scenario(
            google_payment_token=os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            google_order_id='DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            plan=base.ProPlan.OneMonth,
            expires_at=redeemed_at + datetime.timedelta(days=30),
            grace_period=datetime.timedelta(0),
            payment_provider=base.PaymentProvider.GooglePlayStore,
        ),
        Scenario(
            google_payment_token=os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            google_order_id='DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            plan=base.ProPlan.TwelveMonth,
            expires_at=redeemed_at + datetime.timedelta(days=31),
            grace_period=datetime.timedelta(0),
            payment_provider=base.PaymentProvider.GooglePlayStore,
        ),
    ]

    db_conn: psycopg.Connection = db_engine.getconn()
    for index, it in enumerate(scenarios):
        # Add the "unredeemed" version of the payment, e.g. mock the notification from
        # IOS App Store/Google Play Store
        assert it.payment_provider == base.PaymentProvider.GooglePlayStore, "Currently only google is mocked"
        payment_tx = base.PaymentProviderTransaction()
        payment_tx.provider = it.payment_provider
        payment_tx.google_payment_token = it.google_payment_token
        payment_tx.google_order_id = it.google_order_id

        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=payment_tx,
            plan=it.plan,
            purchased_at=now,
            expires_at=it.expires_at,
            platform_refund_expires_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_key.verify_key),
            err=err,
        )
        assert not err.msg_list

        unredeemed_payment_list = backend.get_unredeemed_payments_list(db_conn)
        assert len(unredeemed_payment_list) == 1
        assert derived_status(unredeemed_payment_list[0]) == base.PaymentStatus.Unredeemed
        assert unredeemed_payment_list[0].payment_provider == it.payment_provider
        assert unredeemed_payment_list[0].purchased_at == now
        assert unredeemed_payment_list[0].redeemed_at is None
        assert unredeemed_payment_list[0].expires_at == it.expires_at
        assert unredeemed_payment_list[0].revoked_at is None
        assert unredeemed_payment_list[0].google_payment_token == it.google_payment_token
        assert unredeemed_payment_list[0].google_order_id == it.google_order_id
        assert unredeemed_payment_list[0].plan == it.plan

        # Register the payment
        add_pro_payment_tx = backend.UserPaymentTransaction()
        add_pro_payment_tx.provider = payment_tx.provider
        add_pro_payment_tx.google_payment_token = payment_tx.google_payment_token
        add_pro_payment_tx.google_order_id = payment_tx.google_order_id

        add_payment_hash = backend.make_add_pro_payment_message(
            master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, payment_tx=add_pro_payment_tx
        )

        redeemed_payment = backend.verify_and_add_pro_payment(
            conn=db_conn,
            signing_key=backend_key,
            request_at=now,
            redeemed_at=redeemed_at,
            master_pkey=master_key.verify_key,
            rotating_pkey=rotating_key.verify_key,
            payment_tx=add_pro_payment_tx,
            master_sig=master_key.sign(add_payment_hash).signature,
            rotating_sig=rotating_key.sign(add_payment_hash).signature,
        )
        it.proof = redeemed_payment.proof

        # Verify payment was redeemed
        unredeemed_payment_list = backend.get_unredeemed_payments_list(db_conn)
        assert not unredeemed_payment_list
        assert redeemed_payment.status == backend.RedeemPaymentStatus.Success

        # Claiming it again is idempotent: it returns ok + a freshly-signed proof for the user's current
        # entitlement (identical to the first claim), rather than an AlreadyRedeemed error.
        redeemed_payment_2nd = backend.verify_and_add_pro_payment(
            conn=db_conn,
            signing_key=backend_key,
            request_at=now,
            redeemed_at=redeemed_at,
            master_pkey=master_key.verify_key,
            rotating_pkey=rotating_key.verify_key,
            payment_tx=add_pro_payment_tx,
            master_sig=master_key.sign(add_payment_hash).signature,
            rotating_sig=rotating_key.sign(add_payment_hash).signature,
        )

        assert redeemed_payment_2nd.status == backend.RedeemPaymentStatus.Success
        assert len(redeemed_payment_2nd.proof.revocation_tag) == backend.BLAKE2B_DIGEST_SIZE

    # Two payments stacked for one user → ONE generation, REUSED (item 3: a generation is an epoch, not a
    # per-payment value — a redeem reuses the current generation rather than rolling, since neither payment
    # was revoked). So the revocation_tag is stable across the stack.
    gen_ids: list[int] = [
        row[0]
        for row in db.query(
            db_conn,
            "SELECT g.id FROM generations g JOIN users u ON u.id = g.user_id WHERE u.master_pkey = %s ORDER BY g.id",
            bytes(master_key.verify_key),
        )
    ]
    assert len(gen_ids) == 1

    # Item 5 (privacy — subscription-cadence leak): the revocation_tag a group member observes on the
    # user's proofs is STABLE across the stack. Both redeems produced proofs carrying the SAME tag (the
    # reused generation's token), so bump frequency can't leak the renewal cadence — the tag changes only
    # on a binding revocation (test_revocation_cutting_refund_rolls_generation).
    assert scenarios[0].proof.revocation_tag == scenarios[1].proof.revocation_tag

    user_list: list[backend.UserRow] = backend.get_users_list(db_conn)
    assert len(user_list) == 1
    assert user_list[0].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(user_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert user_list[0].current_generation_id == gen_ids[0]
    assert len(user_list[0].token) == backend.BLAKE2B_DIGEST_SIZE
    assert user_list[0].token == scenarios[1].proof.revocation_tag
    assert user_list[0].expires_at == scenarios[1].expires_at

    payment_list: list[backend.PaymentRow] = backend.get_payments_list(db_conn)
    assert len(payment_list) == 2
    assert payment_list[0].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(payment_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert payment_list[0].plan == scenarios[0].plan
    assert payment_list[0].payment_provider == scenarios[0].payment_provider
    assert payment_list[0].auto_renewing
    assert payment_list[0].redeemed_at == redeemed_at
    assert payment_list[0].expires_at == scenarios[0].expires_at
    assert payment_list[0].revoked_at is None
    assert payment_list[0].google_payment_token == scenarios[0].google_payment_token
    assert payment_list[0].google_order_id == scenarios[0].google_order_id
    assert not payment_list[0].apple.tx_id
    assert not payment_list[0].apple.original_tx_id
    assert not payment_list[0].apple.web_line_order_tx_id

    assert payment_list[1].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(payment_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert payment_list[1].plan == scenarios[1].plan
    assert payment_list[1].payment_provider == scenarios[1].payment_provider
    assert payment_list[1].auto_renewing
    assert payment_list[1].redeemed_at == redeemed_at
    assert payment_list[1].expires_at == scenarios[1].expires_at
    assert payment_list[1].revoked_at is None
    assert payment_list[1].google_payment_token == scenarios[1].google_payment_token
    assert payment_list[1].google_order_id == scenarios[1].google_order_id
    assert not payment_list[0].apple.tx_id
    assert not payment_list[0].apple.original_tx_id
    assert not payment_list[0].apple.web_line_order_tx_id

    revocation_list: list[backend.RevocationRow] = backend.get_revocations_list(db_conn)
    assert not revocation_list

    expire_result: backend.ExpireResult = backend.expire_payments_revocations_and_users(
        db_conn, now=scenarios[0].expires_at
    )
    assert expire_result.success
    assert expire_result.revocations == 0
    assert expire_result.users == 0

    # NOTE: Update the latest payments grace period but set auto-renewing off
    payment_tx = base.PaymentProviderTransaction()
    payment_tx.provider = scenarios[1].payment_provider
    payment_tx.google_payment_token = scenarios[1].google_payment_token
    payment_tx.google_order_id = scenarios[1].google_order_id
    new_grace_period = datetime.timedelta(milliseconds=10000)
    updated: bool = backend.update_payment_renewal_info(
        db_conn, payment_tx=payment_tx, grace_period=new_grace_period, auto_renewing=False, err=err
    )
    assert not err.has() and updated

    # NOTE: Verify that the new grace was assigned to the user
    payment_list = backend.get_payments_list(db_conn)
    assert len(payment_list) == 2
    assert payment_list[0].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(payment_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert payment_list[0].plan == scenarios[0].plan
    assert payment_list[0].payment_provider == scenarios[0].payment_provider
    assert payment_list[0].auto_renewing
    assert payment_list[0].redeemed_at == redeemed_at
    assert payment_list[0].expires_at == scenarios[0].expires_at
    assert payment_list[0].grace_period == scenarios[0].grace_period
    assert payment_list[0].revoked_at is None
    assert payment_list[0].google_payment_token == scenarios[0].google_payment_token
    assert payment_list[0].google_order_id == scenarios[0].google_order_id
    assert not payment_list[0].apple.tx_id
    assert not payment_list[0].apple.original_tx_id
    assert not payment_list[0].apple.web_line_order_tx_id

    assert payment_list[1].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(payment_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert payment_list[1].plan == scenarios[1].plan
    assert payment_list[1].payment_provider == scenarios[1].payment_provider
    assert not payment_list[1].auto_renewing
    assert payment_list[1].redeemed_at == redeemed_at
    assert payment_list[1].expires_at == scenarios[1].expires_at
    assert payment_list[1].grace_period == new_grace_period
    assert payment_list[1].revoked_at is None
    assert payment_list[1].google_payment_token == scenarios[1].google_payment_token
    assert payment_list[1].google_order_id == scenarios[1].google_order_id
    assert not payment_list[0].apple.tx_id
    assert not payment_list[0].apple.original_tx_id
    assert not payment_list[0].apple.web_line_order_tx_id

    # NOTE: Get the user and payments and verify that the expiry and grace are correct
    with db.transaction(db_conn) as tx:
        get: backend.GetUserAndPayments = backend.get_user_and_payments(tx, master_pkey=master_key.verify_key)
        assert not get.user.auto_renewing
        assert get.user.grace_period == new_grace_period

    # NOTE: Verify the DB invariants
    backend.verify_db(db_conn, err)
    if err.msg_list:
        for error in err.msg_list:
            print(f"ERROR: {error}")
        assert not err.msg_list

    # NOTE: Now test that if a user submits 2 payments with the same payment token the 2nd one gets
    # automatically redeemed (because the payment token matches the first payment) so the user
    # doesn't have to manually pair the master public key to that payment.
    auto_redeem_google_payment_token = 'fake_auto_redeem_token'
    auto_redeem_user_master_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    auto_redeem_user_rotating_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    auto_redeem_scenarios: list[Scenario] = [
        Scenario(
            google_payment_token=auto_redeem_google_payment_token,
            google_order_id='DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            plan=base.ProPlan.OneMonth,
            expires_at=redeemed_at + datetime.timedelta(days=30),
            grace_period=datetime.timedelta(0),
            payment_provider=base.PaymentProvider.GooglePlayStore,
        ),
        Scenario(
            google_payment_token=auto_redeem_google_payment_token,
            google_order_id='DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            plan=base.ProPlan.TwelveMonth,
            expires_at=redeemed_at + datetime.timedelta(days=31),
            grace_period=datetime.timedelta(0),
            payment_provider=base.PaymentProvider.GooglePlayStore,
        ),
    ]

    for index, it in enumerate(auto_redeem_scenarios):
        # Add the "unredeemed" version of the payment, e.g. mock the notification from
        # IOS App Store/Google Play Store
        assert it.payment_provider == base.PaymentProvider.GooglePlayStore, "Currently only google is mocked"
        payment_tx = base.PaymentProviderTransaction()
        payment_tx.provider = it.payment_provider
        payment_tx.google_payment_token = it.google_payment_token
        payment_tx.google_order_id = it.google_order_id
        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=payment_tx,
            plan=it.plan,
            purchased_at=now,
            expires_at=it.expires_at,
            platform_refund_expires_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(auto_redeem_user_master_key.verify_key),
            err=err,
        )
        assert not err.msg_list

        # NOTE: Only for the first payment we will claim it. The 2nd one should automatically be
        # redeemed
        assert len(auto_redeem_scenarios) == 2
        if index == 0:
            unredeemed_payment_list = backend.get_unredeemed_payments_list(db_conn)
            assert len(unredeemed_payment_list) == 1

            # Register the payment
            add_pro_payment_tx = backend.UserPaymentTransaction()
            add_pro_payment_tx.provider = payment_tx.provider
            add_pro_payment_tx.google_payment_token = payment_tx.google_payment_token
            add_pro_payment_tx.google_order_id = payment_tx.google_order_id
            add_payment_hash = backend.make_add_pro_payment_message(
                master_pkey=auto_redeem_user_master_key.verify_key,
                rotating_pkey=auto_redeem_user_rotating_key.verify_key,
                payment_tx=add_pro_payment_tx,
            )

            redeemed_payment = backend.verify_and_add_pro_payment(
                conn=db_conn,
                signing_key=backend_key,
                request_at=now,
                redeemed_at=redeemed_at,
                master_pkey=auto_redeem_user_master_key.verify_key,
                rotating_pkey=auto_redeem_user_rotating_key.verify_key,
                payment_tx=add_pro_payment_tx,
                master_sig=auto_redeem_user_master_key.sign(add_payment_hash).signature,
                rotating_sig=auto_redeem_user_rotating_key.sign(add_payment_hash).signature,
            )

            assert redeemed_payment.status == backend.RedeemPaymentStatus.Success, redeemed_payment

            # Verify payment was redeemed
            unredeemed_payment_list = backend.get_unredeemed_payments_list(db_conn)
            assert not unredeemed_payment_list

            payment_list = backend.get_payments_list(db_conn)
            assert len(payment_list) == 3

            # Item 5 (privacy): capture the tag the manual redeem established. The proof carries it, and
            # the server-side auto-redeem below must leave it unchanged.
            with db.transaction(db_conn) as tx:
                auto_redeem_tag_after_manual = backend.get_user_and_payments(
                    tx, auto_redeem_user_master_key.verify_key
                ).user.token
            assert redeemed_payment.proof.revocation_tag == auto_redeem_tag_after_manual

        # NOTE: This is the payment that was not claimed via add_pro_payment. If we check the
        # payments table there should be 4 payments (2 from the first test, 2 from this test). The 2
        # from this test should be set to redeemed.
        if index == 1:
            unredeemed_payment_list = backend.get_unredeemed_payments_list(db_conn)
            assert not unredeemed_payment_list

            payments_list: list[backend.PaymentRow] = backend.get_payments_list(db_conn)
            assert len(payments_list) == 4
            assert derived_status(payments_list[2]) == base.PaymentStatus.Redeemed
            assert payments_list[2].google_order_id == auto_redeem_scenarios[0].google_order_id
            assert payments_list[2].google_payment_token == auto_redeem_google_payment_token
            assert payments_list[2].master_pkey == bytes(auto_redeem_user_master_key.verify_key)
            assert payments_list[2].purchased_at == now
            assert payments_list[2].auto_renewing
            assert payments_list[2].grace_period == auto_redeem_scenarios[0].grace_period

            assert derived_status(payments_list[3]) == base.PaymentStatus.Redeemed
            assert payments_list[3].google_order_id == auto_redeem_scenarios[1].google_order_id
            assert payments_list[3].google_payment_token == auto_redeem_google_payment_token
            assert payments_list[3].master_pkey == bytes(auto_redeem_user_master_key.verify_key)
            assert payments_list[3].redeemed_at == backend.to_redeemed_at(payments_list[3].purchased_at)
            assert payments_list[3].auto_renewing
            assert payments_list[3].grace_period == auto_redeem_scenarios[1].grace_period

            # Item 5 (privacy — cadence leak): the SERVER-SIDE auto-redeem (the exact renewal path that
            # used to roll the generation on every cycle) must NOT change the observable revocation_tag.
            with db.transaction(db_conn) as tx:
                auto_redeem_tag_after_auto = backend.get_user_and_payments(
                    tx, auto_redeem_user_master_key.verify_key
                ).user.token
            assert auto_redeem_tag_after_auto == auto_redeem_tag_after_manual


def test_revocation_cutting_refund_rolls_generation(monkeypatch, pg_database):
    """Item 4 case 2: a refund that drops the user's remaining entitlement BELOW what an outstanding
    proof can still certify (a proof's reach is clamped to ~30 days) must revoke the current generation
    and roll the user onto a fresh one for the reduced-but-still-standing entitlement. This is the middle
    case between the two already covered in test_server_add_payment_flow: a non-cutting refund that leaves
    far-future entitlement (skip — no roll, no revocation entry) and a refund that leaves nothing (revoke
    without a roll — the terminally-revoked generation stays put)."""
    monkeypatch.setattr("providers.google_play.api.subscription_v1_acknowledge", lambda *a, **k: None)
    monkeypatch.setattr(
        "providers.google_play.api.fetch_subscription_v2_details",
        lambda *a, **k: google_play.types.SubscriptionV2Data(),
    )

    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = datetime.datetime.now(datetime.timezone.utc)
    redeemed_at = base.round_datetime_to_next_day(now)

    db_conn = db_engine.getconn()

    def seed_and_redeem(expires_at: datetime.datetime) -> str:
        seed_tx = base.PaymentProviderTransaction()
        seed_tx.provider = base.PaymentProvider.GooglePlayStore
        seed_tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        seed_tx.google_order_id = 'DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=seed_tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=now,
            expires_at=expires_at,
            platform_refund_expires_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_key.verify_key),
            err=err,
        )
        user_tx = backend.UserPaymentTransaction()
        user_tx.provider = base.PaymentProvider.GooglePlayStore
        user_tx.google_payment_token = seed_tx.google_payment_token
        user_tx.google_order_id = seed_tx.google_order_id
        msg = backend.make_add_pro_payment_message(
            master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, payment_tx=user_tx
        )
        redeemed = backend.verify_and_add_pro_payment(
            conn=db_conn,
            signing_key=backend_key,
            request_at=now,
            redeemed_at=redeemed_at,
            master_pkey=master_key.verify_key,
            rotating_pkey=rotating_key.verify_key,
            payment_tx=user_tx,
            master_sig=master_key.sign(msg).signature,
            rotating_sig=rotating_key.sign(msg).signature,
        )
        assert redeemed.status == backend.RedeemPaymentStatus.Success, f'{err.msg_list}'
        return seed_tx.google_payment_token

    try:
        # Two stacked payments on one (shared, item-3) generation: a long one we will refund and a short
        # survivor that leaves only ~5 days of entitlement — less than the ~30-day reach of a live proof.
        long_token = seed_and_redeem(redeemed_at + datetime.timedelta(days=90))
        seed_and_redeem(redeemed_at + datetime.timedelta(days=5))

        with db.transaction(db_conn) as tx:
            user_before = backend.get_user_and_payments(tx, master_key.verify_key).user
        gen_before, token_before = user_before.current_generation_id, user_before.token

        # Refund the long payment. The survivor leaves entitlement well inside the proof-reach window, so
        # an outstanding proof would now over-certify: the generation must roll.
        with db.transaction(db_conn) as tx:
            revoked = backend.add_google_revocation(tx, google_payment_token=long_token, revoke_at=now, err=err)
            assert revoked
            assert not err.has()

        with db.transaction(db_conn) as tx:
            user_after = backend.get_user_and_payments(tx, master_key.verify_key)
            assert user_after.user.current_generation_id != gen_before
            assert user_after.user.token != token_before
            assert not backend.is_generation_revoked(tx.conn, user_after.user.current_generation_id, now)
            assert backend.is_generation_revoked(tx.conn, gen_before, now)
        assert len(backend.get_revocations_list(db_conn)) == 1
    finally:
        db_engine.putconn(db_conn)
        db_engine.close()


def test_apple_refund_reversal_reinstates_and_rolls_generation(pg_database):
    """REFUND_REVERSED: Apple undoes a refund it previously granted, so we must reinstate what the original
    REFUND revoked. A full refund revokes the only payment -> no entitlement -> the user's generation is
    revoked (and stays current, nothing to roll onto). A reversal that lands while the paid window is still
    live must un-revoke the payment, restore the ORIGINAL expiry (never extend), and roll the user onto a
    FRESH, non-revoked generation (the old broadcast one stays revoked). Redelivery is an idempotent no-op."""
    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = datetime.datetime.now(datetime.timezone.utc)
    redeemed_at = base.round_datetime_to_next_day(now)
    original_tx = os.urandom(8).hex()
    tx_id = os.urandom(8).hex()
    expires_at = redeemed_at + datetime.timedelta(days=90)

    db_conn = db_engine.getconn()
    try:
        # Seed + redeem a single long (90d) Apple payment.
        seed_tx = base.PaymentProviderTransaction()
        seed_tx.provider = base.PaymentProvider.iOSAppStore
        seed_tx.apple_original_tx_id = original_tx
        seed_tx.apple_tx_id = tx_id
        seed_tx.apple_web_line_order_tx_id = os.urandom(8).hex()
        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=seed_tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=now,
            expires_at=expires_at,
            platform_refund_expires_at=base.EPOCH,
            platform_obfuscated_account_id=app_store.uuid_from_master_pk(bytes(master_key.verify_key)),
            err=err,
        )
        assert not err.has(), err.msg_list

        user_tx = backend.UserPaymentTransaction()
        user_tx.provider = base.PaymentProvider.iOSAppStore
        user_tx.apple_tx_id = tx_id
        msg = backend.make_add_pro_payment_message(
            master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, payment_tx=user_tx
        )
        redeemed = backend.verify_and_add_pro_payment(
            conn=db_conn,
            signing_key=backend_key,
            request_at=now,
            redeemed_at=redeemed_at,
            master_pkey=master_key.verify_key,
            rotating_pkey=rotating_key.verify_key,
            payment_tx=user_tx,
            master_sig=master_key.sign(msg).signature,
            rotating_sig=rotating_key.sign(msg).signature,
        )
        assert redeemed.status == backend.RedeemPaymentStatus.Success, f'{err.msg_list}'

        with db.transaction(db_conn) as tx:
            user_before = backend.get_user_and_payments(tx, master_key.verify_key).user
        gen_before, token_before, expiry_before = (
            user_before.current_generation_id,
            user_before.token,
            user_before.expires_at,
        )

        # Full refund: revokes the only payment -> generation revoked, stays current (nothing to roll onto).
        with db.transaction(db_conn) as tx:
            assert backend.add_apple_revocation(tx, apple_original_tx_id=original_tx, revoke_at=now, err=err)
            assert not err.has(), err.msg_list
        with db.transaction(db_conn) as tx:
            user_refunded = backend.get_user_and_payments(tx, master_key.verify_key).user
            assert backend.is_generation_revoked(tx.conn, user_refunded.current_generation_id, now)
        assert len(backend.get_revocations_list(db_conn)) == 1

        # Reversal WHILE the 90d window is still live -> reinstate: un-revoke, restore expiry, roll onto a
        # fresh non-revoked generation; the old (revoked) one stays broadcast, no new revocation entry.
        with db.transaction(db_conn) as tx:
            assert backend.reinstate_apple_payment(
                tx, apple_original_tx_id=original_tx, apple_tx_id=tx_id, auto_renewing=True, reinstated_at=now
            )
        with db.transaction(db_conn) as tx:
            reinstated = backend.get_user_and_payments(tx, master_key.verify_key).user
            assert reinstated.expires_at == expiry_before  # original window restored, not extended
            assert reinstated.current_generation_id != gen_before  # rolled onto a fresh generation
            assert reinstated.token != token_before
            assert not backend.is_generation_revoked(tx.conn, reinstated.current_generation_id, now)
            assert backend.is_generation_revoked(tx.conn, gen_before, now)  # old generation stays revoked
        assert len(backend.get_revocations_list(db_conn)) == 1  # no new revocation entry

        # Idempotent: a redelivered reversal is a clean no-op (payment already active, no further roll).
        gen_after = reinstated.current_generation_id
        with db.transaction(db_conn) as tx:
            assert backend.reinstate_apple_payment(
                tx, apple_original_tx_id=original_tx, apple_tx_id=tx_id, auto_renewing=True, reinstated_at=now
            )
        with db.transaction(db_conn) as tx:
            again = backend.get_user_and_payments(tx, master_key.verify_key).user
            assert again.current_generation_id == gen_after
            assert again.expires_at == expiry_before
    finally:
        db_engine.putconn(db_conn)
        db_engine.close()


def test_payment_binding_rejects_mismatched_master_key(monkeypatch, pg_database):
    '''The store-attested account tag binds a redeem to exactly one master key: a purchase tagged for
    key A cannot be claimed by a different key B, even though B's own request signature is valid.
    Covers both providers -- Google's raw-pubkey tag and Apple's derived-UUID tag -- i.e. the property
    that closes the Apple tx_id authorization hole (the old `''` stub let any key claim any tx_id).'''
    # Google's redeem path fetches+acks against Google; stub both so the owner-success path stays local.
    monkeypatch.setattr("providers.google_play.api.subscription_v1_acknowledge", lambda *a, **k: None)
    monkeypatch.setattr(
        "providers.google_play.api.fetch_subscription_v2_details",
        lambda *a, **k: google_play.types.SubscriptionV2Data(),
    )

    db_engine = backend.bootstrap_db(database_url=pg_database())
    assert db_engine
    backend_key = nacl.signing.SigningKey.generate()
    owner = nacl.signing.SigningKey.generate()
    owner_rot = nacl.signing.SigningKey.generate()
    attacker = nacl.signing.SigningKey.generate()
    attacker_rot = nacl.signing.SigningKey.generate()
    now = datetime.datetime.now(datetime.timezone.utc)
    redeemed_at = base.round_datetime_to_next_day(now)

    db_conn = db_engine.getconn()
    try:

        def redeem(redeem_tx, signer, rot):
            msg = backend.make_add_pro_payment_message(
                master_pkey=signer.verify_key, rotating_pkey=rot.verify_key, payment_tx=redeem_tx
            )
            return backend.verify_and_add_pro_payment(
                conn=db_conn,
                signing_key=backend_key,
                request_at=now,
                redeemed_at=redeemed_at,
                master_pkey=signer.verify_key,
                rotating_pkey=rot.verify_key,
                payment_tx=redeem_tx,
                master_sig=signer.sign(msg).signature,
                rotating_sig=rot.sign(msg).signature,
            )

        def check_binding(seed_tx, redeem_tx, owner_tag):
            err = base.ErrorSink()
            backend.add_unredeemed_payment(
                db_conn,
                payment_tx=seed_tx,
                plan=base.ProPlan.OneMonth,
                purchased_at=now,
                expires_at=redeemed_at + datetime.timedelta(days=30),
                platform_refund_expires_at=base.EPOCH,
                platform_obfuscated_account_id=owner_tag,
                err=err,
            )
            assert not err.has(), err.msg_list

            # A different key -- validly signed -- must be rejected: its derived tag != the stored tag.
            with pytest.raises(base.FailError) as exc:
                redeem(redeem_tx, attacker, attacker_rot)
            assert exc.value.code == base.ErrorCode.unknown_payment
            db_conn.rollback()

            # The tagged owner can claim the very same payment.
            assert redeem(redeem_tx, owner, owner_rot).status == backend.RedeemPaymentStatus.Success

        # Google: the tag is the raw 32-byte master pubkey.
        g_seed = base.PaymentProviderTransaction()
        g_seed.provider = base.PaymentProvider.GooglePlayStore
        g_seed.google_payment_token = os.urandom(8).hex()
        g_seed.google_order_id = os.urandom(8).hex()
        g_redeem = backend.UserPaymentTransaction()
        g_redeem.provider = base.PaymentProvider.GooglePlayStore
        g_redeem.google_payment_token = g_seed.google_payment_token
        g_redeem.google_order_id = g_seed.google_order_id
        check_binding(g_seed, g_redeem, bytes(owner.verify_key))

        # Apple: the tag is the derived v4 UUID of the pubkey.
        a_seed = base.PaymentProviderTransaction()
        a_seed.provider = base.PaymentProvider.iOSAppStore
        a_seed.apple_original_tx_id = os.urandom(8).hex()
        a_seed.apple_tx_id = os.urandom(8).hex()
        a_seed.apple_web_line_order_tx_id = os.urandom(8).hex()
        a_redeem = backend.UserPaymentTransaction()
        a_redeem.provider = base.PaymentProvider.iOSAppStore
        a_redeem.apple_tx_id = a_seed.apple_tx_id
        check_binding(a_seed, a_redeem, app_store.uuid_from_master_pk(bytes(owner.verify_key)))
    finally:
        db_engine.putconn(db_conn)
        db_engine.close()


def test_bump_revocation_ticket(pg_database):
    """Item 7: the manual DR bump (backing the `revoke bump-ticket` CLI command) advances the monotonic
    revocation ticket by the given amount and returns the new value. Used to recover after a DB restore
    from an older backup rolls the counter backward (see docs/deploy.md)."""
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    conn = db_engine.getconn()
    try:
        assert backend.get_revocation_ticket(conn) == 0
        assert backend.bump_revocation_ticket(conn, 1000) == 1000  # returns the new value
        assert backend.get_revocation_ticket(conn) == 1000  # and it persisted
        assert backend.bump_revocation_ticket(conn, 5) == 1005  # cumulative, not absolute
        assert backend.get_revocation_ticket(conn) == 1005
    finally:
        db_engine.putconn(conn)
        db_engine.close()


def test_server_add_payment_flow(monkeypatch, pg_database):
    monkeypatch.setattr("providers.google_play.api.subscription_v1_acknowledge", lambda *args, **kwargs: None)

    dummy_sub_v2_data = google_play.types.SubscriptionV2Data()
    monkeypatch.setattr(
        "providers.google_play.api.fetch_subscription_v2_details", lambda *args, **kwargs: dummy_sub_v2_data
    )

    db_url = pg_database()
    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=db_url)
    assert db_engine
    # Setup local flask instance. The signing key is external now (not in the DB), so generate
    # one for this test and hand it to the server; use it directly to verify signatures below.
    backend_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    db_conn: psycopg.Connection = db_engine.getconn()
    flask_app: flask.Flask = server.init(testing_mode=True, database_url=db_url, backend_key=backend_key)
    flask_client: werkzeug.Client = flask_app.test_client()

    # Setup keys for onion requests
    server_x25519_skey = backend_key.to_curve25519_private_key()
    our_x25519_skey = nacl.public.PrivateKey.generate()
    shared_key: bytes = onion_req.make_shared_key(
        our_x25519_skey=our_x25519_skey, server_x25519_pkey=server_x25519_skey.public_key
    )

    # Register an unredeemed payment (by writing the the token to the DB directly)
    start_unix_ts_ms = int(time.time() * 1000)
    unix_ts_ms = start_unix_ts_ms  # ms, for the wire bodies
    request_at = base.datetime_from_unix_ms(unix_ts_ms)  # datetime, for hashes + DB seeding
    next_day_at = base.round_datetime_to_next_day(request_at)
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    payment_tx = base.PaymentProviderTransaction()
    payment_tx.provider = base.PaymentProvider.GooglePlayStore
    payment_tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
    payment_tx.google_order_id = 'DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
    backend.add_unredeemed_payment(
        db_conn,
        payment_tx=payment_tx,
        plan=base.ProPlan.OneMonth,
        purchased_at=request_at,
        expires_at=next_day_at + datetime.timedelta(days=90),
        platform_refund_expires_at=base.EPOCH,
        platform_obfuscated_account_id=bytes(master_key.verify_key),
        err=err,
    )
    assert not err.msg_list, f'{err.msg_list}'

    # Grab the pro status before anything has happened
    hash_to_sign = backend.make_get_pro_status_message(
        master_pkey=master_key.verify_key, request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000)
    )
    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'ts': unix_ts_ms // 1000,
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_status',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'
    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields — the cheap status endpoint carries the latest payment, none yet.
    result_latest = result_json.get('latest_payment')
    result_status = base.json_dict_require_str(d=result_json, key='user_status', err=err)
    assert not err.msg_list, '{err.msg_list}'
    assert result_status == server.UserProStatus.Never.value, f'Response was: {json.dumps(response_json, indent=2)}'
    assert result_latest is None, f'Response was: {json.dumps(response_json, indent=2)}'

    # Simulate client request to register a payment
    add_pro_payment_tx = backend.UserPaymentTransaction()
    add_pro_payment_tx.provider = payment_tx.provider
    add_pro_payment_tx.google_payment_token = payment_tx.google_payment_token
    add_pro_payment_tx.google_order_id = payment_tx.google_order_id
    add_pro_payment_tx.payment_id = backend.payment_id_from_user_tx(add_pro_payment_tx)

    payment_hash_to_sign = backend.make_add_pro_payment_message(
        master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, payment_tx=add_pro_payment_tx
    )

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/add_pro_payment',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(rotating_key.verify_key).hex(),
            'master_sig': bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
            'rotating_sig': bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
            'payment_tx': {'provider': add_pro_payment_tx.provider.value, 'payment_id': add_pro_payment_tx.payment_id},
        },
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    assert isinstance(result_json, dict)
    result_revocation_tag_hex = base.json_dict_require_str(d=result_json, key='revocation_tag', err=err)
    result_rotating_pkey_hex = base.json_dict_require_str(d=result_json, key='rotating_pkey', err=err)
    result_expiry_ts = base.json_dict_require_int(d=result_json, key='expiry_ts', err=err)
    result_sig_hex = base.json_dict_require_str(d=result_json, key='sig', err=err)
    assert not err.msg_list, '{err.msg_list}'

    # Parse hex fields to bytes
    result_rotating_pkey = nacl.signing.VerifyKey(
        base.hex_to_bytes(
            hex=result_rotating_pkey_hex,
            label='Rotating public key',
            hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2,
            err=err,
        )
    )
    result_sig = base.hex_to_bytes(
        hex=result_sig_hex, label='Signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2, err=err
    )
    result_revocation_tag = base.hex_to_bytes(
        hex=result_revocation_tag_hex, label='Revocation tag', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2, err=err
    )
    assert not err.msg_list, '{err.msg_list}'

    # Check the rotating key returned matches what we asked the server to sign
    assert result_rotating_pkey == rotating_key.verify_key

    # Check that the server signed our proof w/ their public key
    proof_hash = backend.build_proof_message(
        result_revocation_tag, result_rotating_pkey, base.datetime_from_unix_seconds(result_expiry_ts)
    )
    backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        assert len(get_user.user.token) == backend.BLAKE2B_DIGEST_SIZE

    # Authorise a new rotated key for the pro subscription
    new_rotating_key = nacl.signing.SigningKey.generate()
    unix_ts_ms = int(time.time() * 1000)
    hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=new_rotating_key.verify_key,
        request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000),
    )

    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'rotating_pkey': bytes(new_rotating_key.verify_key).hex(),
        'ts': unix_ts_ms // 1000,
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'rotating_sig': bytes(new_rotating_key.sign(hash_to_sign).signature).hex(),
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/generate_pro_proof',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_revocation_tag_hex = base.json_dict_require_str(d=result_json, key='revocation_tag', err=err)
    result_rotating_pkey_hex = base.json_dict_require_str(d=result_json, key='rotating_pkey', err=err)
    result_expiry_ts = base.json_dict_require_int(d=result_json, key='expiry_ts', err=err)
    result_sig_hex = base.json_dict_require_str(d=result_json, key='sig', err=err)
    assert not err.msg_list, '{err.msg_list}'

    # Parse hex fields to bytes
    result_rotating_pkey = nacl.signing.VerifyKey(
        base.hex_to_bytes(
            hex=result_rotating_pkey_hex,
            label='Rotating public key',
            hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2,
            err=err,
        )
    )
    result_sig = base.hex_to_bytes(
        hex=result_sig_hex, label='Signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2, err=err
    )
    result_revocation_tag = base.hex_to_bytes(
        hex=result_revocation_tag_hex, label='Revocation tag', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2, err=err
    )
    assert not err.msg_list, '{err.msg_list}'

    # Check the rotating key returned matches what we asked the server to sign
    assert result_rotating_pkey == new_rotating_key.verify_key

    # Check that the server signed our proof w/ their public key
    proof_hash = backend.build_proof_message(
        result_revocation_tag, result_rotating_pkey, base.datetime_from_unix_seconds(result_expiry_ts)
    )
    backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    # Check that the expiry time does not exceed 31 days (we clamped to 30 days and if there's
    # overrun of 30 days we round up to 31 days)
    assert result_expiry_ts % base.SECONDS_IN_DAY == 0
    assert result_expiry_ts == base.unix_seconds_from_datetime(
        base.round_datetime_to_start_of_day(request_at + datetime.timedelta(days=31))
    ) or result_expiry_ts == base.unix_seconds_from_datetime(
        base.round_datetime_to_start_of_day(request_at + datetime.timedelta(days=30))
    )

    new_add_pro_payment_tx = backend.UserPaymentTransaction()
    # Register another payment on the same user, backend will choose the latest expiring payment
    new_payment_tx = base.PaymentProviderTransaction()
    new_payment_tx.provider = base.PaymentProvider.GooglePlayStore
    new_payment_tx.google_payment_token = os.urandom(int(len(payment_tx.google_payment_token) / 2)).hex()
    new_payment_tx.google_order_id = 'DEV.' + os.urandom(int(len(payment_tx.google_payment_token) / 2)).hex()
    backend.add_unredeemed_payment(
        db_conn,
        payment_tx=new_payment_tx,
        plan=base.ProPlan.OneMonth,
        purchased_at=request_at,
        expires_at=request_at + datetime.timedelta(days=30),
        platform_refund_expires_at=base.EPOCH,
        platform_obfuscated_account_id=bytes(master_key.verify_key),
        err=err,
    )

    new_add_pro_payment_tx.provider = new_payment_tx.provider
    new_add_pro_payment_tx.google_payment_token = new_payment_tx.google_payment_token
    new_add_pro_payment_tx.google_order_id = new_payment_tx.google_order_id
    new_add_pro_payment_tx.payment_id = backend.payment_id_from_user_tx(new_add_pro_payment_tx)
    payment_hash_to_sign = backend.make_add_pro_payment_message(
        master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, payment_tx=new_add_pro_payment_tx
    )

    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'rotating_pkey': bytes(rotating_key.verify_key).hex(),
        'master_sig': bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
        'rotating_sig': bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
        'payment_tx': {
            'provider': new_add_pro_payment_tx.provider.value,
            'payment_id': new_add_pro_payment_tx.payment_id,
        },
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/add_pro_payment',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_revocation_tag_hex = base.json_dict_require_str(d=result_json, key='revocation_tag', err=err)
    result_rotating_pkey_hex = base.json_dict_require_str(d=result_json, key='rotating_pkey', err=err)
    result_expiry_ts = base.json_dict_require_int(d=result_json, key='expiry_ts', err=err)
    result_sig_hex = base.json_dict_require_str(d=result_json, key='sig', err=err)
    assert not err.msg_list, '{err.msg_list}'

    # Parse hex fields to bytes
    result_rotating_pkey = nacl.signing.VerifyKey(
        base.hex_to_bytes(
            hex=result_rotating_pkey_hex,
            label='Rotating public key',
            hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2,
            err=err,
        )
    )
    result_sig = base.hex_to_bytes(
        hex=result_sig_hex, label='Signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2, err=err
    )
    result_revocation_tag = base.hex_to_bytes(
        hex=result_revocation_tag_hex, label='Revocation tag', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2, err=err
    )
    assert not err.msg_list, '{err.msg_list}'

    # Check the rotating key returned matches what we asked the server to sign
    assert result_rotating_pkey == rotating_key.verify_key

    # Check that the server signed our proof w/ their public key
    proof_hash = backend.build_proof_message(
        result_revocation_tag, result_rotating_pkey, base.datetime_from_unix_seconds(result_expiry_ts)
    )
    backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    curr_revocation_ticket: int = 0

    # Get the revocation list
    request_body = {'ticket': curr_revocation_ticket}
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_revocations',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_items = base.json_dict_require_array(d=result_json, key='items', err=err)
    result_ticket = base.json_dict_require_int(d=result_json, key='ticket', err=err)
    result_retry_in = base.json_dict_require_int(d=result_json, key='retry_in', err=err)
    assert not err.msg_list, '{err.msg_list}'
    assert result_ticket == 0
    assert result_retry_in == base.SECONDS_IN_DAY
    curr_revocation_ticket = result_ticket

    # Check that the server returned an empty revocation list, we no longer revoke the old
    # payment but we _do_ increment the user's generation index
    assert not result_items

    # Flask did some writes using an independent connection so those writes are made visible by
    # refreshing the connection and updating the "snapshot" that the following code sees.
    db_conn = db_engine.getconn()

    # Capture the user's current generation. The manual revoke below targets only the shorter
    # (30-day) payment while the original (~90-day) payment survives, so item 4 must SKIP the
    # revocation entirely: the surviving entitlement still covers everything any outstanding proof
    # can certify (≤ 30 days of reach), so the generation must NOT roll and nothing must land on
    # the (network-costly) revocation list.
    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        assert len(get_user.user.token) == backend.BLAKE2B_DIGEST_SIZE
    kept_generation_token: bytes = get_user.user.token
    kept_generation_id: int = get_user.user.current_generation_id

    # We will now manually revoke the shorter payment and check the revocation list again
    with db.transaction(db_conn) as tx:
        revoked = backend.add_google_revocation(
            tx,
            google_payment_token=new_add_pro_payment_tx.google_payment_token,
            revoke_at=base.datetime_from_unix_ms(unix_ts_ms),
            err=err,
        )
        assert revoked
        assert not err.has()

    # Get the revocation list, again
    request_body = {'ticket': curr_revocation_ticket}
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_revocations',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_items = base.json_dict_require_array(d=result_json, key='items', err=err)
    result_ticket = base.json_dict_require_int(d=result_json, key='ticket', err=err)
    result_retry_in = base.json_dict_require_int(d=result_json, key='retry_in', err=err)
    result_retain_for = base.json_dict_require_int(d=result_json, key='retain_for', err=err)
    assert not err.msg_list, '{err.msg_list}'
    # Item 4: the non-cutting refund produced NO revocation entry, so the ticket is unchanged.
    assert result_ticket == 0
    assert result_retry_in == base.SECONDS_IN_DAY
    assert result_retain_for == base.SECONDS_IN_MONTH
    curr_revocation_ticket = result_ticket
    assert not result_items

    # The generation must be UNCHANGED and still LIVE: no roll happened, and the current
    # generation is NOT on the revocation list (the surviving payment keeps it honest).
    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        now_dt = base.datetime_from_unix_ms(unix_ts_ms)
        assert get_user.user.current_generation_id == kept_generation_id
        assert get_user.user.token == kept_generation_token
        assert not backend.is_generation_revoked(tx.conn, get_user.user.current_generation_id, now_dt)

    assert not err.has()

    # Try grabbing the revocation again with the current ticket (we should get
    # an empty list because we passed in the most up to date ticket)
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_revocations',
        request_body={'ticket': curr_revocation_ticket},
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_items = base.json_dict_require_array(d=result_json, key='items', err=err)
    result_ticket = base.json_dict_require_int(d=result_json, key='ticket', err=err)
    result_retry_in = base.json_dict_require_int(d=result_json, key='retry_in', err=err)
    result_retain_for = base.json_dict_require_int(d=result_json, key='retain_for', err=err)
    assert not err.msg_list, '{err.msg_list}'
    # Item 4: the non-cutting refund above created no revocation entry, so the ticket is still 0.
    assert result_ticket == 0, f'Response was: {json.dumps(response_json, indent=2)}'
    assert result_retry_in == base.SECONDS_IN_DAY
    assert result_retain_for == base.SECONDS_IN_MONTH

    # List should be empty because we passed in the newest revocation
    # ticket. There are no changes to the revocation list so the backend
    # will return an empty list
    assert not result_items, f'Response was: {json.dumps(response_json, indent=2)}'

    # Get the pro status now w/ a bunch of payments
    unix_ts_ms = int(time.time() * 1000)
    hash_to_sign = backend.make_get_pro_status_message(
        master_pkey=master_key.verify_key, request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000)
    )

    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'ts': unix_ts_ms // 1000,
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_status',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields — status endpoint carries user_status + the single latest payment.
    result_latest = result_json.get('latest_payment')
    result_status = base.json_dict_require_str(d=result_json, key='user_status', err=err)
    assert not err.msg_list, '{err.msg_list}'
    assert result_status == server.UserProStatus.Active.value, f'Response was: {json.dumps(response_json, indent=2)}'
    assert result_latest is not None, f'Response was: {json.dumps(response_json, indent=2)}'

    # Retry the request but use a too old timestamp
    unix_ts_ms = int((time.time() + base.DEFAULT_TIMESTAMP_TOLERANCE.total_seconds() * 2) * 1000)
    hash_to_sign = backend.make_get_pro_status_message(
        master_pkey=master_key.verify_key, request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000)
    )
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_status',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
            'ts': unix_ts_ms // 1000,
        },
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'fail', f'Response was: {json.dumps(response_json, indent=2)}'
    assert len(response_json['error']) > 0, f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'result' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Retry the request but create a hash with the rotating key
    unix_ts_ms = int(time.time() * 1000)
    hash_to_sign = backend.make_get_pro_status_message(
        master_pkey=rotating_key.verify_key, request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000)
    )
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_status',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
            'ts': unix_ts_ms // 1000,
        },
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'fail', f'Response was: {json.dumps(response_json, indent=2)}'
    assert len(response_json['error']) > 0, f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'result' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Page the full payment history via the dedicated get-payment-details endpoint (keyset cursor,
    # newest-first). The user has 2 redeemed payments; walk them one page at a time.

    def get_payment_details_page(limit: int, before: str) -> dict:
        unix_ts_ms = int(time.time() * 1000)
        hash_to_sign = backend.make_get_payment_details_message(
            master_pkey=master_key.verify_key,
            request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000),
            limit=limit,
            before=before,
        )
        onion_request = onion_req.make_request_v4(
            our_x25519_pkey=our_x25519_skey.public_key,
            shared_key=shared_key,
            endpoint='/get_payment_details',
            request_body={
                'master_pkey': bytes(master_key.verify_key).hex(),
                'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
                'ts': unix_ts_ms // 1000,
                'limit': limit,
                'before': before,
            },
        )
        response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success
        body = json.loads(onion_response.body)
        assert isinstance(body, dict) and body['status'] == 'ok', f'Response {onion_response.body!r}'
        return body['result']

    # Page 1 (newest): one item, a cursor for more, total is 2, and NO account status here
    # (that lives on get_pro_status now).
    page1 = get_payment_details_page(limit=1, before='')
    assert 'user_status' not in page1, page1
    assert base.json_dict_require_int(d=page1, key='payments_total', err=err) == 2
    page1_items = base.json_dict_require_array(d=page1, key='items', err=err)
    assert len(page1_items) == 1, page1
    cursor1 = page1.get('next_cursor')
    assert isinstance(cursor1, str) and cursor1, page1

    # Page 2 (older): the second, distinct payment.
    page2 = get_payment_details_page(limit=1, before=cursor1)
    page2_items = base.json_dict_require_array(d=page2, key='items', err=err)
    assert not err.msg_list, err.msg_list
    assert len(page2_items) == 1, page2
    assert isinstance(page1_items[0], dict) and isinstance(page2_items[0], dict)
    assert page1_items[0]['payment_id'] != page2_items[0]['payment_id'], (page1_items, page2_items)

    # Page 3: past the end → empty, no further cursor.
    page3 = get_payment_details_page(limit=1, before=(page2.get('next_cursor') or ''))
    assert not base.json_dict_require_array(d=page3, key='items', err=err), page3
    assert page3.get('next_cursor') is None, page3

    # A garbage cursor is rejected (invalid_request) — never silently treated as page 1.
    bad_ts = int(time.time() * 1000)
    bad_hash = backend.make_get_payment_details_message(
        master_pkey=master_key.verify_key,
        request_at=base.datetime_from_unix_seconds(bad_ts // 1000),
        limit=1,
        before='deadbeef',
    )
    bad_onion = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_payment_details',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'master_sig': bytes(master_key.sign(bad_hash).signature).hex(),
            'ts': bad_ts // 1000,
            'limit': 1,
            'before': 'deadbeef',
        },
    )
    bad_response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=bad_onion)
    bad_onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=bad_response.data)
    assert bad_onion_response.success
    bad_body = json.loads(bad_onion_response.body)
    assert isinstance(bad_body, dict) and bad_body['status'] == 'fail', bad_body

    # NOTE: Add a grace period to the payment and check that we can still generate proofs in said
    # grace period
    # NOTE: Verify that there is no grace period set first
    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        assert get_user.user.grace_period == datetime.timedelta(0)

    # NOTE: Grab the latest expiring payment so that we have access to the payment details
    last_payment = backend.PaymentRow()
    for payment_it in backend.get_payments_list(db_conn):
        if payment_it.expires_at > last_payment.expires_at:
            last_payment = payment_it

    # NOTE: Add a grace period
    payment_tx = base.PaymentProviderTransaction()
    payment_tx.provider = last_payment.payment_provider
    payment_tx.apple_original_tx_id = last_payment.apple.original_tx_id
    payment_tx.apple_tx_id = last_payment.apple.tx_id
    payment_tx.apple_web_line_order_tx_id = last_payment.apple.web_line_order_tx_id
    payment_tx.google_payment_token = last_payment.google_payment_token
    payment_tx.google_order_id = last_payment.google_order_id
    backend.update_payment_renewal_info(
        db_conn, payment_tx, grace_period=base.timedelta_from_ms(10 * 1000), auto_renewing=True, err=err
    )
    assert not err.has()

    # NOTE: Verify that the grace period is set and calculate the pro-proof deadline
    pro_proof_deadline_unix_ts_ms = 0
    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        assert get_user.user.grace_period > datetime.timedelta(0)
        pro_proof_deadline_unix_ts_ms = base.unix_ms_from_datetime(get_user.user.expires_at)

    # NOTE: Try to generate a proof on the deadline timestamp (which includes grace), should be permitted
    unix_ts_ms = pro_proof_deadline_unix_ts_ms
    hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_ms(unix_ts_ms),
    )

    proof = backend.generate_pro_proof(
        conn=db_conn,
        signing_key=backend_key,
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_ms(unix_ts_ms),
        master_sig=bytes(master_key.sign(hash_to_sign).signature),
        rotating_sig=bytes(rotating_key.sign(hash_to_sign).signature),
    )

    # NOTE: Check that the proof verifies
    proof_hash = backend.build_proof_message(proof.revocation_tag, proof.rotating_pkey, proof.expires_at)
    backend_key.verify_key.verify(smessage=proof_hash, signature=proof.sig)

    # NOTE: Generating a proof after the deadline must now fail — entitlement expired → FailError.
    unix_ts_ms = pro_proof_deadline_unix_ts_ms + 1
    hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_ms(unix_ts_ms),
    )

    with pytest.raises(base.FailError) as exc_info:
        backend.generate_pro_proof(
            conn=db_conn,
            signing_key=backend_key,
            master_pkey=master_key.verify_key,
            rotating_pkey=rotating_key.verify_key,
            request_at=base.datetime_from_unix_ms(unix_ts_ms),
            master_sig=bytes(master_key.sign(hash_to_sign).signature),
            rotating_sig=bytes(rotating_key.sign(hash_to_sign).signature),
        )
    assert exc_info.value.code == base.ErrorCode.subscription_expired

    # Revoke the original payment from the user (so we have ended up revoking everything)
    with db.transaction(db_conn) as tx:
        gen_before_final_revoke = backend.get_user_and_payments(tx, master_key.verify_key).user.current_generation_id
        revoked = backend.add_google_revocation(
            tx,
            google_payment_token=payment_tx.google_payment_token,
            revoke_at=base.datetime_from_unix_ms(start_unix_ts_ms),
            err=err,
        )
    assert revoked
    assert not err.has()

    # Revoking the LAST valid payment must NOT roll onto a fresh generation — there's no remaining
    # entitlement to roll onto, so the current generation stays put and is now terminally revoked
    # (contrast the partial revoke above, which DID roll). This is the "shouldn't roll" case.
    with db.transaction(db_conn) as tx:
        get_user_after = backend.get_user_and_payments(tx, master_key.verify_key)
        assert get_user_after.user.current_generation_id == gen_before_final_revoke
        assert backend.is_generation_revoked(
            tx.conn, get_user_after.user.current_generation_id, base.datetime_from_unix_ms(start_unix_ts_ms)
        )

    # Try requesting a proof normally which should now fail as everything has been revoked
    hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_seconds(start_unix_ts_ms // 1000),
    )

    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'rotating_pkey': bytes(rotating_key.verify_key).hex(),
        'ts': start_unix_ts_ms // 1000,
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'rotating_sig': bytes(rotating_key.sign(hash_to_sign).signature).hex(),
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/generate_pro_proof',
        request_body=request_body,
    )

    # POST and get response for pro proof
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the pro proof response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from the pro proof response
    assert response_json['status'] == 'fail', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Initiate a "refund" request on the payment

    throwaway_id = os.urandom(16).hex()

    # Create Apple payment, only apple payments can set refund requested
    apple_payment_tx = base.PaymentProviderTransaction()
    apple_payment_tx.provider = base.PaymentProvider.iOSAppStore
    apple_payment_tx.apple_original_tx_id = throwaway_id
    apple_payment_tx.apple_tx_id = throwaway_id
    apple_payment_tx.apple_web_line_order_tx_id = throwaway_id

    apple_tx = backend.UserPaymentTransaction()
    apple_tx.provider = base.PaymentProvider.iOSAppStore
    apple_tx.apple_tx_id = throwaway_id
    apple_tx.payment_id = backend.payment_id_from_user_tx(apple_tx)
    backend.add_unredeemed_payment(
        db_conn,
        payment_tx=apple_payment_tx,
        plan=base.ProPlan.OneMonth,
        purchased_at=base.datetime_from_unix_ms(unix_ts_ms),
        expires_at=base.datetime_from_unix_ms(unix_ts_ms) + datetime.timedelta(days=30),
        platform_refund_expires_at=base.EPOCH,
        platform_obfuscated_account_id='',
        err=err,
    )

    # Register the payment
    payment_hash_to_sign = backend.make_add_pro_payment_message(
        master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, payment_tx=apple_tx
    )

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/add_pro_payment',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(rotating_key.verify_key).hex(),
            'master_sig': bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
            'rotating_sig': bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
            'payment_tx': {'provider': base.PaymentProvider.iOSAppStore.value, 'payment_id': apple_tx.payment_id},
        },
    )
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)

    # Set refunded
    hash_to_sign = backend.make_set_payment_refund_requested_message(
        master_pkey=master_key.verify_key,
        request_at=base.datetime_from_unix_seconds(start_unix_ts_ms // 1000),
        refund_requested_at=base.datetime_from_unix_seconds(start_unix_ts_ms // 1000),
        payment_tx=apple_tx,
    )

    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'ts': start_unix_ts_ms // 1000,
        'refund_requested_ts': start_unix_ts_ms // 1000,
        'payment_tx': {'provider': base.PaymentProvider.iOSAppStore.value, 'payment_id': apple_tx.payment_id},
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/set_payment_refund_requested',
        request_body=request_body,
    )

    # POST and get response for refund request
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON refund request
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse fields in the JSON
    assert (
        'error' not in response_json
    ), f'Request was: {json.dumps(request_body, indent=2)}\nResponse was: {json.dumps(response_json, indent=2)}'
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert response_json['result']['updated'], f'Response was: {json.dumps(response_json, indent=2)}'

    # Initiate a "refund" on a non-existing payment

    fake_payment = backend.UserPaymentTransaction()
    fake_payment.provider = base.PaymentProvider.GooglePlayStore
    fake_payment.google_payment_token = 'non-existent-payment-token-to-trigger-fail-response'
    fake_payment.google_order_id = 'non-existent-order-id-to-trigger-fail-response'
    fake_payment.payment_id = backend.payment_id_from_user_tx(fake_payment)

    hash_to_sign = backend.make_set_payment_refund_requested_message(
        master_pkey=master_key.verify_key,
        request_at=base.datetime_from_unix_seconds(start_unix_ts_ms // 1000),
        refund_requested_at=base.datetime_from_unix_seconds(start_unix_ts_ms // 1000),
        payment_tx=fake_payment,
    )

    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'payment_tx': {'provider': fake_payment.provider.value, 'payment_id': fake_payment.payment_id},
        'ts': start_unix_ts_ms // 1000,
        'refund_requested_ts': start_unix_ts_ms // 1000,
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/set_payment_refund_requested',
        request_body=request_body,
    )

    # POST and get response for refund request
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON refund request
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse fields in the JSON, we expect it to fail
    assert 'error' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'


def test_onion_request_response_lifecycle():
    # Also call into and test the vendored onion request (as we are currently
    # maintaining a bleeding edge version of it).
    onion_req.test_onion_request_response_lifecycle()


def test_google_duration_parser():
    err = base.ErrorSink()

    MINUTE_S = 60
    HOUR_S = 60 * MINUTE_S
    DAY_S = 24 * HOUR_S

    test_cases = [
        ("P1D", DAY_S),
        ("P7D", 7 * DAY_S),
        ("P14D", 14 * DAY_S),
        ("P30D", 30 * DAY_S),
        ("P1M", 30 * DAY_S),
        ("P3M", 90 * DAY_S),
        ("P12M", 12 * 30 * DAY_S),
        ("P1Y", 365 * DAY_S),
        ("P1DT1H", 25 * HOUR_S),
        ("P1DT1H12M", 25 * HOUR_S + (12 * MINUTE_S)),
        ("PT1S", 1),
        ("PT59S", 59),
        ("PT50M1S", 50 * MINUTE_S + 1),
    ]

    for string, seconds in test_cases:
        dur = GoogleDuration(string, err)
        assert dur.seconds == seconds, f' {seconds} != {dur.seconds} ({dur.iso8601})'
        assert dur.seconds * 1000 == dur.milliseconds
        assert not err.has()


def print_python_decl_code_for_apple_obj(obj: object, indent_level: int = 0, var_name: str = None):
    class_name = obj.__class__.__name__

    # Initialize result string
    if var_name is None:
        var_name = class_name.lower()
    indent = " " * (indent_level * 4)
    result = f"{indent}{var_name} = Apple{class_name}()\n"

    # Get non-callable, non-private attributes
    attrs = {
        attr: getattr(obj, attr) for attr in dir(obj) if not attr.startswith('_') and not callable(getattr(obj, attr))
    }

    # Process each attribute
    for attr, value in attrs.items():
        if value is None:
            formatted_value = "None"
        elif isinstance(value, enum.Enum):
            formatted_value = f"Apple{value}"
        elif isinstance(value, str):
            formatted_value = f"'{value}'"
        elif isinstance(value, (int, float)):
            formatted_value = str(value)
        elif isinstance(value, bool):
            formatted_value = str(value).title()
        elif isinstance(value, (list, tuple, dict)):
            formatted_value = pprint.pformat(value)
        elif hasattr(value, '__dict__') or (
            hasattr(value, '__class__') and not isinstance(value, (int, str, float, bool, list, tuple, dict))
        ):
            # Handle nested objects
            nested_var_name = f"{var_name}_{attr}"
            formatted_value = nested_var_name
            result += print_python_decl_code_for_apple_obj(value, indent_level, nested_var_name)
        else:
            # For enum-like objects or other complex types, try to preserve their full qualification
            formatted_value = str(value)
            if hasattr(value, '__module__') and value.__module__ != 'builtins':
                formatted_value = f"{value.__module__}.{formatted_value}"
        result += f"{indent}{var_name}.{attr:<35} = {formatted_value}\n"
    return result


def dump_apple_signed_payloads(core: app_store.Core, body: AppleResponseBodyV2DecodedPayload, prefix: str = ''):
    print("# NOTE: Generated by dump_apple_signed_payloads")
    print("# NOTE: Signed Payload")
    print(print_python_decl_code_for_apple_obj(body, 0, prefix + "body"))

    err = base.ErrorSink()
    decoded_notification = app_store.decoded_notification_from_apple_response_body_v2(
        body, core.signed_data_verifier, err
    )
    assert not err.has(), err.msg_list

    print("# NOTE: Signed Renewal Info")
    print(print_python_decl_code_for_apple_obj(decoded_notification.renewal_info, 0, prefix + 'renewal_info'))

    print("# NOTE: Signed Transaction Info")
    print(print_python_decl_code_for_apple_obj(decoded_notification.tx_info, 0, prefix + 'tx_info') + "\n")

    print(
        f'{prefix}decoded_notification = app_store.DecodedNotification(body={prefix}body, tx_info={prefix}tx_info, renewal_info={prefix}renewal_info)'
    )
    print(
        f'_ = app_store.handle_notification(decoded_notification={prefix}decoded_notification, conn=test.conn, err=err)'
    )


def test_apple_grace_period_stores_duration_not_absolute_date(pg_database):
    """Regression: DID_FAIL_TO_RENEW / GRACE_PERIOD must store the grace *duration*
    (gracePeriodExpiresDate - expiresDate), not the absolute gracePeriodExpiresDate.

    gracePeriodExpiresDate is an absolute ms-epoch timestamp per the App Store Server API; storing it
    straight into the duration field `grace_period` made `expiry + grace_period` land ~50
    years in the future on any grace-period renewal failure. No prior test covered this path (every
    scenario set gracePeriodExpiresDate = None)."""
    err = base.ErrorSink()
    with TestingContext(pg_database) as test:
        original_tx_id = '2000001024993299'
        tx_id = '2000001025686313'
        web_line_id = '2000000113844706'
        expires_ms = 1759388947000
        grace_len_ms = 16 * base.MILLISECONDS_IN_DAY  # a duration, deliberately unlike an epoch

        with test.connection() as conn:
            # Given an ingested (unredeemed) Apple payment with grace defaulting to 0.
            payment_tx = base.PaymentProviderTransaction()
            payment_tx.provider = base.PaymentProvider.iOSAppStore
            payment_tx.apple_original_tx_id = original_tx_id
            payment_tx.apple_tx_id = tx_id
            payment_tx.apple_web_line_order_tx_id = web_line_id
            backend.add_unredeemed_payment(
                conn,
                payment_tx=payment_tx,
                plan=base.ProPlan.OneMonth,
                expires_at=base.datetime_from_unix_ms(expires_ms),
                purchased_at=base.datetime_from_unix_ms(expires_ms - (30 * base.MILLISECONDS_IN_DAY)),
                platform_refund_expires_at=base.datetime_from_unix_ms(expires_ms),
                platform_obfuscated_account_id='',
                err=err,
            )
            assert not err.has(), err.msg_list

            # When a GRACE_PERIOD failed-renewal notification arrives (gracePeriodExpiresDate absolute).
            body = AppleResponseBodyV2DecodedPayload()
            body_data = AppleData()
            body_data.environment = AppleEnvironment.SANDBOX
            body.data = body_data
            body.notificationType = AppleNotificationTypeV2.DID_FAIL_TO_RENEW
            body.subtype = AppleSubtype.GRACE_PERIOD
            body.notificationUUID = 'grace-period-regression-uuid'
            body.signedDate = expires_ms

            renewal_info = AppleJWSRenewalInfoDecodedPayload()
            renewal_info.gracePeriodExpiresDate = expires_ms + grace_len_ms

            tx_info = AppleJWSTransactionDecodedPayload()
            tx_info.originalTransactionId = original_tx_id
            tx_info.transactionId = tx_id
            tx_info.webOrderLineItemId = web_line_id
            tx_info.expiresDate = expires_ms

            decoded = app_store.DecodedNotification(body=body, tx_info=tx_info, renewal_info=renewal_info)
            handled = app_store.handle_notification(
                decoded_notification=decoded, conn=conn, notification_retry_duration=datetime.timedelta(0), err=err
            )
            assert not err.has(), err.msg_list
            assert handled

            # Then the stored value is the grace DURATION (timedelta), not the absolute date,
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 1
            assert payment_list[0].grace_period == base.timedelta_from_ms(grace_len_ms)
            # and `expiry + grace` resolves to exactly gracePeriodExpiresDate (the absolute instant).
            assert payment_list[0].expires_at + payment_list[0].grace_period == base.datetime_from_unix_ms(
                renewal_info.gracePeriodExpiresDate
            )


def test_platform_apple(pg_database):
    err = base.ErrorSink()

    # One Session account is claimed then auto-redeemed across every phase below; the client sets this
    # UUID as each purchase's appAccountToken, so the notifications carry it and the redeem (and the
    # later auto-redeems) bind against it.
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    apple_token = app_store.uuid_from_master_pk(bytes(master_key.verify_key))

    # NOTE: These tests were using the old debug product id, "com.getsession.org.pro_sub" which was
    # for 1 week. The codebase shortly after removed these but the captured data was from prior to
    # that. For the most part, the tests still work if we patch up the productId even though the
    # entitlement durations don't line up now.
    #
    # We can fix this by re-generating the data if needed. However for the most part what we we
    # intended to test, is still being tested despite changing the productId from 1 week to 1 month.

    # NOTE: Did renew notification
    with TestingContext(pg_database) as test:

        # NOTE: Generate by constructing object from dump_apple_signed_payload()
        body = AppleResponseBodyV2DecodedPayload()
        body.data = AppleData(
            environment=AppleEnvironment.SANDBOX,
            rawEnvironment='Sandbox',
            appAppleId=1470168868,
            bundleId='com.loki-project.loki-messenger',
            bundleVersion='637',
            signedTransactionInfo='eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNDk5ODk1NCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzNzU1NDYxIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTMwMjU1MjAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5MzAyNzMyMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTkzMDI1MTg4MzUsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUkVORVdBTCIsInN0b3JlZnJvbnQiOiJBVVMiLCJzdG9yZWZyb250SWQiOiIxNDM0NjAiLCJwcmljZSI6MTk5MCwiY3VycmVuY3kiOiJBVUQiLCJhcHBUcmFuc2FjdGlvbklkIjoiNzA0ODk3NDY5OTAzMzgzOTE5In0.z6RAI8q01swThVeEg9PKQk4sJO5JsTQWAbn8VpWE44OEpEgQV59aq4P4WXhvCaOfvHzXz-nlH6vO5CTh5ZLCyw',
            signedRenewalInfo='eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjoxOTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTkzMDI1MTg4MzUsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTMwMTgzMjAwMCwicmVuZXdhbERhdGUiOjE3NTkzMDI3MzIwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.PTBcFXS-NkVikMo-rhj7bQfDl3iOKKE6oFL4-DbdWKxU1XbkCeBDg9vPReH2ebZnkbsj6gqu61VNeQojpWFEug',
            status=AppleStatus.ACTIVE,
            rawStatus=1,
            consumptionRequestReason=None,
            rawConsumptionRequestReason=None,
        )
        body.externalPurchaseToken = None
        body.notificationType = AppleNotificationTypeV2.DID_RENEW
        body.notificationUUID = '1a7cdc3d-9360-49c3-ae37-0423e4c6e7c7'
        body.rawNotificationType = 'DID_RENEW'
        body.rawSubtype = None
        body.signedDate = 1759302518835
        body.subtype = None
        body.summary = None
        body.version = '2.0'

        renewal_info = AppleJWSRenewalInfoDecodedPayload()
        renewal_info.appAccountToken = None
        renewal_info.appTransactionId = '704897469903383919'
        renewal_info.autoRenewProductId = None
        renewal_info.autoRenewStatus = None
        renewal_info.currency = 'AUD'
        renewal_info.eligibleWinBackOfferIds = None
        renewal_info.environment = AppleEnvironment.SANDBOX
        renewal_info.expirationIntent = None
        renewal_info.gracePeriodExpiresDate = None
        renewal_info.isInBillingRetryPeriod = None
        renewal_info.offerDiscountType = None
        renewal_info.offerIdentifier = None
        renewal_info.offerPeriod = None
        renewal_info.offerType = None
        renewal_info.originalTransactionId = '2000001024993299'
        renewal_info.priceIncreaseStatus = None
        renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        renewal_info.rawAutoRenewStatus = None
        renewal_info.rawEnvironment = 'Sandbox'
        renewal_info.rawExpirationIntent = None
        renewal_info.rawOfferDiscountType = None
        renewal_info.rawOfferType = None
        renewal_info.rawPriceIncreaseStatus = None
        renewal_info.recentSubscriptionStartDate = None
        renewal_info.renewalDate = None
        renewal_info.renewalPrice = None
        renewal_info.signedDate = 1759302518835

        tx_info = AppleJWSTransactionDecodedPayload()
        tx_info.appAccountToken = apple_token
        tx_info.appTransactionId = '704897469903383919'
        tx_info.bundleId = 'com.loki-project.loki-messenger'
        tx_info.currency = 'AUD'
        tx_info.environment = AppleEnvironment.SANDBOX
        tx_info.expiresDate = 1759302732000
        tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        tx_info.isUpgraded = None
        tx_info.offerDiscountType = None
        tx_info.offerIdentifier = None
        tx_info.offerPeriod = None
        tx_info.offerType = None
        tx_info.originalPurchaseDate = 1759301833000
        tx_info.originalTransactionId = '2000001024993299'
        tx_info.price = 1990
        tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        tx_info.purchaseDate = 1759302552000
        tx_info.quantity = 1
        tx_info.rawEnvironment = 'Sandbox'
        tx_info.rawInAppOwnershipType = 'PURCHASED'
        tx_info.rawOfferDiscountType = None
        tx_info.rawOfferType = None
        tx_info.rawRevocationReason = None
        tx_info.rawTransactionReason = 'RENEWAL'
        tx_info.rawType = 'Auto-Renewable Subscription'
        tx_info.revocationDate = None
        tx_info.revocationReason = None
        tx_info.signedDate = 1759302518835
        tx_info.storefront = 'AUS'
        tx_info.storefrontId = '143460'
        tx_info.subscriptionGroupIdentifier = '21752814'
        tx_info.transactionId = '2000001024998954'
        tx_info.transactionReason = AppleTransactionReason.RENEWAL
        tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        tx_info.webOrderLineItemId = '2000000113755461'

        notification = app_store.DecodedNotification(body=body, tx_info=tx_info, renewal_info=renewal_info)
        err = base.ErrorSink()
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=notification, conn=conn, notification_retry_duration=datetime.timedelta(0), err=err
            )
            assert not err.has(), err.msg_list

            # NOTE: Subscription renewal should be unredeemed
            unredeemed_list: list[backend.PaymentRow] = backend.get_unredeemed_payments_list(conn)
            assert len(unredeemed_list) == 1
            assert unredeemed_list[0].master_pkey is None
            assert derived_status(unredeemed_list[0]) == base.PaymentStatus.Unredeemed
            assert unredeemed_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert unredeemed_list[0].apple.original_tx_id == tx_info.originalTransactionId
            assert unredeemed_list[0].apple.tx_id == tx_info.transactionId
            assert unredeemed_list[0].apple.web_line_order_tx_id == tx_info.webOrderLineItemId

        # NOTE: Then claim the payment (master_key/rotating_key generated at the top of the test)
        add_pro_payment_tx = backend.UserPaymentTransaction()
        add_pro_payment_tx.provider = base.PaymentProvider.iOSAppStore
        add_pro_payment_tx.apple_tx_id = unredeemed_list[0].apple.tx_id
        add_pro_payment_tx.payment_id = backend.payment_id_from_user_tx(add_pro_payment_tx)
        payment_hash_to_sign = backend.make_add_pro_payment_message(
            master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, payment_tx=add_pro_payment_tx
        )

        # NOTE: POST and get response
        response = test.flask_client.post(
            '/add_pro_payment',
            json={
                'master_pkey': bytes(master_key.verify_key).hex(),
                'rotating_pkey': bytes(rotating_key.verify_key).hex(),
                'master_sig': bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
                'rotating_sig': bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
                'payment_tx': {
                    'provider': add_pro_payment_tx.provider.value,
                    'payment_id': add_pro_payment_tx.payment_id,
                },
            },
        )

        # NOTE: Parse the JSON from the response
        response_json = json.loads(response.data)
        assert isinstance(response_json, dict), f'Response {response_json}'

        # NOTE: Parse status from response
        assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
        assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

        # NOTE: Parse result object is at root
        assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
        result_json = response_json['result']

        # NOTE: Extract the fields
        assert isinstance(result_json, dict)
        result_revocation_tag_hex = base.json_dict_require_str(d=result_json, key='revocation_tag', err=err)
        result_rotating_pkey_hex = base.json_dict_require_str(d=result_json, key='rotating_pkey', err=err)
        result_expiry_ts = base.json_dict_require_int(d=result_json, key='expiry_ts', err=err)
        result_sig_hex = base.json_dict_require_str(d=result_json, key='sig', err=err)
        assert not err.msg_list, '{err.msg_list}'

        # NOTE: Parse hex fields to bytes
        result_rotating_pkey = nacl.signing.VerifyKey(
            base.hex_to_bytes(
                hex=result_rotating_pkey_hex,
                label='Rotating public key',
                hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2,
                err=err,
            )
        )
        result_sig = base.hex_to_bytes(
            hex=result_sig_hex, label='Signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2, err=err
        )
        result_revocation_tag = base.hex_to_bytes(
            hex=result_revocation_tag_hex, label='Revocation tag', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2, err=err
        )
        assert not err.msg_list, '{err.msg_list}'

        # NOTE: Check the rotating key returned matches what we asked the server to sign
        assert result_rotating_pkey == rotating_key.verify_key

        # NOTE: Check that the server signed our proof w/ their public key
        proof_hash = backend.build_proof_message(
            result_revocation_tag, result_rotating_pkey, base.datetime_from_unix_seconds(result_expiry_ts)
        )
        test.backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    # The following is a sequence of notifications/events that transpired for the same account under
    # the same billing cycle (e.g. a subscribe, cancelling of subscription, then expiring). Since
    # it's under the same billing cycle they all have the same original TX ID as well as the same
    # web line order TX ID.
    #
    # Having the same web line order TX ID and original transaction ID is essential for these tests
    # to work such that state changes (like disabling auto-renewal) updates the correct transaction
    # on our backend.
    #
    # This was done by executing these sequences in the time-frame that a subscription is active for
    # on Apple's sandbox environment.
    with TestingContext(pg_database) as test:
        # Subscribe notification

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        body = AppleResponseBodyV2DecodedPayload()
        body_data = AppleData()
        body_data.appAppleId = 1470168868
        body_data.bundleId = 'com.loki-project.loki-messenger'
        body_data.bundleVersion = '637'
        body_data.consumptionRequestReason = None
        body_data.environment = AppleEnvironment.SANDBOX
        body_data.rawConsumptionRequestReason = None
        body_data.rawEnvironment = 'Sandbox'
        body_data.rawStatus = 1
        body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjoxOTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTkzODg3NzY5NDEsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTM4ODc2NzAwMCwicmVuZXdhbERhdGUiOjE3NTkzODg5NDcwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.DBRrGNE2YqL0amjPVw62gZqfYtTqoSZGWhl0sKEpVfyn41aaVRKHA7CzntLV78RDyE30pzAsHM3ShH-eKXDsuA'
        body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNTY4NjMxMyIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzODQ0NzA2IiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTM4ODc2NzAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5Mzg4OTQ3MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTkzODg3NzY5NDEsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.xKPDulHd1Iq8wQmkx99rc5ZZsNtib5HOhtVns62blRQK_YZbRKj-8YzK6QzE-UmVK3Xu73CC0TCU1VljYsjauw'
        body_data.status = AppleStatus.ACTIVE
        body.data = body_data
        body.externalPurchaseToken = None
        body.notificationType = AppleNotificationTypeV2.SUBSCRIBED
        body.notificationUUID = '9f9730f8-f3df-436a-b7e5-e85ef9c6afe4'
        body.rawNotificationType = 'SUBSCRIBED'
        body.rawSubtype = 'RESUBSCRIBE'
        body.signedDate = 1759388776941
        body.subtype = AppleSubtype.RESUBSCRIBE
        body.summary = None
        body.version = '2.0'

        # NOTE: Signed Renewal Info
        renewal_info = AppleJWSRenewalInfoDecodedPayload()
        renewal_info.appAccountToken = None
        renewal_info.appTransactionId = '704897469903383919'
        renewal_info.autoRenewProductId = None
        renewal_info.autoRenewStatus = None
        renewal_info.currency = 'AUD'
        renewal_info.eligibleWinBackOfferIds = None
        renewal_info.environment = AppleEnvironment.SANDBOX
        renewal_info.expirationIntent = None
        renewal_info.gracePeriodExpiresDate = None
        renewal_info.isInBillingRetryPeriod = None
        renewal_info.offerDiscountType = None
        renewal_info.offerIdentifier = None
        renewal_info.offerPeriod = None
        renewal_info.offerType = None
        renewal_info.originalTransactionId = '2000001024993299'
        renewal_info.priceIncreaseStatus = None
        renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        renewal_info.rawAutoRenewStatus = None
        renewal_info.rawEnvironment = 'Sandbox'
        renewal_info.rawExpirationIntent = None
        renewal_info.rawOfferDiscountType = None
        renewal_info.rawOfferType = None
        renewal_info.rawPriceIncreaseStatus = None
        renewal_info.recentSubscriptionStartDate = None
        renewal_info.renewalDate = None
        renewal_info.renewalPrice = None
        renewal_info.signedDate = 1759388776941

        # NOTE: Signed Transaction Info
        tx_info = AppleJWSTransactionDecodedPayload()
        tx_info.appAccountToken = apple_token
        tx_info.appTransactionId = '704897469903383919'
        tx_info.bundleId = 'com.loki-project.loki-messenger'
        tx_info.currency = 'AUD'
        tx_info.environment = AppleEnvironment.SANDBOX
        tx_info.expiresDate = 1759388947000
        tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        tx_info.isUpgraded = None
        tx_info.offerDiscountType = None
        tx_info.offerIdentifier = None
        tx_info.offerPeriod = None
        tx_info.offerType = None
        tx_info.originalPurchaseDate = 1759301833000
        tx_info.originalTransactionId = '2000001024993299'
        tx_info.price = 1990
        tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        tx_info.purchaseDate = 1759388767000
        tx_info.quantity = 1
        tx_info.rawEnvironment = 'Sandbox'
        tx_info.rawInAppOwnershipType = 'PURCHASED'
        tx_info.rawOfferDiscountType = None
        tx_info.rawOfferType = None
        tx_info.rawRevocationReason = None
        tx_info.rawTransactionReason = 'PURCHASE'
        tx_info.rawType = 'Auto-Renewable Subscription'
        tx_info.revocationDate = None
        tx_info.revocationReason = None
        tx_info.signedDate = 1759388776941
        tx_info.storefront = 'AUS'
        tx_info.storefrontId = '143460'
        tx_info.subscriptionGroupIdentifier = '21752814'
        tx_info.transactionId = '2000001025686313'
        tx_info.transactionReason = AppleTransactionReason.PURCHASE
        tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        tx_info.webOrderLineItemId = '2000000113844706'

        decoded_notification = app_store.DecodedNotification(body=body, tx_info=tx_info, renewal_info=renewal_info)

        err = base.ErrorSink()
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: Subscription purchase is unredeemed
            unredeemed_list = backend.get_unredeemed_payments_list(conn)
            assert len(unredeemed_list) == 1
            assert unredeemed_list[0].master_pkey is None
            assert derived_status(unredeemed_list[0]) == base.PaymentStatus.Unredeemed
            assert unredeemed_list[0].plan == base.ProPlan.OneMonth
            assert unredeemed_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert unredeemed_list[0].auto_renewing
            assert unredeemed_list[0].purchased_at == base.datetime_from_unix_ms(tx_info.purchaseDate)
            assert unredeemed_list[0].redeemed_at is None
            assert unredeemed_list[0].expires_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert unredeemed_list[0].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert unredeemed_list[0].platform_refund_expires_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert unredeemed_list[0].revoked_at is None
        assert unredeemed_list[0].apple.original_tx_id == tx_info.originalTransactionId
        assert unredeemed_list[0].apple.tx_id == tx_info.transactionId
        assert unredeemed_list[0].apple.web_line_order_tx_id == tx_info.webOrderLineItemId

        # Did change renewal status notification

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        body = AppleResponseBodyV2DecodedPayload()
        body_data = AppleData()
        body_data.appAppleId = 1470168868
        body_data.bundleId = 'com.loki-project.loki-messenger'
        body_data.bundleVersion = '637'
        body_data.consumptionRequestReason = None
        body_data.environment = AppleEnvironment.SANDBOX
        body_data.rawConsumptionRequestReason = None
        body_data.rawEnvironment = 'Sandbox'
        body_data.rawStatus = 1
        body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwic2lnbmVkRGF0ZSI6MTc1OTM4ODg1NTQ3MywiZW52aXJvbm1lbnQiOiJTYW5kYm94IiwicmVjZW50U3Vic2NyaXB0aW9uU3RhcnREYXRlIjoxNzU5Mzg4NzY3MDAwLCJyZW5ld2FsRGF0ZSI6MTc1OTM4ODk0NzAwMCwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.PQSXN92IUZjgPP0WG8SiiYt8PJ1pgRr5E3p2JE73gX2Vu3lrOJEHh33k805X7_O-K80qbvIWS9KivV4FJ1BDTA'
        body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNTY4NjMxMyIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzODQ0NzA2IiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTM4ODc2NzAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5Mzg4OTQ3MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTkzODg4NTU0NzMsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.9djRjpncPSUbAapGFYxImOjex47JXKUqQTOWlvuAwoJ8HvMlE4LciVZNMXN5-L7F3CEwmSywU62PfpYa6m6EiA'
        body_data.status = AppleStatus.ACTIVE
        body.data = body_data
        body.externalPurchaseToken = None
        body.notificationType = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_STATUS
        body.notificationUUID = 'ebb7519a-1f8b-4038-8228-5b1250ab998d'
        body.rawNotificationType = 'DID_CHANGE_RENEWAL_STATUS'
        body.rawSubtype = 'AUTO_RENEW_DISABLED'
        body.signedDate = 1759388855473
        body.subtype = AppleSubtype.AUTO_RENEW_DISABLED
        body.summary = None
        body.version = '2.0'

        # NOTE: Signed Renewal Info
        renewal_info = AppleJWSRenewalInfoDecodedPayload()
        renewal_info.appAccountToken = None
        renewal_info.appTransactionId = '704897469903383919'
        renewal_info.autoRenewProductId = None
        renewal_info.autoRenewStatus = None
        renewal_info.currency = 'AUD'
        renewal_info.eligibleWinBackOfferIds = None
        renewal_info.environment = AppleEnvironment.SANDBOX
        renewal_info.expirationIntent = None
        renewal_info.gracePeriodExpiresDate = None
        renewal_info.isInBillingRetryPeriod = None
        renewal_info.offerDiscountType = None
        renewal_info.offerIdentifier = None
        renewal_info.offerPeriod = None
        renewal_info.offerType = None
        renewal_info.originalTransactionId = '2000001024993299'
        renewal_info.priceIncreaseStatus = None
        renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        renewal_info.rawAutoRenewStatus = None
        renewal_info.rawEnvironment = 'Sandbox'
        renewal_info.rawExpirationIntent = None
        renewal_info.rawOfferDiscountType = None
        renewal_info.rawOfferType = None
        renewal_info.rawPriceIncreaseStatus = None
        renewal_info.recentSubscriptionStartDate = None
        renewal_info.renewalDate = None
        renewal_info.renewalPrice = None
        renewal_info.signedDate = 1759388855473

        # NOTE: Signed Transaction Info
        tx_info = AppleJWSTransactionDecodedPayload()
        tx_info.appAccountToken = apple_token
        tx_info.appTransactionId = '704897469903383919'
        tx_info.bundleId = 'com.loki-project.loki-messenger'
        tx_info.currency = 'AUD'
        tx_info.environment = AppleEnvironment.SANDBOX
        tx_info.expiresDate = 1759388947000
        tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        tx_info.isUpgraded = None
        tx_info.offerDiscountType = None
        tx_info.offerIdentifier = None
        tx_info.offerPeriod = None
        tx_info.offerType = None
        tx_info.originalPurchaseDate = 1759301833000
        tx_info.originalTransactionId = '2000001024993299'
        tx_info.price = 1990
        tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        tx_info.purchaseDate = 1759388767000
        tx_info.quantity = 1
        tx_info.rawEnvironment = 'Sandbox'
        tx_info.rawInAppOwnershipType = 'PURCHASED'
        tx_info.rawOfferDiscountType = None
        tx_info.rawOfferType = None
        tx_info.rawRevocationReason = None
        tx_info.rawTransactionReason = 'PURCHASE'
        tx_info.rawType = 'Auto-Renewable Subscription'
        tx_info.revocationDate = None
        tx_info.revocationReason = None
        tx_info.signedDate = 1759388855473
        tx_info.storefront = 'AUS'
        tx_info.storefrontId = '143460'
        tx_info.subscriptionGroupIdentifier = '21752814'
        tx_info.transactionId = '2000001025686313'
        tx_info.transactionReason = AppleTransactionReason.PURCHASE
        tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        tx_info.webOrderLineItemId = '2000000113844706'

        decoded_notification = app_store.DecodedNotification(body=body, tx_info=tx_info, renewal_info=renewal_info)

        err = base.ErrorSink()
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: Check payment is still in the DB and that auto-renewing was turned off
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 1
            assert payment_list[0].master_pkey is None
            assert derived_status(payment_list[0]) == base.PaymentStatus.Unredeemed
            assert payment_list[0].plan == base.ProPlan.OneMonth
            assert payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert not payment_list[0].auto_renewing
            assert payment_list[0].purchased_at == base.datetime_from_unix_ms(tx_info.purchaseDate)
            assert payment_list[0].redeemed_at is None
            assert payment_list[0].expires_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert payment_list[0].platform_refund_expires_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].revoked_at is None
        assert payment_list[0].apple.original_tx_id == tx_info.originalTransactionId
        assert payment_list[0].apple.tx_id == tx_info.transactionId
        assert payment_list[0].apple.web_line_order_tx_id == tx_info.webOrderLineItemId

        # Expire (voluntary) notification

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        body = AppleResponseBodyV2DecodedPayload()
        body_data = AppleData()
        body_data.appAppleId = 1470168868
        body_data.bundleId = 'com.loki-project.loki-messenger'
        body_data.bundleVersion = '637'
        body_data.consumptionRequestReason = None
        body_data.environment = AppleEnvironment.SANDBOX
        body_data.rawConsumptionRequestReason = None
        body_data.rawEnvironment = 'Sandbox'
        body_data.rawStatus = 2
        body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJleHBpcmF0aW9uSW50ZW50IjoxLCJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwiaXNJbkJpbGxpbmdSZXRyeVBlcmlvZCI6ZmFsc2UsInNpZ25lZERhdGUiOjE3NTkzODkwNDE2MDQsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTM4ODc2NzAwMCwicmVuZXdhbERhdGUiOjE3NTkzODg5NDcwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.wTjYhoiB_reDAIaFXJs0MoMXlXqLAk_QsiS3-o08UeVihVhIUfQD_cYvooh9MHfUE7n6qF-NduDA5JXjij6dKw'
        body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNTY4NjMxMyIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzODQ0NzA2IiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTM4ODc2NzAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5Mzg4OTQ3MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTkzODkwNDE2MDQsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.h6EK76-WgYIOnppoD5zJNc0gy2ItMzv20Vb-djXcw34wMFGd0_u66M4TnlkP_FrJ_20enN2rnRFFAhWWZbZIAg'
        body_data.status = AppleStatus.EXPIRED
        body.data = body_data
        body.externalPurchaseToken = None
        body.notificationType = AppleNotificationTypeV2.EXPIRED
        body.notificationUUID = 'c7726298-32eb-48f7-9623-097ff6de4d69'
        body.rawNotificationType = 'EXPIRED'
        body.rawSubtype = 'VOLUNTARY'
        body.signedDate = 1759389041604
        body.subtype = AppleSubtype.VOLUNTARY
        body.summary = None
        body.version = '2.0'

        # NOTE: Signed Renewal Info
        renewal_info = AppleJWSRenewalInfoDecodedPayload()
        renewal_info.appAccountToken = None
        renewal_info.appTransactionId = '704897469903383919'
        renewal_info.autoRenewProductId = None
        renewal_info.autoRenewStatus = None
        renewal_info.currency = 'AUD'
        renewal_info.eligibleWinBackOfferIds = None
        renewal_info.environment = AppleEnvironment.SANDBOX
        renewal_info.expirationIntent = None
        renewal_info.gracePeriodExpiresDate = None
        renewal_info.isInBillingRetryPeriod = None
        renewal_info.offerDiscountType = None
        renewal_info.offerIdentifier = None
        renewal_info.offerPeriod = None
        renewal_info.offerType = None
        renewal_info.originalTransactionId = '2000001024993299'
        renewal_info.priceIncreaseStatus = None
        renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        renewal_info.rawAutoRenewStatus = None
        renewal_info.rawEnvironment = 'Sandbox'
        renewal_info.rawExpirationIntent = None
        renewal_info.rawOfferDiscountType = None
        renewal_info.rawOfferType = None
        renewal_info.rawPriceIncreaseStatus = None
        renewal_info.recentSubscriptionStartDate = None
        renewal_info.renewalDate = None
        renewal_info.renewalPrice = None
        renewal_info.signedDate = 1759389041604

        # NOTE: Signed Transaction Info
        tx_info = AppleJWSTransactionDecodedPayload()
        tx_info.appAccountToken = apple_token
        tx_info.appTransactionId = '704897469903383919'
        tx_info.bundleId = 'com.loki-project.loki-messenger'
        tx_info.currency = 'AUD'
        tx_info.environment = AppleEnvironment.SANDBOX
        tx_info.expiresDate = 1759388947000
        tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        tx_info.isUpgraded = None
        tx_info.offerDiscountType = None
        tx_info.offerIdentifier = None
        tx_info.offerPeriod = None
        tx_info.offerType = None
        tx_info.originalPurchaseDate = 1759301833000
        tx_info.originalTransactionId = '2000001024993299'
        tx_info.price = 1990
        tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        tx_info.purchaseDate = 1759388767000
        tx_info.quantity = 1
        tx_info.rawEnvironment = 'Sandbox'
        tx_info.rawInAppOwnershipType = 'PURCHASED'
        tx_info.rawOfferDiscountType = None
        tx_info.rawOfferType = None
        tx_info.rawRevocationReason = None
        tx_info.rawTransactionReason = 'PURCHASE'
        tx_info.rawType = 'Auto-Renewable Subscription'
        tx_info.revocationDate = None
        tx_info.revocationReason = None
        tx_info.signedDate = 1759389041604
        tx_info.storefront = 'AUS'
        tx_info.storefrontId = '143460'
        tx_info.subscriptionGroupIdentifier = '21752814'
        tx_info.transactionId = '2000001025686313'
        tx_info.transactionReason = AppleTransactionReason.PURCHASE
        tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        tx_info.webOrderLineItemId = '2000000113844706'

        decoded_notification = app_store.DecodedNotification(body=body, tx_info=tx_info, renewal_info=renewal_info)

        err = base.ErrorSink()
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: The payment expires as per Apple's notification. We don't have to do anything
            # necessarily as our proofs will self-expire.

            # NOTE: Check payment is still in the DB
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 1
            assert payment_list[0].master_pkey is None
            assert derived_status(payment_list[0]) == base.PaymentStatus.Unredeemed
            assert payment_list[0].plan == base.ProPlan.OneMonth
            assert payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert payment_list[0].purchased_at == base.datetime_from_unix_ms(tx_info.purchaseDate)
            assert payment_list[0].redeemed_at is None
            assert payment_list[0].expires_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert payment_list[0].platform_refund_expires_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].revoked_at is None
            assert payment_list[0].apple.original_tx_id == tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id == tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id == tx_info.webOrderLineItemId

        # NOTE: Now expire the payment
        with test.connection() as conn:
            backend.expire_payments_revocations_and_users(
                conn=conn, now=payment_list[0].expires_at + datetime.timedelta(milliseconds=1)
            )

            # NOTE: Now check that the payments were marked expired
            payment_list = backend.get_payments_list(conn)

            assert len(payment_list) == 1
            assert payment_list[0].master_pkey is None
            assert derived_status(payment_list[0], payment_list[0].expires_at) == base.PaymentStatus.Expired
            assert payment_list[0].plan == base.ProPlan.OneMonth
            assert payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert payment_list[0].purchased_at == base.datetime_from_unix_ms(tx_info.purchaseDate)
            assert payment_list[0].redeemed_at is None
            assert payment_list[0].expires_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert payment_list[0].platform_refund_expires_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].revoked_at is None
            assert payment_list[0].apple.original_tx_id == tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id == tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id == tx_info.webOrderLineItemId

    # NOTE: Execute the sequence
    #  - 0 [SUBSCRIBED,                sub: RESUBSCRIBE]         Subscribe to 3 months
    #  - 1 [DID_CHANGE_RENEWAL_PREF,   sub: UPGRADE]             "Upgrade" to 1 wk (happens immediately)
    #  - 2 [DID_CHANGE_RENEWAL_STATUS, sub: AUTO_RENEW_DISABLED] Disable auto-renew
    #  - 3 [DID_CHANGE_RENEWAL_PREF,   sub: DOWNGRADE]           Queue downgrade to 3 months at end of 1wk billing cycle
    #  - 4 [DID_CHANGE_RENEWAL_PREF]                             Cancel the downgrade (we are now back at 1wk subscription)
    #  - 5 [DID_CHANGE_RENEWAL_STATUS, sub: AUTO_RENEW_DISABLED] Disable auto-renew
    #  - 6 [EXPIRED,                   sub: VOLUNTARY]           ??
    with TestingContext(pg_database) as test:

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e00_sub_to_3_months_body = AppleResponseBodyV2DecodedPayload()
        e00_sub_to_3_months_body_data = AppleData()
        e00_sub_to_3_months_body_data.appAppleId = 1470168868
        e00_sub_to_3_months_body_data.bundleId = 'com.loki-project.loki-messenger'
        e00_sub_to_3_months_body_data.bundleVersion = '637'
        e00_sub_to_3_months_body_data.consumptionRequestReason = None
        e00_sub_to_3_months_body_data.environment = AppleEnvironment.SANDBOX
        e00_sub_to_3_months_body_data.rawConsumptionRequestReason = None
        e00_sub_to_3_months_body_data.rawEnvironment = 'Sandbox'
        e00_sub_to_3_months_body_data.rawStatus = 1
        e00_sub_to_3_months_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1Yl8zX21vbnRocyIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjo1OTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc3ODU0NDUsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3MjgzMTgwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.s3yvWeyKDVbZSciqRVRpMBGkpNnQ10lEn-6jXL9yPK-Yi-nEkXOLIzl4Ji5VutI-2kY2vZlxj7mVXu-2v3Mi0Q'
        e00_sub_to_3_months_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTg5OCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTEzODY0NjA1IiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc3ODAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI4MzE4MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc3ODU0NDUsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjU5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.bMfO0cWYCajFTg5Mmv2nyU_lBQfyPM9Z5pOw_B6jO9jy1qxc49DffTVf_ZOU5HH-04W7t3qczVi8KkLeWNbi_A'
        e00_sub_to_3_months_body_data.status = AppleStatus.ACTIVE
        e00_sub_to_3_months_body.data = e00_sub_to_3_months_body_data
        e00_sub_to_3_months_body.externalPurchaseToken = None
        e00_sub_to_3_months_body.notificationType = AppleNotificationTypeV2.SUBSCRIBED
        e00_sub_to_3_months_body.notificationUUID = 'fee6ade6-5871-4e0f-9d2e-5d6229a24027'
        e00_sub_to_3_months_body.rawNotificationType = 'SUBSCRIBED'
        e00_sub_to_3_months_body.rawSubtype = 'RESUBSCRIBE'
        e00_sub_to_3_months_body.signedDate = 1759727785445
        e00_sub_to_3_months_body.subtype = AppleSubtype.RESUBSCRIBE
        e00_sub_to_3_months_body.summary = None
        e00_sub_to_3_months_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e00_sub_to_3_months_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e00_sub_to_3_months_renewal_info.appAccountToken = None
        e00_sub_to_3_months_renewal_info.appTransactionId = '704897469903383919'
        e00_sub_to_3_months_renewal_info.autoRenewProductId = None
        e00_sub_to_3_months_renewal_info.autoRenewStatus = None
        e00_sub_to_3_months_renewal_info.currency = 'AUD'
        e00_sub_to_3_months_renewal_info.eligibleWinBackOfferIds = None
        e00_sub_to_3_months_renewal_info.environment = AppleEnvironment.SANDBOX
        e00_sub_to_3_months_renewal_info.expirationIntent = None
        e00_sub_to_3_months_renewal_info.gracePeriodExpiresDate = None
        e00_sub_to_3_months_renewal_info.isInBillingRetryPeriod = None
        e00_sub_to_3_months_renewal_info.offerDiscountType = None
        e00_sub_to_3_months_renewal_info.offerIdentifier = None
        e00_sub_to_3_months_renewal_info.offerPeriod = None
        e00_sub_to_3_months_renewal_info.offerType = None
        e00_sub_to_3_months_renewal_info.originalTransactionId = '2000001024993299'
        e00_sub_to_3_months_renewal_info.priceIncreaseStatus = None
        e00_sub_to_3_months_renewal_info.productId = 'com.getsession.org.pro_sub_3_months'
        e00_sub_to_3_months_renewal_info.rawAutoRenewStatus = None
        e00_sub_to_3_months_renewal_info.rawEnvironment = 'Sandbox'
        e00_sub_to_3_months_renewal_info.rawExpirationIntent = None
        e00_sub_to_3_months_renewal_info.rawOfferDiscountType = None
        e00_sub_to_3_months_renewal_info.rawOfferType = None
        e00_sub_to_3_months_renewal_info.rawPriceIncreaseStatus = None
        e00_sub_to_3_months_renewal_info.recentSubscriptionStartDate = None
        e00_sub_to_3_months_renewal_info.renewalDate = None
        e00_sub_to_3_months_renewal_info.renewalPrice = None
        e00_sub_to_3_months_renewal_info.signedDate = 1759727785445

        # NOTE: Signed Transaction Info
        e00_sub_to_3_months_tx_info = AppleJWSTransactionDecodedPayload()
        e00_sub_to_3_months_tx_info.appAccountToken = apple_token
        e00_sub_to_3_months_tx_info.appTransactionId = '704897469903383919'
        e00_sub_to_3_months_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e00_sub_to_3_months_tx_info.currency = 'AUD'
        e00_sub_to_3_months_tx_info.environment = AppleEnvironment.SANDBOX
        e00_sub_to_3_months_tx_info.expiresDate = 1759728318000
        e00_sub_to_3_months_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e00_sub_to_3_months_tx_info.isUpgraded = None
        e00_sub_to_3_months_tx_info.offerDiscountType = None
        e00_sub_to_3_months_tx_info.offerIdentifier = None
        e00_sub_to_3_months_tx_info.offerPeriod = None
        e00_sub_to_3_months_tx_info.offerType = None
        e00_sub_to_3_months_tx_info.originalPurchaseDate = 1759301833000
        e00_sub_to_3_months_tx_info.originalTransactionId = '2000001024993299'
        e00_sub_to_3_months_tx_info.price = 5990
        e00_sub_to_3_months_tx_info.productId = 'com.getsession.org.pro_sub_3_months'
        e00_sub_to_3_months_tx_info.purchaseDate = 1759727778000
        e00_sub_to_3_months_tx_info.quantity = 1
        e00_sub_to_3_months_tx_info.rawEnvironment = 'Sandbox'
        e00_sub_to_3_months_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e00_sub_to_3_months_tx_info.rawOfferDiscountType = None
        e00_sub_to_3_months_tx_info.rawOfferType = None
        e00_sub_to_3_months_tx_info.rawRevocationReason = None
        e00_sub_to_3_months_tx_info.rawTransactionReason = 'PURCHASE'
        e00_sub_to_3_months_tx_info.rawType = 'Auto-Renewable Subscription'
        e00_sub_to_3_months_tx_info.revocationDate = None
        e00_sub_to_3_months_tx_info.revocationReason = None
        e00_sub_to_3_months_tx_info.signedDate = 1759727785445
        e00_sub_to_3_months_tx_info.storefront = 'AUS'
        e00_sub_to_3_months_tx_info.storefrontId = '143460'
        e00_sub_to_3_months_tx_info.subscriptionGroupIdentifier = '21752814'
        e00_sub_to_3_months_tx_info.transactionId = '2000001027701898'
        e00_sub_to_3_months_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e00_sub_to_3_months_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e00_sub_to_3_months_tx_info.webOrderLineItemId = '2000000113864605'

        e00_sub_to_3_months_decoded_notification = app_store.DecodedNotification(
            body=e00_sub_to_3_months_body,
            tx_info=e00_sub_to_3_months_tx_info,
            renewal_info=e00_sub_to_3_months_renewal_info,
        )

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e01_upgrade_to_1wk_body = AppleResponseBodyV2DecodedPayload()
        e01_upgrade_to_1wk_body_data = AppleData()
        e01_upgrade_to_1wk_body_data.appAppleId = 1470168868
        e01_upgrade_to_1wk_body_data.bundleId = 'com.loki-project.loki-messenger'
        e01_upgrade_to_1wk_body_data.bundleVersion = '637'
        e01_upgrade_to_1wk_body_data.consumptionRequestReason = None
        e01_upgrade_to_1wk_body_data.environment = AppleEnvironment.SANDBOX
        e01_upgrade_to_1wk_body_data.rawConsumptionRequestReason = None
        e01_upgrade_to_1wk_body_data.rawEnvironment = 'Sandbox'
        e01_upgrade_to_1wk_body_data.rawStatus = 1
        e01_upgrade_to_1wk_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjoxOTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc3OTk4MTAsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3Mjc5NzAwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.-iX0StcW4lxx8zCskl1SFf-HNOV5KiwddKJ42XmWaFCsEuABtAWszBEsJu4OIQTHh6aamYx5CkoBTeUy6hsRtg'
        e01_upgrade_to_1wk_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc3OTk4MTAsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.PHyVvDlmjoO3KFj9U_JsA7pxIp730GIwIskog5Pfsrcb_HZpXcU1LUOZYkQJjtfVPyfunMpIJAuomhfcXiGk1g'
        e01_upgrade_to_1wk_body_data.status = AppleStatus.ACTIVE
        e01_upgrade_to_1wk_body.data = e01_upgrade_to_1wk_body_data
        e01_upgrade_to_1wk_body.externalPurchaseToken = None
        e01_upgrade_to_1wk_body.notificationType = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_PREF
        e01_upgrade_to_1wk_body.notificationUUID = 'a3a3b7ae-3bd8-4b98-a83d-e5f4380aeaa2'
        e01_upgrade_to_1wk_body.rawNotificationType = 'DID_CHANGE_RENEWAL_PREF'
        e01_upgrade_to_1wk_body.rawSubtype = 'UPGRADE'
        e01_upgrade_to_1wk_body.signedDate = 1759727799810
        e01_upgrade_to_1wk_body.subtype = AppleSubtype.UPGRADE
        e01_upgrade_to_1wk_body.summary = None
        e01_upgrade_to_1wk_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e01_upgrade_to_1wk_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e01_upgrade_to_1wk_renewal_info.appAccountToken = None
        e01_upgrade_to_1wk_renewal_info.appTransactionId = '704897469903383919'
        e01_upgrade_to_1wk_renewal_info.autoRenewProductId = None
        e01_upgrade_to_1wk_renewal_info.autoRenewStatus = None
        e01_upgrade_to_1wk_renewal_info.currency = 'AUD'
        e01_upgrade_to_1wk_renewal_info.eligibleWinBackOfferIds = None
        e01_upgrade_to_1wk_renewal_info.environment = AppleEnvironment.SANDBOX
        e01_upgrade_to_1wk_renewal_info.expirationIntent = None
        e01_upgrade_to_1wk_renewal_info.gracePeriodExpiresDate = None
        e01_upgrade_to_1wk_renewal_info.isInBillingRetryPeriod = None
        e01_upgrade_to_1wk_renewal_info.offerDiscountType = None
        e01_upgrade_to_1wk_renewal_info.offerIdentifier = None
        e01_upgrade_to_1wk_renewal_info.offerPeriod = None
        e01_upgrade_to_1wk_renewal_info.offerType = None
        e01_upgrade_to_1wk_renewal_info.originalTransactionId = '2000001024993299'
        e01_upgrade_to_1wk_renewal_info.priceIncreaseStatus = None
        e01_upgrade_to_1wk_renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        e01_upgrade_to_1wk_renewal_info.rawAutoRenewStatus = None
        e01_upgrade_to_1wk_renewal_info.rawEnvironment = 'Sandbox'
        e01_upgrade_to_1wk_renewal_info.rawExpirationIntent = None
        e01_upgrade_to_1wk_renewal_info.rawOfferDiscountType = None
        e01_upgrade_to_1wk_renewal_info.rawOfferType = None
        e01_upgrade_to_1wk_renewal_info.rawPriceIncreaseStatus = None
        e01_upgrade_to_1wk_renewal_info.recentSubscriptionStartDate = None
        e01_upgrade_to_1wk_renewal_info.renewalDate = None
        e01_upgrade_to_1wk_renewal_info.renewalPrice = None
        e01_upgrade_to_1wk_renewal_info.signedDate = 1759727799810

        # NOTE: Signed Transaction Info
        e01_upgrade_to_1wk_tx_info = AppleJWSTransactionDecodedPayload()
        e01_upgrade_to_1wk_tx_info.appAccountToken = apple_token
        e01_upgrade_to_1wk_tx_info.appTransactionId = '704897469903383919'
        e01_upgrade_to_1wk_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e01_upgrade_to_1wk_tx_info.currency = 'AUD'
        e01_upgrade_to_1wk_tx_info.environment = AppleEnvironment.SANDBOX
        e01_upgrade_to_1wk_tx_info.expiresDate = 1759727970000
        e01_upgrade_to_1wk_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e01_upgrade_to_1wk_tx_info.isUpgraded = None
        e01_upgrade_to_1wk_tx_info.offerDiscountType = None
        e01_upgrade_to_1wk_tx_info.offerIdentifier = None
        e01_upgrade_to_1wk_tx_info.offerPeriod = None
        e01_upgrade_to_1wk_tx_info.offerType = None
        e01_upgrade_to_1wk_tx_info.originalPurchaseDate = 1759301833000
        e01_upgrade_to_1wk_tx_info.originalTransactionId = '2000001024993299'
        e01_upgrade_to_1wk_tx_info.price = 1990
        e01_upgrade_to_1wk_tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        e01_upgrade_to_1wk_tx_info.purchaseDate = 1759727790000
        e01_upgrade_to_1wk_tx_info.quantity = 1
        e01_upgrade_to_1wk_tx_info.rawEnvironment = 'Sandbox'
        e01_upgrade_to_1wk_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e01_upgrade_to_1wk_tx_info.rawOfferDiscountType = None
        e01_upgrade_to_1wk_tx_info.rawOfferType = None
        e01_upgrade_to_1wk_tx_info.rawRevocationReason = None
        e01_upgrade_to_1wk_tx_info.rawTransactionReason = 'PURCHASE'
        e01_upgrade_to_1wk_tx_info.rawType = 'Auto-Renewable Subscription'
        e01_upgrade_to_1wk_tx_info.revocationDate = None
        e01_upgrade_to_1wk_tx_info.revocationReason = None
        e01_upgrade_to_1wk_tx_info.signedDate = 1759727799810
        e01_upgrade_to_1wk_tx_info.storefront = 'AUS'
        e01_upgrade_to_1wk_tx_info.storefrontId = '143460'
        e01_upgrade_to_1wk_tx_info.subscriptionGroupIdentifier = '21752814'
        e01_upgrade_to_1wk_tx_info.transactionId = '2000001027701928'
        e01_upgrade_to_1wk_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e01_upgrade_to_1wk_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e01_upgrade_to_1wk_tx_info.webOrderLineItemId = '2000000114202140'

        e01_upgrade_to_1wk_decoded_notification = app_store.DecodedNotification(
            body=e01_upgrade_to_1wk_body,
            tx_info=e01_upgrade_to_1wk_tx_info,
            renewal_info=e01_upgrade_to_1wk_renewal_info,
        )

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e02_disable_auto_renew_body = AppleResponseBodyV2DecodedPayload()
        e02_disable_auto_renew_body_data = AppleData()
        e02_disable_auto_renew_body_data.appAppleId = 1470168868
        e02_disable_auto_renew_body_data.bundleId = 'com.loki-project.loki-messenger'
        e02_disable_auto_renew_body_data.bundleVersion = '637'
        e02_disable_auto_renew_body_data.consumptionRequestReason = None
        e02_disable_auto_renew_body_data.environment = AppleEnvironment.SANDBOX
        e02_disable_auto_renew_body_data.rawConsumptionRequestReason = None
        e02_disable_auto_renew_body_data.rawEnvironment = 'Sandbox'
        e02_disable_auto_renew_body_data.rawStatus = 1
        e02_disable_auto_renew_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwic2lnbmVkRGF0ZSI6MTc1OTcyNzgyMTk1MiwiZW52aXJvbm1lbnQiOiJTYW5kYm94IiwicmVjZW50U3Vic2NyaXB0aW9uU3RhcnREYXRlIjoxNzU5NzI3Nzc4MDAwLCJyZW5ld2FsRGF0ZSI6MTc1OTcyNzk3MDAwMCwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.fR7KkdRfmctSc8VYJsGLNNnqtoXmHgmvainD-4L0_5iVBDQlkiTGYtuoH4lyiwZY98X8POdqiU-gdhXDfv3pLQ'
        e02_disable_auto_renew_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4MjE5NTIsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.qxH5ABfXbiUnCQSe9QlwXMLdbhdE1FI1-1IRuKnYpw0Eel1Z4NDrGFasT-TMbAAFa8e4NCOAu_QdKsPtygluOg'
        e02_disable_auto_renew_body_data.status = AppleStatus.ACTIVE
        e02_disable_auto_renew_body.data = e02_disable_auto_renew_body_data
        e02_disable_auto_renew_body.externalPurchaseToken = None
        e02_disable_auto_renew_body.notificationType = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_STATUS
        e02_disable_auto_renew_body.notificationUUID = '6a8251d2-425d-49a3-81b6-517cefc4a5ea'
        e02_disable_auto_renew_body.rawNotificationType = 'DID_CHANGE_RENEWAL_STATUS'
        e02_disable_auto_renew_body.rawSubtype = 'AUTO_RENEW_DISABLED'
        e02_disable_auto_renew_body.signedDate = 1759727821952
        e02_disable_auto_renew_body.subtype = AppleSubtype.AUTO_RENEW_DISABLED
        e02_disable_auto_renew_body.summary = None
        e02_disable_auto_renew_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e02_disable_auto_renew_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e02_disable_auto_renew_renewal_info.appAccountToken = None
        e02_disable_auto_renew_renewal_info.appTransactionId = '704897469903383919'
        e02_disable_auto_renew_renewal_info.autoRenewProductId = None
        e02_disable_auto_renew_renewal_info.autoRenewStatus = None
        e02_disable_auto_renew_renewal_info.currency = 'AUD'
        e02_disable_auto_renew_renewal_info.eligibleWinBackOfferIds = None
        e02_disable_auto_renew_renewal_info.environment = AppleEnvironment.SANDBOX
        e02_disable_auto_renew_renewal_info.expirationIntent = None
        e02_disable_auto_renew_renewal_info.gracePeriodExpiresDate = None
        e02_disable_auto_renew_renewal_info.isInBillingRetryPeriod = None
        e02_disable_auto_renew_renewal_info.offerDiscountType = None
        e02_disable_auto_renew_renewal_info.offerIdentifier = None
        e02_disable_auto_renew_renewal_info.offerPeriod = None
        e02_disable_auto_renew_renewal_info.offerType = None
        e02_disable_auto_renew_renewal_info.originalTransactionId = '2000001024993299'
        e02_disable_auto_renew_renewal_info.priceIncreaseStatus = None
        e02_disable_auto_renew_renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        e02_disable_auto_renew_renewal_info.rawAutoRenewStatus = None
        e02_disable_auto_renew_renewal_info.rawEnvironment = 'Sandbox'
        e02_disable_auto_renew_renewal_info.rawExpirationIntent = None
        e02_disable_auto_renew_renewal_info.rawOfferDiscountType = None
        e02_disable_auto_renew_renewal_info.rawOfferType = None
        e02_disable_auto_renew_renewal_info.rawPriceIncreaseStatus = None
        e02_disable_auto_renew_renewal_info.recentSubscriptionStartDate = None
        e02_disable_auto_renew_renewal_info.renewalDate = None
        e02_disable_auto_renew_renewal_info.renewalPrice = None
        e02_disable_auto_renew_renewal_info.signedDate = 1759727821952

        # NOTE: Signed Transaction Info
        e02_disable_auto_renew_tx_info = AppleJWSTransactionDecodedPayload()
        e02_disable_auto_renew_tx_info.appAccountToken = apple_token
        e02_disable_auto_renew_tx_info.appTransactionId = '704897469903383919'
        e02_disable_auto_renew_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e02_disable_auto_renew_tx_info.currency = 'AUD'
        e02_disable_auto_renew_tx_info.environment = AppleEnvironment.SANDBOX
        e02_disable_auto_renew_tx_info.expiresDate = 1759727970000
        e02_disable_auto_renew_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e02_disable_auto_renew_tx_info.isUpgraded = None
        e02_disable_auto_renew_tx_info.offerDiscountType = None
        e02_disable_auto_renew_tx_info.offerIdentifier = None
        e02_disable_auto_renew_tx_info.offerPeriod = None
        e02_disable_auto_renew_tx_info.offerType = None
        e02_disable_auto_renew_tx_info.originalPurchaseDate = 1759301833000
        e02_disable_auto_renew_tx_info.originalTransactionId = '2000001024993299'
        e02_disable_auto_renew_tx_info.price = 1990
        e02_disable_auto_renew_tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        e02_disable_auto_renew_tx_info.purchaseDate = 1759727790000
        e02_disable_auto_renew_tx_info.quantity = 1
        e02_disable_auto_renew_tx_info.rawEnvironment = 'Sandbox'
        e02_disable_auto_renew_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e02_disable_auto_renew_tx_info.rawOfferDiscountType = None
        e02_disable_auto_renew_tx_info.rawOfferType = None
        e02_disable_auto_renew_tx_info.rawRevocationReason = None
        e02_disable_auto_renew_tx_info.rawTransactionReason = 'PURCHASE'
        e02_disable_auto_renew_tx_info.rawType = 'Auto-Renewable Subscription'
        e02_disable_auto_renew_tx_info.revocationDate = None
        e02_disable_auto_renew_tx_info.revocationReason = None
        e02_disable_auto_renew_tx_info.signedDate = 1759727821952
        e02_disable_auto_renew_tx_info.storefront = 'AUS'
        e02_disable_auto_renew_tx_info.storefrontId = '143460'
        e02_disable_auto_renew_tx_info.subscriptionGroupIdentifier = '21752814'
        e02_disable_auto_renew_tx_info.transactionId = '2000001027701928'
        e02_disable_auto_renew_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e02_disable_auto_renew_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e02_disable_auto_renew_tx_info.webOrderLineItemId = '2000000114202140'

        e02_disable_auto_renew_decoded_notification = app_store.DecodedNotification(
            body=e02_disable_auto_renew_body,
            tx_info=e02_disable_auto_renew_tx_info,
            renewal_info=e02_disable_auto_renew_renewal_info,
        )

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e03_queue_downgrade_to_3_months_body = AppleResponseBodyV2DecodedPayload()
        e03_queue_downgrade_to_3_months_body_data = AppleData()
        e03_queue_downgrade_to_3_months_body_data.appAppleId = 1470168868
        e03_queue_downgrade_to_3_months_body_data.bundleId = 'com.loki-project.loki-messenger'
        e03_queue_downgrade_to_3_months_body_data.bundleVersion = '637'
        e03_queue_downgrade_to_3_months_body_data.consumptionRequestReason = None
        e03_queue_downgrade_to_3_months_body_data.environment = AppleEnvironment.SANDBOX
        e03_queue_downgrade_to_3_months_body_data.rawConsumptionRequestReason = None
        e03_queue_downgrade_to_3_months_body_data.rawEnvironment = 'Sandbox'
        e03_queue_downgrade_to_3_months_body_data.rawStatus = 1
        e03_queue_downgrade_to_3_months_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjo1OTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4Mzg0NTAsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3Mjc5NzAwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.x9ex7aFlmHJ3U286ZLPluVX5ES0PjgVzIVOxxzKVjrNjRi-GVsSHuDSJbz_wkF0zBBtvEcOOgOnjIqiHVRPmMA'
        e03_queue_downgrade_to_3_months_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4Mzg0NTAsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.CjL3XeQfKQaz-bCwrYsDGlVKTHgoeg1zXXsheGtsuMsqzxJrjF7VdutsywY_YyQ7lzWiOuEB4nqXX96ZvJpJiA'
        e03_queue_downgrade_to_3_months_body_data.status = AppleStatus.ACTIVE
        e03_queue_downgrade_to_3_months_body.data = e03_queue_downgrade_to_3_months_body_data
        e03_queue_downgrade_to_3_months_body.externalPurchaseToken = None
        e03_queue_downgrade_to_3_months_body.notificationType = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_PREF
        e03_queue_downgrade_to_3_months_body.notificationUUID = '01c574dc-64b7-45d3-889a-5fdcb08fb5c0'
        e03_queue_downgrade_to_3_months_body.rawNotificationType = 'DID_CHANGE_RENEWAL_PREF'
        e03_queue_downgrade_to_3_months_body.rawSubtype = 'DOWNGRADE'
        e03_queue_downgrade_to_3_months_body.signedDate = 1759727838450
        e03_queue_downgrade_to_3_months_body.subtype = AppleSubtype.DOWNGRADE
        e03_queue_downgrade_to_3_months_body.summary = None
        e03_queue_downgrade_to_3_months_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e03_queue_downgrade_to_3_months_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e03_queue_downgrade_to_3_months_renewal_info.appAccountToken = None
        e03_queue_downgrade_to_3_months_renewal_info.appTransactionId = '704897469903383919'
        e03_queue_downgrade_to_3_months_renewal_info.autoRenewProductId = None
        e03_queue_downgrade_to_3_months_renewal_info.autoRenewStatus = None
        e03_queue_downgrade_to_3_months_renewal_info.currency = 'AUD'
        e03_queue_downgrade_to_3_months_renewal_info.eligibleWinBackOfferIds = None
        e03_queue_downgrade_to_3_months_renewal_info.environment = AppleEnvironment.SANDBOX
        e03_queue_downgrade_to_3_months_renewal_info.expirationIntent = None
        e03_queue_downgrade_to_3_months_renewal_info.gracePeriodExpiresDate = None
        e03_queue_downgrade_to_3_months_renewal_info.isInBillingRetryPeriod = None
        e03_queue_downgrade_to_3_months_renewal_info.offerDiscountType = None
        e03_queue_downgrade_to_3_months_renewal_info.offerIdentifier = None
        e03_queue_downgrade_to_3_months_renewal_info.offerPeriod = None
        e03_queue_downgrade_to_3_months_renewal_info.offerType = None
        e03_queue_downgrade_to_3_months_renewal_info.originalTransactionId = '2000001024993299'
        e03_queue_downgrade_to_3_months_renewal_info.priceIncreaseStatus = None
        e03_queue_downgrade_to_3_months_renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        e03_queue_downgrade_to_3_months_renewal_info.rawAutoRenewStatus = None
        e03_queue_downgrade_to_3_months_renewal_info.rawEnvironment = 'Sandbox'
        e03_queue_downgrade_to_3_months_renewal_info.rawExpirationIntent = None
        e03_queue_downgrade_to_3_months_renewal_info.rawOfferDiscountType = None
        e03_queue_downgrade_to_3_months_renewal_info.rawOfferType = None
        e03_queue_downgrade_to_3_months_renewal_info.rawPriceIncreaseStatus = None
        e03_queue_downgrade_to_3_months_renewal_info.recentSubscriptionStartDate = None
        e03_queue_downgrade_to_3_months_renewal_info.renewalDate = None
        e03_queue_downgrade_to_3_months_renewal_info.renewalPrice = None
        e03_queue_downgrade_to_3_months_renewal_info.signedDate = 1759727838450

        # NOTE: Signed Transaction Info
        e03_queue_downgrade_to_3_months_tx_info = AppleJWSTransactionDecodedPayload()
        e03_queue_downgrade_to_3_months_tx_info.appAccountToken = apple_token
        e03_queue_downgrade_to_3_months_tx_info.appTransactionId = '704897469903383919'
        e03_queue_downgrade_to_3_months_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e03_queue_downgrade_to_3_months_tx_info.currency = 'AUD'
        e03_queue_downgrade_to_3_months_tx_info.environment = AppleEnvironment.SANDBOX
        e03_queue_downgrade_to_3_months_tx_info.expiresDate = 1759727970000
        e03_queue_downgrade_to_3_months_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e03_queue_downgrade_to_3_months_tx_info.isUpgraded = None
        e03_queue_downgrade_to_3_months_tx_info.offerDiscountType = None
        e03_queue_downgrade_to_3_months_tx_info.offerIdentifier = None
        e03_queue_downgrade_to_3_months_tx_info.offerPeriod = None
        e03_queue_downgrade_to_3_months_tx_info.offerType = None
        e03_queue_downgrade_to_3_months_tx_info.originalPurchaseDate = 1759301833000
        e03_queue_downgrade_to_3_months_tx_info.originalTransactionId = '2000001024993299'
        e03_queue_downgrade_to_3_months_tx_info.price = 1990
        e03_queue_downgrade_to_3_months_tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        e03_queue_downgrade_to_3_months_tx_info.purchaseDate = 1759727790000
        e03_queue_downgrade_to_3_months_tx_info.quantity = 1
        e03_queue_downgrade_to_3_months_tx_info.rawEnvironment = 'Sandbox'
        e03_queue_downgrade_to_3_months_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e03_queue_downgrade_to_3_months_tx_info.rawOfferDiscountType = None
        e03_queue_downgrade_to_3_months_tx_info.rawOfferType = None
        e03_queue_downgrade_to_3_months_tx_info.rawRevocationReason = None
        e03_queue_downgrade_to_3_months_tx_info.rawTransactionReason = 'PURCHASE'
        e03_queue_downgrade_to_3_months_tx_info.rawType = 'Auto-Renewable Subscription'
        e03_queue_downgrade_to_3_months_tx_info.revocationDate = None
        e03_queue_downgrade_to_3_months_tx_info.revocationReason = None
        e03_queue_downgrade_to_3_months_tx_info.signedDate = 1759727838450
        e03_queue_downgrade_to_3_months_tx_info.storefront = 'AUS'
        e03_queue_downgrade_to_3_months_tx_info.storefrontId = '143460'
        e03_queue_downgrade_to_3_months_tx_info.subscriptionGroupIdentifier = '21752814'
        e03_queue_downgrade_to_3_months_tx_info.transactionId = '2000001027701928'
        e03_queue_downgrade_to_3_months_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e03_queue_downgrade_to_3_months_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e03_queue_downgrade_to_3_months_tx_info.webOrderLineItemId = '2000000114202140'

        e03_queue_downgrade_to_3_months_decoded_notification = app_store.DecodedNotification(
            body=e03_queue_downgrade_to_3_months_body,
            tx_info=e03_queue_downgrade_to_3_months_tx_info,
            renewal_info=e03_queue_downgrade_to_3_months_renewal_info,
        )

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e04_cancel_downgrade_to_3_months_body = AppleResponseBodyV2DecodedPayload()
        e04_cancel_downgrade_to_3_months_body_data = AppleData()
        e04_cancel_downgrade_to_3_months_body_data.appAppleId = 1470168868
        e04_cancel_downgrade_to_3_months_body_data.bundleId = 'com.loki-project.loki-messenger'
        e04_cancel_downgrade_to_3_months_body_data.bundleVersion = '637'
        e04_cancel_downgrade_to_3_months_body_data.consumptionRequestReason = None
        e04_cancel_downgrade_to_3_months_body_data.environment = AppleEnvironment.SANDBOX
        e04_cancel_downgrade_to_3_months_body_data.rawConsumptionRequestReason = None
        e04_cancel_downgrade_to_3_months_body_data.rawEnvironment = 'Sandbox'
        e04_cancel_downgrade_to_3_months_body_data.rawStatus = 1
        e04_cancel_downgrade_to_3_months_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjoxOTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4NjYyMzEsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3Mjc5NzAwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.TISJVF_0VsKDc7UAwT3Z4vM8oSRco0cPGQ4z6r3kAi44Ya1f1Rlppfcy49QrnhZGqubPusYnBVG8fMUCXiX3jw'
        e04_cancel_downgrade_to_3_months_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4NjYyMzEsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.tJMEYs32Qyqgnhx3ITrzpgERSIRi_1KjfF5H9Eyhg1ZRb-yhgoVw0KfbE5cfQD_JIxf-BVYLXmzsG6tzjeE0cg'
        e04_cancel_downgrade_to_3_months_body_data.status = AppleStatus.ACTIVE
        e04_cancel_downgrade_to_3_months_body.data = e04_cancel_downgrade_to_3_months_body_data
        e04_cancel_downgrade_to_3_months_body.externalPurchaseToken = None
        e04_cancel_downgrade_to_3_months_body.notificationType = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_PREF
        e04_cancel_downgrade_to_3_months_body.notificationUUID = 'a7a530f8-2e03-4b16-ba4c-cee50725f8d8'
        e04_cancel_downgrade_to_3_months_body.rawNotificationType = 'DID_CHANGE_RENEWAL_PREF'
        e04_cancel_downgrade_to_3_months_body.rawSubtype = None
        e04_cancel_downgrade_to_3_months_body.signedDate = 1759727866231
        e04_cancel_downgrade_to_3_months_body.subtype = None
        e04_cancel_downgrade_to_3_months_body.summary = None
        e04_cancel_downgrade_to_3_months_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e04_cancel_downgrade_to_3_months_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e04_cancel_downgrade_to_3_months_renewal_info.appAccountToken = None
        e04_cancel_downgrade_to_3_months_renewal_info.appTransactionId = '704897469903383919'
        e04_cancel_downgrade_to_3_months_renewal_info.autoRenewProductId = None
        e04_cancel_downgrade_to_3_months_renewal_info.autoRenewStatus = None
        e04_cancel_downgrade_to_3_months_renewal_info.currency = 'AUD'
        e04_cancel_downgrade_to_3_months_renewal_info.eligibleWinBackOfferIds = None
        e04_cancel_downgrade_to_3_months_renewal_info.environment = AppleEnvironment.SANDBOX
        e04_cancel_downgrade_to_3_months_renewal_info.expirationIntent = None
        e04_cancel_downgrade_to_3_months_renewal_info.gracePeriodExpiresDate = None
        e04_cancel_downgrade_to_3_months_renewal_info.isInBillingRetryPeriod = None
        e04_cancel_downgrade_to_3_months_renewal_info.offerDiscountType = None
        e04_cancel_downgrade_to_3_months_renewal_info.offerIdentifier = None
        e04_cancel_downgrade_to_3_months_renewal_info.offerPeriod = None
        e04_cancel_downgrade_to_3_months_renewal_info.offerType = None
        e04_cancel_downgrade_to_3_months_renewal_info.originalTransactionId = '2000001024993299'
        e04_cancel_downgrade_to_3_months_renewal_info.priceIncreaseStatus = None
        e04_cancel_downgrade_to_3_months_renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        e04_cancel_downgrade_to_3_months_renewal_info.rawAutoRenewStatus = None
        e04_cancel_downgrade_to_3_months_renewal_info.rawEnvironment = 'Sandbox'
        e04_cancel_downgrade_to_3_months_renewal_info.rawExpirationIntent = None
        e04_cancel_downgrade_to_3_months_renewal_info.rawOfferDiscountType = None
        e04_cancel_downgrade_to_3_months_renewal_info.rawOfferType = None
        e04_cancel_downgrade_to_3_months_renewal_info.rawPriceIncreaseStatus = None
        e04_cancel_downgrade_to_3_months_renewal_info.recentSubscriptionStartDate = None
        e04_cancel_downgrade_to_3_months_renewal_info.renewalDate = None
        e04_cancel_downgrade_to_3_months_renewal_info.renewalPrice = None
        e04_cancel_downgrade_to_3_months_renewal_info.signedDate = 1759727866231

        # NOTE: Signed Transaction Info
        e04_cancel_downgrade_to_3_months_tx_info = AppleJWSTransactionDecodedPayload()
        e04_cancel_downgrade_to_3_months_tx_info.appAccountToken = apple_token
        e04_cancel_downgrade_to_3_months_tx_info.appTransactionId = '704897469903383919'
        e04_cancel_downgrade_to_3_months_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e04_cancel_downgrade_to_3_months_tx_info.currency = 'AUD'
        e04_cancel_downgrade_to_3_months_tx_info.environment = AppleEnvironment.SANDBOX
        e04_cancel_downgrade_to_3_months_tx_info.expiresDate = 1759727970000
        e04_cancel_downgrade_to_3_months_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e04_cancel_downgrade_to_3_months_tx_info.isUpgraded = None
        e04_cancel_downgrade_to_3_months_tx_info.offerDiscountType = None
        e04_cancel_downgrade_to_3_months_tx_info.offerIdentifier = None
        e04_cancel_downgrade_to_3_months_tx_info.offerPeriod = None
        e04_cancel_downgrade_to_3_months_tx_info.offerType = None
        e04_cancel_downgrade_to_3_months_tx_info.originalPurchaseDate = 1759301833000
        e04_cancel_downgrade_to_3_months_tx_info.originalTransactionId = '2000001024993299'
        e04_cancel_downgrade_to_3_months_tx_info.price = 1990
        e04_cancel_downgrade_to_3_months_tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        e04_cancel_downgrade_to_3_months_tx_info.purchaseDate = 1759727790000
        e04_cancel_downgrade_to_3_months_tx_info.quantity = 1
        e04_cancel_downgrade_to_3_months_tx_info.rawEnvironment = 'Sandbox'
        e04_cancel_downgrade_to_3_months_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e04_cancel_downgrade_to_3_months_tx_info.rawOfferDiscountType = None
        e04_cancel_downgrade_to_3_months_tx_info.rawOfferType = None
        e04_cancel_downgrade_to_3_months_tx_info.rawRevocationReason = None
        e04_cancel_downgrade_to_3_months_tx_info.rawTransactionReason = 'PURCHASE'
        e04_cancel_downgrade_to_3_months_tx_info.rawType = 'Auto-Renewable Subscription'
        e04_cancel_downgrade_to_3_months_tx_info.revocationDate = None
        e04_cancel_downgrade_to_3_months_tx_info.revocationReason = None
        e04_cancel_downgrade_to_3_months_tx_info.signedDate = 1759727866231
        e04_cancel_downgrade_to_3_months_tx_info.storefront = 'AUS'
        e04_cancel_downgrade_to_3_months_tx_info.storefrontId = '143460'
        e04_cancel_downgrade_to_3_months_tx_info.subscriptionGroupIdentifier = '21752814'
        e04_cancel_downgrade_to_3_months_tx_info.transactionId = '2000001027701928'
        e04_cancel_downgrade_to_3_months_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e04_cancel_downgrade_to_3_months_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e04_cancel_downgrade_to_3_months_tx_info.webOrderLineItemId = '2000000114202140'

        e04_cancel_downgrade_to_3_months_decoded_notification = app_store.DecodedNotification(
            body=e04_cancel_downgrade_to_3_months_body,
            tx_info=e04_cancel_downgrade_to_3_months_tx_info,
            renewal_info=e04_cancel_downgrade_to_3_months_renewal_info,
        )

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e05_disable_auto_renew_body = AppleResponseBodyV2DecodedPayload()
        e05_disable_auto_renew_body_data = AppleData()
        e05_disable_auto_renew_body_data.appAppleId = 1470168868
        e05_disable_auto_renew_body_data.bundleId = 'com.loki-project.loki-messenger'
        e05_disable_auto_renew_body_data.bundleVersion = '637'
        e05_disable_auto_renew_body_data.consumptionRequestReason = None
        e05_disable_auto_renew_body_data.environment = AppleEnvironment.SANDBOX
        e05_disable_auto_renew_body_data.rawConsumptionRequestReason = None
        e05_disable_auto_renew_body_data.rawEnvironment = 'Sandbox'
        e05_disable_auto_renew_body_data.rawStatus = 1
        e05_disable_auto_renew_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwic2lnbmVkRGF0ZSI6MTc1OTcyNzg3Njg3NywiZW52aXJvbm1lbnQiOiJTYW5kYm94IiwicmVjZW50U3Vic2NyaXB0aW9uU3RhcnREYXRlIjoxNzU5NzI3Nzc4MDAwLCJyZW5ld2FsRGF0ZSI6MTc1OTcyNzk3MDAwMCwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.5iJPdUIWMXMTQkwipeRQVDhu0d-ykTuNzuhxKuPdSjeOHbnNyi4kZP95RYWmkKyJ37Dt9NFkIBZeMoOVsjHhqw'
        e05_disable_auto_renew_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc4NzY4NzcsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.me1YuoHaLhLPQgwG0oFW672qlEBGCgQVIL9bYvz6FCsHT4R4faGKpcH8U4ScP008mc6AH3jutl2rWWKenG_MoA'
        e05_disable_auto_renew_body_data.status = AppleStatus.ACTIVE
        e05_disable_auto_renew_body.data = e05_disable_auto_renew_body_data
        e05_disable_auto_renew_body.externalPurchaseToken = None
        e05_disable_auto_renew_body.notificationType = AppleNotificationTypeV2.DID_CHANGE_RENEWAL_STATUS
        e05_disable_auto_renew_body.notificationUUID = '2b7ed399-8a88-4445-8a59-3d2017637c15'
        e05_disable_auto_renew_body.rawNotificationType = 'DID_CHANGE_RENEWAL_STATUS'
        e05_disable_auto_renew_body.rawSubtype = 'AUTO_RENEW_DISABLED'
        e05_disable_auto_renew_body.signedDate = 1759727876877
        e05_disable_auto_renew_body.subtype = AppleSubtype.AUTO_RENEW_DISABLED
        e05_disable_auto_renew_body.summary = None
        e05_disable_auto_renew_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e05_disable_auto_renew_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e05_disable_auto_renew_renewal_info.appAccountToken = None
        e05_disable_auto_renew_renewal_info.appTransactionId = '704897469903383919'
        e05_disable_auto_renew_renewal_info.autoRenewProductId = None
        e05_disable_auto_renew_renewal_info.autoRenewStatus = None
        e05_disable_auto_renew_renewal_info.currency = 'AUD'
        e05_disable_auto_renew_renewal_info.eligibleWinBackOfferIds = None
        e05_disable_auto_renew_renewal_info.environment = AppleEnvironment.SANDBOX
        e05_disable_auto_renew_renewal_info.expirationIntent = None
        e05_disable_auto_renew_renewal_info.gracePeriodExpiresDate = None
        e05_disable_auto_renew_renewal_info.isInBillingRetryPeriod = None
        e05_disable_auto_renew_renewal_info.offerDiscountType = None
        e05_disable_auto_renew_renewal_info.offerIdentifier = None
        e05_disable_auto_renew_renewal_info.offerPeriod = None
        e05_disable_auto_renew_renewal_info.offerType = None
        e05_disable_auto_renew_renewal_info.originalTransactionId = '2000001024993299'
        e05_disable_auto_renew_renewal_info.priceIncreaseStatus = None
        e05_disable_auto_renew_renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        e05_disable_auto_renew_renewal_info.rawAutoRenewStatus = None
        e05_disable_auto_renew_renewal_info.rawEnvironment = 'Sandbox'
        e05_disable_auto_renew_renewal_info.rawExpirationIntent = None
        e05_disable_auto_renew_renewal_info.rawOfferDiscountType = None
        e05_disable_auto_renew_renewal_info.rawOfferType = None
        e05_disable_auto_renew_renewal_info.rawPriceIncreaseStatus = None
        e05_disable_auto_renew_renewal_info.recentSubscriptionStartDate = None
        e05_disable_auto_renew_renewal_info.renewalDate = None
        e05_disable_auto_renew_renewal_info.renewalPrice = None
        e05_disable_auto_renew_renewal_info.signedDate = 1759727876877

        # NOTE: Signed Transaction Info
        e05_disable_auto_renew_tx_info = AppleJWSTransactionDecodedPayload()
        e05_disable_auto_renew_tx_info.appAccountToken = apple_token
        e05_disable_auto_renew_tx_info.appTransactionId = '704897469903383919'
        e05_disable_auto_renew_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e05_disable_auto_renew_tx_info.currency = 'AUD'
        e05_disable_auto_renew_tx_info.environment = AppleEnvironment.SANDBOX
        e05_disable_auto_renew_tx_info.expiresDate = 1759727970000
        e05_disable_auto_renew_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e05_disable_auto_renew_tx_info.isUpgraded = None
        e05_disable_auto_renew_tx_info.offerDiscountType = None
        e05_disable_auto_renew_tx_info.offerIdentifier = None
        e05_disable_auto_renew_tx_info.offerPeriod = None
        e05_disable_auto_renew_tx_info.offerType = None
        e05_disable_auto_renew_tx_info.originalPurchaseDate = 1759301833000
        e05_disable_auto_renew_tx_info.originalTransactionId = '2000001024993299'
        e05_disable_auto_renew_tx_info.price = 1990
        e05_disable_auto_renew_tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        e05_disable_auto_renew_tx_info.purchaseDate = 1759727790000
        e05_disable_auto_renew_tx_info.quantity = 1
        e05_disable_auto_renew_tx_info.rawEnvironment = 'Sandbox'
        e05_disable_auto_renew_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e05_disable_auto_renew_tx_info.rawOfferDiscountType = None
        e05_disable_auto_renew_tx_info.rawOfferType = None
        e05_disable_auto_renew_tx_info.rawRevocationReason = None
        e05_disable_auto_renew_tx_info.rawTransactionReason = 'PURCHASE'
        e05_disable_auto_renew_tx_info.rawType = 'Auto-Renewable Subscription'
        e05_disable_auto_renew_tx_info.revocationDate = None
        e05_disable_auto_renew_tx_info.revocationReason = None
        e05_disable_auto_renew_tx_info.signedDate = 1759727876877
        e05_disable_auto_renew_tx_info.storefront = 'AUS'
        e05_disable_auto_renew_tx_info.storefrontId = '143460'
        e05_disable_auto_renew_tx_info.subscriptionGroupIdentifier = '21752814'
        e05_disable_auto_renew_tx_info.transactionId = '2000001027701928'
        e05_disable_auto_renew_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e05_disable_auto_renew_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e05_disable_auto_renew_tx_info.webOrderLineItemId = '2000000114202140'

        e05_disable_auto_renew_decoded_notification = app_store.DecodedNotification(
            body=e05_disable_auto_renew_body,
            tx_info=e05_disable_auto_renew_tx_info,
            renewal_info=e05_disable_auto_renew_renewal_info,
        )

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e06_expire_voluntary_body = AppleResponseBodyV2DecodedPayload()
        e06_expire_voluntary_body_data = AppleData()
        e06_expire_voluntary_body_data.appAppleId = 1470168868
        e06_expire_voluntary_body_data.bundleId = 'com.loki-project.loki-messenger'
        e06_expire_voluntary_body_data.bundleVersion = '637'
        e06_expire_voluntary_body_data.consumptionRequestReason = None
        e06_expire_voluntary_body_data.environment = AppleEnvironment.SANDBOX
        e06_expire_voluntary_body_data.rawConsumptionRequestReason = None
        e06_expire_voluntary_body_data.rawEnvironment = 'Sandbox'
        e06_expire_voluntary_body_data.rawStatus = 2
        e06_expire_voluntary_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJleHBpcmF0aW9uSW50ZW50IjoxLCJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1YiIsImF1dG9SZW5ld1N0YXR1cyI6MCwiaXNJbkJpbGxpbmdSZXRyeVBlcmlvZCI6ZmFsc2UsInNpZ25lZERhdGUiOjE3NTk3Mjc5ODU3OTksImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc1OTcyNzc3ODAwMCwicmVuZXdhbERhdGUiOjE3NTk3Mjc5NzAwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.VYSGUnH9JX-BUvKERAICKF_BTIAyBmZwXaLsjh1jFRnfuaulaP9Fk_jW4TUubVfwNx54I6lCFndQkb0LerPXig'
        e06_expire_voluntary_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAyNzcwMTkyOCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0MjAyMTQwIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc1OTcyNzc5MDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzU5NzI3OTcwMDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NTk3Mjc5ODU3OTksImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.ySyuX_8zEZNC7Csjeb-iNYEI4xrpOkX_uIiIBbLfKaAtRMkUd_8HhNgK_6mqhC-YRyis0AGr3JqUqDchBpitFg'
        e06_expire_voluntary_body_data.status = AppleStatus.EXPIRED
        e06_expire_voluntary_body.data = e06_expire_voluntary_body_data
        e06_expire_voluntary_body.externalPurchaseToken = None
        e06_expire_voluntary_body.notificationType = AppleNotificationTypeV2.EXPIRED
        e06_expire_voluntary_body.notificationUUID = 'ae5e6496-626b-4c23-828f-3fa9143c2f5e'
        e06_expire_voluntary_body.rawNotificationType = 'EXPIRED'
        e06_expire_voluntary_body.rawSubtype = 'VOLUNTARY'
        e06_expire_voluntary_body.signedDate = 1759727985799
        e06_expire_voluntary_body.subtype = AppleSubtype.VOLUNTARY
        e06_expire_voluntary_body.summary = None
        e06_expire_voluntary_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e06_expire_voluntary_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e06_expire_voluntary_renewal_info.appAccountToken = None
        e06_expire_voluntary_renewal_info.appTransactionId = '704897469903383919'
        e06_expire_voluntary_renewal_info.autoRenewProductId = None
        e06_expire_voluntary_renewal_info.autoRenewStatus = None
        e06_expire_voluntary_renewal_info.currency = 'AUD'
        e06_expire_voluntary_renewal_info.eligibleWinBackOfferIds = None
        e06_expire_voluntary_renewal_info.environment = AppleEnvironment.SANDBOX
        e06_expire_voluntary_renewal_info.expirationIntent = None
        e06_expire_voluntary_renewal_info.gracePeriodExpiresDate = None
        e06_expire_voluntary_renewal_info.isInBillingRetryPeriod = None
        e06_expire_voluntary_renewal_info.offerDiscountType = None
        e06_expire_voluntary_renewal_info.offerIdentifier = None
        e06_expire_voluntary_renewal_info.offerPeriod = None
        e06_expire_voluntary_renewal_info.offerType = None
        e06_expire_voluntary_renewal_info.originalTransactionId = '2000001024993299'
        e06_expire_voluntary_renewal_info.priceIncreaseStatus = None
        e06_expire_voluntary_renewal_info.productId = 'com.getsession.org.pro_sub_1_month'
        e06_expire_voluntary_renewal_info.rawAutoRenewStatus = None
        e06_expire_voluntary_renewal_info.rawEnvironment = 'Sandbox'
        e06_expire_voluntary_renewal_info.rawExpirationIntent = None
        e06_expire_voluntary_renewal_info.rawOfferDiscountType = None
        e06_expire_voluntary_renewal_info.rawOfferType = None
        e06_expire_voluntary_renewal_info.rawPriceIncreaseStatus = None
        e06_expire_voluntary_renewal_info.recentSubscriptionStartDate = None
        e06_expire_voluntary_renewal_info.renewalDate = None
        e06_expire_voluntary_renewal_info.renewalPrice = None
        e06_expire_voluntary_renewal_info.signedDate = 1759727985799

        # NOTE: Signed Transaction Info
        e06_expire_voluntary_tx_info = AppleJWSTransactionDecodedPayload()
        e06_expire_voluntary_tx_info.appAccountToken = apple_token
        e06_expire_voluntary_tx_info.appTransactionId = '704897469903383919'
        e06_expire_voluntary_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e06_expire_voluntary_tx_info.currency = 'AUD'
        e06_expire_voluntary_tx_info.environment = AppleEnvironment.SANDBOX
        e06_expire_voluntary_tx_info.expiresDate = 1759727970000
        e06_expire_voluntary_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e06_expire_voluntary_tx_info.isUpgraded = None
        e06_expire_voluntary_tx_info.offerDiscountType = None
        e06_expire_voluntary_tx_info.offerIdentifier = None
        e06_expire_voluntary_tx_info.offerPeriod = None
        e06_expire_voluntary_tx_info.offerType = None
        e06_expire_voluntary_tx_info.originalPurchaseDate = 1759301833000
        e06_expire_voluntary_tx_info.originalTransactionId = '2000001024993299'
        e06_expire_voluntary_tx_info.price = 1990
        e06_expire_voluntary_tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        e06_expire_voluntary_tx_info.purchaseDate = 1759727790000
        e06_expire_voluntary_tx_info.quantity = 1
        e06_expire_voluntary_tx_info.rawEnvironment = 'Sandbox'
        e06_expire_voluntary_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e06_expire_voluntary_tx_info.rawOfferDiscountType = None
        e06_expire_voluntary_tx_info.rawOfferType = None
        e06_expire_voluntary_tx_info.rawRevocationReason = None
        e06_expire_voluntary_tx_info.rawTransactionReason = 'PURCHASE'
        e06_expire_voluntary_tx_info.rawType = 'Auto-Renewable Subscription'
        e06_expire_voluntary_tx_info.revocationDate = None
        e06_expire_voluntary_tx_info.revocationReason = None
        e06_expire_voluntary_tx_info.signedDate = 1759727985799
        e06_expire_voluntary_tx_info.storefront = 'AUS'
        e06_expire_voluntary_tx_info.storefrontId = '143460'
        e06_expire_voluntary_tx_info.subscriptionGroupIdentifier = '21752814'
        e06_expire_voluntary_tx_info.transactionId = '2000001027701928'
        e06_expire_voluntary_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e06_expire_voluntary_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e06_expire_voluntary_tx_info.webOrderLineItemId = '2000000114202140'

        e06_expire_voluntary_decoded_notification = app_store.DecodedNotification(
            body=e06_expire_voluntary_body,
            tx_info=e06_expire_voluntary_tx_info,
            renewal_info=e06_expire_voluntary_renewal_info,
        )

        # NOTE: Execute and test notifications (master_key/rotating_key from the top of the test)
        err = base.ErrorSink()

        # NOTE: Witness 3 month subscription
        unredeemed_payment_list = []
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e00_sub_to_3_months_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list
            unredeemed_payment_list = backend.get_unredeemed_payments_list(conn)

        assert len(unredeemed_payment_list) == 1
        assert unredeemed_payment_list[0].master_pkey is None
        assert derived_status(unredeemed_payment_list[0]) == base.PaymentStatus.Unredeemed
        assert unredeemed_payment_list[0].plan == base.ProPlan.ThreeMonth
        assert unredeemed_payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
        assert unredeemed_payment_list[0].auto_renewing
        assert unredeemed_payment_list[0].purchased_at == base.datetime_from_unix_ms(
            e00_sub_to_3_months_tx_info.purchaseDate
        )
        assert unredeemed_payment_list[0].redeemed_at is None
        assert unredeemed_payment_list[0].expires_at == base.datetime_from_unix_ms(
            e00_sub_to_3_months_tx_info.expiresDate
        )
        assert unredeemed_payment_list[0].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
        assert unredeemed_payment_list[0].platform_refund_expires_at == base.datetime_from_unix_ms(
            e00_sub_to_3_months_tx_info.expiresDate
        )
        assert unredeemed_payment_list[0].revoked_at is None
        assert unredeemed_payment_list[0].apple.original_tx_id == e00_sub_to_3_months_tx_info.originalTransactionId
        assert unredeemed_payment_list[0].apple.tx_id == e00_sub_to_3_months_tx_info.transactionId
        assert unredeemed_payment_list[0].apple.web_line_order_tx_id == e00_sub_to_3_months_tx_info.webOrderLineItemId

        # NOTE: Then redeem the payment
        add_pro_payment_tx = backend.UserPaymentTransaction()
        add_pro_payment_tx.provider = base.PaymentProvider.iOSAppStore
        add_pro_payment_tx.apple_tx_id = unredeemed_payment_list[0].apple.tx_id
        add_pro_payment_tx.payment_id = backend.payment_id_from_user_tx(add_pro_payment_tx)
        payment_hash_to_sign = backend.make_add_pro_payment_message(
            master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, payment_tx=add_pro_payment_tx
        )

        # NOTE: POST and get response
        response = test.flask_client.post(
            '/add_pro_payment',
            json={
                'master_pkey': bytes(master_key.verify_key).hex(),
                'rotating_pkey': bytes(rotating_key.verify_key).hex(),
                'master_sig': bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
                'rotating_sig': bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
                'payment_tx': {
                    'provider': add_pro_payment_tx.provider.value,
                    'payment_id': add_pro_payment_tx.payment_id,
                },
            },
        )

        # NOTE: Check payment got redeemed to the DB
        with test.connection() as conn:
            payment_list = backend.get_payments_list(conn)

        assert len(payment_list) == 1
        assert payment_list[0].master_pkey == bytes(master_key.verify_key)
        assert derived_status(payment_list[0]) == base.PaymentStatus.Redeemed
        assert payment_list[0].plan == base.ProPlan.ThreeMonth
        assert payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
        assert payment_list[0].auto_renewing
        assert payment_list[0].purchased_at == base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.purchaseDate)
        assert payment_list[0].redeemed_at is not None
        assert payment_list[0].expires_at == base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.expiresDate)
        assert payment_list[0].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
        assert payment_list[0].platform_refund_expires_at == base.datetime_from_unix_ms(
            e00_sub_to_3_months_tx_info.expiresDate
        )
        assert payment_list[0].revoked_at is None
        assert payment_list[0].apple.original_tx_id == e00_sub_to_3_months_tx_info.originalTransactionId
        assert payment_list[0].apple.tx_id == e00_sub_to_3_months_tx_info.transactionId
        assert payment_list[0].apple.web_line_order_tx_id == e00_sub_to_3_months_tx_info.webOrderLineItemId

        # NOTE: "Upgrade" to 1 week subscription. Initially when we set up the Apple subscriptions,
        # 1 week was put at the top of the list, this makes it have a higher ranking than the 3
        # month subscription following it. This means that going to a 1 week subscription is
        # considered an "upgrade".
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e01_upgrade_to_1wk_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list
            payment_list = backend.get_payments_list(conn)

            # NOTE: An upgrade is applied immediately because the user pays on the spot to upgrade.
            # The old subscription should be revoked incase the user already redeemed it and the
            # new payment should be sitting in the unredeemed queue.

            # NOTE: Check the previous payment was refunded
            assert len(payment_list) == 2
            assert payment_list[0].master_pkey == bytes(master_key.verify_key)
            assert derived_status(payment_list[0]) == base.PaymentStatus.Revoked
            assert payment_list[0].plan == base.ProPlan.ThreeMonth
            assert payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert not payment_list[0].auto_renewing
            assert payment_list[0].purchased_at == base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.purchaseDate)
            assert payment_list[0].redeemed_at is not None
            assert payment_list[0].expires_at == base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.expiresDate)
            assert payment_list[0].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert payment_list[0].platform_refund_expires_at == base.datetime_from_unix_ms(
                e00_sub_to_3_months_tx_info.expiresDate
            )
            assert payment_list[0].revoked_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            assert payment_list[0].apple.original_tx_id == e00_sub_to_3_months_tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id == e00_sub_to_3_months_tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id == e00_sub_to_3_months_tx_info.webOrderLineItemId
            assert payment_list[0].revoked_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)

            # NOTE: The previous payment was revoked, but it won't be in the revocation list because
            # a revocation's start time is rounded to the end of the day. So they won't show up if
            # the proof will expire before the revocation activates.
            #
            # In this example in particular, because we are using the apple sandbox testing
            # environment their timespans for subscriptions are greatly reduced to within the minute
            # range.
            #
            # We will test the other branches by modifying the timestamps, but for the reference
            # tests that use "real" sandbox data we will go with the flow.
            revocation_list: list[backend.RevocationRow] = backend.get_revocations_list(conn)
            assert not revocation_list

            # NOTE: Check the new payment is not in the unredeemed queue because auto-redeeming kicked in
            unredeemed_payment_list = backend.get_unredeemed_payments_list(conn)
            assert not unredeemed_payment_list

            # NOTE: Check the details of the auto-redeemed payment
            assert payment_list[1].master_pkey == bytes(master_key.verify_key)
            assert derived_status(payment_list[1]) == base.PaymentStatus.Redeemed
            assert payment_list[1].plan == base.ProPlan.OneMonth
            assert payment_list[1].payment_provider == base.PaymentProvider.iOSAppStore
            assert payment_list[1].auto_renewing
            assert payment_list[1].purchased_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            assert payment_list[1].redeemed_at == backend.to_redeemed_at(
                base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            )
            assert payment_list[1].expires_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.expiresDate)
            assert payment_list[1].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert payment_list[1].platform_refund_expires_at == base.datetime_from_unix_ms(
                e01_upgrade_to_1wk_tx_info.expiresDate
            )
            assert payment_list[1].revoked_at is None
            assert payment_list[1].apple.original_tx_id == e01_upgrade_to_1wk_tx_info.originalTransactionId
            assert payment_list[1].apple.tx_id == e01_upgrade_to_1wk_tx_info.transactionId
            assert payment_list[1].apple.web_line_order_tx_id == e01_upgrade_to_1wk_tx_info.webOrderLineItemId

        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e02_disable_auto_renew_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: Check the payment was marked not auto-renewing
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 2
            assert not payment_list[-1].auto_renewing

        # NOTE: A downgrade should be a no-op as it's queued to execute at the end of the billing
        # cycle, but it does implicitly mean that auto-renewing is turned back on.
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e03_queue_downgrade_to_3_months_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: Check the new payment has remain unchanged
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 2
            assert payment_list[-1].master_pkey == bytes(master_key.verify_key)
            assert derived_status(payment_list[-1]) == base.PaymentStatus.Redeemed
            assert payment_list[-1].plan == base.ProPlan.OneMonth
            assert payment_list[-1].payment_provider == base.PaymentProvider.iOSAppStore

            # NOTE: In this sequence, apparently, auto-renewing should be turned back on. The reason
            # for this is that since the user downgraded to 1wk plan which takes effect at the end
            # of the month, they are resuming their subscription with _another week_ after their
            # current billing cycle ends.
            #
            # So the auto-renewing flag on our side should be set true
            assert payment_list[-1].auto_renewing

            assert payment_list[-1].purchased_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            assert payment_list[-1].redeemed_at == backend.to_redeemed_at(
                base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            )
            assert payment_list[-1].expires_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.expiresDate)
            assert payment_list[-1].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert payment_list[-1].platform_refund_expires_at == base.datetime_from_unix_ms(
                e01_upgrade_to_1wk_tx_info.expiresDate
            )
            assert payment_list[-1].revoked_at is None
            assert payment_list[-1].apple.original_tx_id == e01_upgrade_to_1wk_tx_info.originalTransactionId
            assert payment_list[-1].apple.tx_id == e01_upgrade_to_1wk_tx_info.transactionId
            assert payment_list[-1].apple.web_line_order_tx_id == e01_upgrade_to_1wk_tx_info.webOrderLineItemId

        # NOTE: Cancelling a downgrade means that the queued downgrade to 3 months is undone. We
        # remain on the 1wk plan
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e04_cancel_downgrade_to_3_months_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: Check that the initial 3 month subscription remains refunded (e.g. unchanged)
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 2
            assert payment_list[0].master_pkey == bytes(master_key.verify_key)
            assert derived_status(payment_list[0]) == base.PaymentStatus.Revoked
            assert payment_list[0].plan == base.ProPlan.ThreeMonth
            assert payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert not payment_list[0].auto_renewing
            assert payment_list[0].purchased_at == base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.purchaseDate)
            assert payment_list[0].redeemed_at is not None
            assert payment_list[0].expires_at == base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.expiresDate)
            assert payment_list[0].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert payment_list[0].platform_refund_expires_at == base.datetime_from_unix_ms(
                e00_sub_to_3_months_tx_info.expiresDate
            )
            assert payment_list[0].revoked_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            assert payment_list[0].apple.original_tx_id == e00_sub_to_3_months_tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id == e00_sub_to_3_months_tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id == e00_sub_to_3_months_tx_info.webOrderLineItemId

            # NOTE: Check that the 1 week plan remains unchanged
            unredeemed_payment_list = []
            with test.connection() as conn:
                unredeemed_payment_list = backend.get_unredeemed_payments_list(conn)
                assert not unredeemed_payment_list

            assert payment_list[-1].master_pkey == bytes(master_key.verify_key)
            assert derived_status(payment_list[-1]) == base.PaymentStatus.Redeemed
            assert payment_list[-1].plan == base.ProPlan.OneMonth
            assert payment_list[-1].payment_provider == base.PaymentProvider.iOSAppStore
            assert payment_list[-1].auto_renewing
            assert payment_list[-1].purchased_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            assert payment_list[-1].redeemed_at == backend.to_redeemed_at(
                base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            )
            assert payment_list[-1].expires_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.expiresDate)
            assert payment_list[-1].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert payment_list[-1].platform_refund_expires_at == base.datetime_from_unix_ms(
                e01_upgrade_to_1wk_tx_info.expiresDate
            )
            assert payment_list[-1].revoked_at is None
            assert payment_list[-1].apple.original_tx_id == e01_upgrade_to_1wk_tx_info.originalTransactionId
            assert payment_list[-1].apple.tx_id == e01_upgrade_to_1wk_tx_info.transactionId
            assert payment_list[-1].apple.web_line_order_tx_id == e01_upgrade_to_1wk_tx_info.webOrderLineItemId

        # NOTE: Disable auto renew, flag should be turned false for the 1 week plan payment
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e05_disable_auto_renew_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: Check the payment was marked not auto-renewing
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 2
            assert not payment_list[-1].auto_renewing

        # NOTE: Expire the subscription
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e06_expire_voluntary_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: This is a no-op, but in this test we haven't advanced time past the expiry yet
            # so actually the subscription should still be marked unredeemed in the database hence
            # check that the 1 week plan remains unchanged
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 2

            assert payment_list[-1].master_pkey == bytes(master_key.verify_key)
            assert derived_status(payment_list[-1]) == base.PaymentStatus.Redeemed
            assert payment_list[-1].plan == base.ProPlan.OneMonth
            assert payment_list[-1].payment_provider == base.PaymentProvider.iOSAppStore
            assert not payment_list[-1].auto_renewing
            assert payment_list[-1].purchased_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            assert payment_list[-1].redeemed_at == backend.to_redeemed_at(
                base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            )
            assert payment_list[-1].expires_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.expiresDate)
            assert payment_list[-1].grace_period == base.DEFAULT_APPLE_GRACE_PERIOD
            assert payment_list[-1].platform_refund_expires_at == base.datetime_from_unix_ms(
                e01_upgrade_to_1wk_tx_info.expiresDate
            )
            assert payment_list[-1].revoked_at is None
            assert payment_list[-1].apple.original_tx_id == e01_upgrade_to_1wk_tx_info.originalTransactionId
            assert payment_list[-1].apple.tx_id == e01_upgrade_to_1wk_tx_info.transactionId
            assert payment_list[-1].apple.web_line_order_tx_id == e01_upgrade_to_1wk_tx_info.webOrderLineItemId

        assert not err.has(), err.msg_list

    # NOTE: Execute the sequence
    #  - 0 [SUBSCRIBED,                sub: ??] Subscribe to 3 months
    #
    # Inbetween we submitted a refund request. Apple asks us for a "consumption request" update. We
    # don't respond to this notification. It's not clear how we'd utilise this API yet.
    #
    # > if the customer provided consent, respond by calling this API and
    # > sending the consumption data in the ConsumptionRequest to the App Store.
    # > If not, don’t respond to the CONSUMPTION_REQUEST notification.
    #
    # > Respond within 12 hours of receiving the CONSUMPTION_REQUEST notification.
    #
    #  - 1 [APPLE CONSUMPTION REQUEST, sub: ??] No-op
    #  - 2 [APPLE REFUND,              sub: ??] Disable auto-renew
    with TestingContext(pg_database) as test:

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e00_sub_to_3_months_body = AppleResponseBodyV2DecodedPayload()
        e00_sub_to_3_months_body_data = AppleData()
        e00_sub_to_3_months_body_data.appAppleId = 1470168868
        e00_sub_to_3_months_body_data.bundleId = 'com.loki-project.loki-messenger'
        e00_sub_to_3_months_body_data.bundleVersion = '637'
        e00_sub_to_3_months_body_data.consumptionRequestReason = None
        e00_sub_to_3_months_body_data.environment = AppleEnvironment.SANDBOX
        e00_sub_to_3_months_body_data.rawConsumptionRequestReason = None
        e00_sub_to_3_months_body_data.rawEnvironment = 'Sandbox'
        e00_sub_to_3_months_body_data.rawStatus = 1
        e00_sub_to_3_months_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1Yl8zX21vbnRocyIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjo1OTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NjA1OTE3OTIwODcsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc2MDU5MTc3NDAwMCwicmVuZXdhbERhdGUiOjE3NjA1OTIzMTQwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.MxjfuaEX7Eu2WHIE6meAiK5a4x1uE9aLB_fOyduqIRLUT4Md1S1PgCdF3wexMogmVBY6H3Wvd0q_Vhb-aEhEIA'
        e00_sub_to_3_months_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAzNTI4ODQ4NiIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0OTMwNzA4IiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc2MDU5MTc3NDAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzYwNTkyMzE0MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NjA1OTE3OTIwODcsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjU5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.3H81XSZJX3dfBrZvnVtAx4lfRXo0aQf_ldjC6MouAwEG-Hg5uEJHGmOQYCl_VjKof8iNEHyaCdNzb07FMYFsEg'
        e00_sub_to_3_months_body_data.status = AppleStatus.ACTIVE
        e00_sub_to_3_months_body.data = e00_sub_to_3_months_body_data
        e00_sub_to_3_months_body.externalPurchaseToken = None
        e00_sub_to_3_months_body.notificationType = AppleNotificationTypeV2.SUBSCRIBED
        e00_sub_to_3_months_body.notificationUUID = 'd32c3ba8-a457-47a4-9f09-0beea5042aa4'
        e00_sub_to_3_months_body.rawNotificationType = 'SUBSCRIBED'
        e00_sub_to_3_months_body.rawSubtype = 'RESUBSCRIBE'
        e00_sub_to_3_months_body.signedDate = 1760591792087
        e00_sub_to_3_months_body.subtype = AppleSubtype.RESUBSCRIBE
        e00_sub_to_3_months_body.summary = None
        e00_sub_to_3_months_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e00_sub_to_3_months_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e00_sub_to_3_months_renewal_info.appAccountToken = None
        e00_sub_to_3_months_renewal_info.appTransactionId = '704897469903383919'
        e00_sub_to_3_months_renewal_info.autoRenewProductId = 'com.getsession.org.pro_sub_3_months'
        e00_sub_to_3_months_renewal_info.autoRenewStatus = AppleAutoRenewStatus.ON
        e00_sub_to_3_months_renewal_info.currency = 'AUD'
        e00_sub_to_3_months_renewal_info.eligibleWinBackOfferIds = None
        e00_sub_to_3_months_renewal_info.environment = AppleEnvironment.SANDBOX
        e00_sub_to_3_months_renewal_info.expirationIntent = None
        e00_sub_to_3_months_renewal_info.gracePeriodExpiresDate = None
        e00_sub_to_3_months_renewal_info.isInBillingRetryPeriod = None
        e00_sub_to_3_months_renewal_info.offerDiscountType = None
        e00_sub_to_3_months_renewal_info.offerIdentifier = None
        e00_sub_to_3_months_renewal_info.offerPeriod = None
        e00_sub_to_3_months_renewal_info.offerType = None
        e00_sub_to_3_months_renewal_info.originalTransactionId = '2000001024993299'
        e00_sub_to_3_months_renewal_info.priceIncreaseStatus = None
        e00_sub_to_3_months_renewal_info.productId = 'com.getsession.org.pro_sub_3_months'
        e00_sub_to_3_months_renewal_info.rawAutoRenewStatus = 1
        e00_sub_to_3_months_renewal_info.rawEnvironment = 'Sandbox'
        e00_sub_to_3_months_renewal_info.rawExpirationIntent = None
        e00_sub_to_3_months_renewal_info.rawOfferDiscountType = None
        e00_sub_to_3_months_renewal_info.rawOfferType = None
        e00_sub_to_3_months_renewal_info.rawPriceIncreaseStatus = None
        e00_sub_to_3_months_renewal_info.recentSubscriptionStartDate = 1760591774000
        e00_sub_to_3_months_renewal_info.renewalDate = 1760592314000
        e00_sub_to_3_months_renewal_info.renewalPrice = 5990
        e00_sub_to_3_months_renewal_info.signedDate = 1760591792087

        # NOTE: Signed Transaction Info
        e00_sub_to_3_months_tx_info = AppleJWSTransactionDecodedPayload()
        e00_sub_to_3_months_tx_info.appAccountToken = apple_token
        e00_sub_to_3_months_tx_info.appTransactionId = '704897469903383919'
        e00_sub_to_3_months_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e00_sub_to_3_months_tx_info.currency = 'AUD'
        e00_sub_to_3_months_tx_info.environment = AppleEnvironment.SANDBOX
        e00_sub_to_3_months_tx_info.expiresDate = 1760592314000
        e00_sub_to_3_months_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e00_sub_to_3_months_tx_info.isUpgraded = None
        e00_sub_to_3_months_tx_info.offerDiscountType = None
        e00_sub_to_3_months_tx_info.offerIdentifier = None
        e00_sub_to_3_months_tx_info.offerPeriod = None
        e00_sub_to_3_months_tx_info.offerType = None
        e00_sub_to_3_months_tx_info.originalPurchaseDate = 1759301833000
        e00_sub_to_3_months_tx_info.originalTransactionId = '2000001024993299'
        e00_sub_to_3_months_tx_info.price = 5990
        e00_sub_to_3_months_tx_info.productId = 'com.getsession.org.pro_sub_3_months'
        e00_sub_to_3_months_tx_info.purchaseDate = 1760591774000
        e00_sub_to_3_months_tx_info.quantity = 1
        e00_sub_to_3_months_tx_info.rawEnvironment = 'Sandbox'
        e00_sub_to_3_months_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e00_sub_to_3_months_tx_info.rawOfferDiscountType = None
        e00_sub_to_3_months_tx_info.rawOfferType = None
        e00_sub_to_3_months_tx_info.rawRevocationReason = None
        e00_sub_to_3_months_tx_info.rawTransactionReason = 'PURCHASE'
        e00_sub_to_3_months_tx_info.rawType = 'Auto-Renewable Subscription'
        e00_sub_to_3_months_tx_info.revocationDate = None
        e00_sub_to_3_months_tx_info.revocationReason = None
        e00_sub_to_3_months_tx_info.signedDate = 1760591792087
        e00_sub_to_3_months_tx_info.storefront = 'AUS'
        e00_sub_to_3_months_tx_info.storefrontId = '143460'
        e00_sub_to_3_months_tx_info.subscriptionGroupIdentifier = '21752814'
        e00_sub_to_3_months_tx_info.transactionId = '2000001035288486'
        e00_sub_to_3_months_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e00_sub_to_3_months_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e00_sub_to_3_months_tx_info.webOrderLineItemId = '2000000114930708'

        e00_sub_to_3_months_decoded_notification = app_store.DecodedNotification(
            body=e00_sub_to_3_months_body,
            tx_info=e00_sub_to_3_months_tx_info,
            renewal_info=e00_sub_to_3_months_renewal_info,
        )
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e00_sub_to_3_months_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e01_consumption_req_body = AppleResponseBodyV2DecodedPayload()
        e01_consumption_req_body_data = AppleData()
        e01_consumption_req_body_data.appAppleId = 1470168868
        e01_consumption_req_body_data.bundleId = 'com.loki-project.loki-messenger'
        e01_consumption_req_body_data.bundleVersion = '637'
        e01_consumption_req_body_data.consumptionRequestReason = AppleConsumptionRequestReason.UNINTENDED_PURCHASE
        e01_consumption_req_body_data.environment = AppleEnvironment.SANDBOX
        e01_consumption_req_body_data.rawConsumptionRequestReason = 'UNINTENDED_PURCHASE'
        e01_consumption_req_body_data.rawEnvironment = 'Sandbox'
        e01_consumption_req_body_data.rawStatus = 1
        e01_consumption_req_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1Yl8zX21vbnRocyIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjo1OTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NjA1OTE5NDExMTcsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc2MDU5MTc3NDAwMCwicmVuZXdhbERhdGUiOjE3NjA1OTIzMTQwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.CJLBoDoGoYO37QRa3WdW0EVWjXu6LfQ4N-tbW0FBPcnNIZMgBBgt1l8sCnUsCJwW_9BWnj8bSotgbaV5AR7d3A'
        e01_consumption_req_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAzMjYwNDg0MCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0OTMwNjUzIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc2MDMzNTEyOTAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzYwMzM1MzA5MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NjA1OTE5NDExMTcsImVudmlyb25tZW50IjoiU2FuZGJveCIsInRyYW5zYWN0aW9uUmVhc29uIjoiUFVSQ0hBU0UiLCJzdG9yZWZyb250IjoiQVVTIiwic3RvcmVmcm9udElkIjoiMTQzNDYwIiwicHJpY2UiOjE5OTAsImN1cnJlbmN5IjoiQVVEIiwiYXBwVHJhbnNhY3Rpb25JZCI6IjcwNDg5NzQ2OTkwMzM4MzkxOSJ9.iUT3zSgIblPeRFlUrP8Lc2bDhQv5jsU0nf2eFyVfTuVpRjBqB-ijTm8TsKwTlKsKX_TAQjR5oG7tjz2x9aAXgA'
        e01_consumption_req_body_data.status = AppleStatus.ACTIVE
        e01_consumption_req_body.data = e01_consumption_req_body_data
        e01_consumption_req_body.externalPurchaseToken = None
        e01_consumption_req_body.notificationType = AppleNotificationTypeV2.CONSUMPTION_REQUEST
        e01_consumption_req_body.notificationUUID = '15101c57-7b3d-49c2-8adf-74ac2740ea8c'
        e01_consumption_req_body.rawNotificationType = 'CONSUMPTION_REQUEST'
        e01_consumption_req_body.rawSubtype = None
        e01_consumption_req_body.signedDate = 1760591941117
        e01_consumption_req_body.subtype = None
        e01_consumption_req_body.summary = None
        e01_consumption_req_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e01_consumption_req_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e01_consumption_req_renewal_info.appAccountToken = None
        e01_consumption_req_renewal_info.appTransactionId = '704897469903383919'
        e01_consumption_req_renewal_info.autoRenewProductId = 'com.getsession.org.pro_sub_3_months'
        e01_consumption_req_renewal_info.autoRenewStatus = AppleAutoRenewStatus.ON
        e01_consumption_req_renewal_info.currency = 'AUD'
        e01_consumption_req_renewal_info.eligibleWinBackOfferIds = None
        e01_consumption_req_renewal_info.environment = AppleEnvironment.SANDBOX
        e01_consumption_req_renewal_info.expirationIntent = None
        e01_consumption_req_renewal_info.gracePeriodExpiresDate = None
        e01_consumption_req_renewal_info.isInBillingRetryPeriod = None
        e01_consumption_req_renewal_info.offerDiscountType = None
        e01_consumption_req_renewal_info.offerIdentifier = None
        e01_consumption_req_renewal_info.offerPeriod = None
        e01_consumption_req_renewal_info.offerType = None
        e01_consumption_req_renewal_info.originalTransactionId = '2000001024993299'
        e01_consumption_req_renewal_info.priceIncreaseStatus = None
        e01_consumption_req_renewal_info.productId = 'com.getsession.org.pro_sub_3_months'
        e01_consumption_req_renewal_info.rawAutoRenewStatus = 1
        e01_consumption_req_renewal_info.rawEnvironment = 'Sandbox'
        e01_consumption_req_renewal_info.rawExpirationIntent = None
        e01_consumption_req_renewal_info.rawOfferDiscountType = None
        e01_consumption_req_renewal_info.rawOfferType = None
        e01_consumption_req_renewal_info.rawPriceIncreaseStatus = None
        e01_consumption_req_renewal_info.recentSubscriptionStartDate = 1760591774000
        e01_consumption_req_renewal_info.renewalDate = 1760592314000
        e01_consumption_req_renewal_info.renewalPrice = 5990
        e01_consumption_req_renewal_info.signedDate = 1760591941117

        # NOTE: Signed Transaction Info
        e01_consumption_req_tx_info = AppleJWSTransactionDecodedPayload()
        e01_consumption_req_tx_info.appAccountToken = apple_token
        e01_consumption_req_tx_info.appTransactionId = '704897469903383919'
        e01_consumption_req_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e01_consumption_req_tx_info.currency = 'AUD'
        e01_consumption_req_tx_info.environment = AppleEnvironment.SANDBOX
        e01_consumption_req_tx_info.expiresDate = 1760335309000
        e01_consumption_req_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e01_consumption_req_tx_info.isUpgraded = None
        e01_consumption_req_tx_info.offerDiscountType = None
        e01_consumption_req_tx_info.offerIdentifier = None
        e01_consumption_req_tx_info.offerPeriod = None
        e01_consumption_req_tx_info.offerType = None
        e01_consumption_req_tx_info.originalPurchaseDate = 1759301833000
        e01_consumption_req_tx_info.originalTransactionId = '2000001024993299'
        e01_consumption_req_tx_info.price = 1990
        e01_consumption_req_tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        e01_consumption_req_tx_info.purchaseDate = 1760335129000
        e01_consumption_req_tx_info.quantity = 1
        e01_consumption_req_tx_info.rawEnvironment = 'Sandbox'
        e01_consumption_req_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e01_consumption_req_tx_info.rawOfferDiscountType = None
        e01_consumption_req_tx_info.rawOfferType = None
        e01_consumption_req_tx_info.rawRevocationReason = None
        e01_consumption_req_tx_info.rawTransactionReason = 'PURCHASE'
        e01_consumption_req_tx_info.rawType = 'Auto-Renewable Subscription'
        e01_consumption_req_tx_info.revocationDate = None
        e01_consumption_req_tx_info.revocationReason = None
        e01_consumption_req_tx_info.signedDate = 1760591941117
        e01_consumption_req_tx_info.storefront = 'AUS'
        e01_consumption_req_tx_info.storefrontId = '143460'
        e01_consumption_req_tx_info.subscriptionGroupIdentifier = '21752814'
        e01_consumption_req_tx_info.transactionId = '2000001032604840'
        e01_consumption_req_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e01_consumption_req_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e01_consumption_req_tx_info.webOrderLineItemId = '2000000114930653'

        e01_consumption_req_decoded_notification = app_store.DecodedNotification(
            body=e01_consumption_req_body,
            tx_info=e01_consumption_req_tx_info,
            renewal_info=e01_consumption_req_renewal_info,
        )
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e01_consumption_req_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

        # NOTE: Generated by dump_apple_signed_payloads
        # NOTE: Signed Payload
        e02_apple_refund_body = AppleResponseBodyV2DecodedPayload()
        e02_apple_refund_body_data = AppleData()
        e02_apple_refund_body_data.appAppleId = 1470168868
        e02_apple_refund_body_data.bundleId = 'com.loki-project.loki-messenger'
        e02_apple_refund_body_data.bundleVersion = '637'
        e02_apple_refund_body_data.consumptionRequestReason = None
        e02_apple_refund_body_data.environment = AppleEnvironment.SANDBOX
        e02_apple_refund_body_data.rawConsumptionRequestReason = None
        e02_apple_refund_body_data.rawEnvironment = 'Sandbox'
        e02_apple_refund_body_data.rawStatus = 1
        e02_apple_refund_body_data.signedRenewalInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJvcmlnaW5hbFRyYW5zYWN0aW9uSWQiOiIyMDAwMDAxMDI0OTkzMjk5IiwiYXV0b1JlbmV3UHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWJfM19tb250aHMiLCJwcm9kdWN0SWQiOiJjb20uZ2V0c2Vzc2lvbi5vcmcucHJvX3N1Yl8zX21vbnRocyIsImF1dG9SZW5ld1N0YXR1cyI6MSwicmVuZXdhbFByaWNlIjo1OTkwLCJjdXJyZW5jeSI6IkFVRCIsInNpZ25lZERhdGUiOjE3NjA1OTIxMjI3ODgsImVudmlyb25tZW50IjoiU2FuZGJveCIsInJlY2VudFN1YnNjcmlwdGlvblN0YXJ0RGF0ZSI6MTc2MDU5MTc3NDAwMCwicmVuZXdhbERhdGUiOjE3NjA1OTIzMTQwMDAsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.D__lwfLRRMuyGLniLChHyDhuh4HnV3VXRA5xcZ-IKkqM-Etk--q7LvyDLX0IrfwcWdV06yNicvEUxFu6stOUgg'
        e02_apple_refund_body_data.signedTransactionInfo = 'eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlFTVRDQ0E3YWdBd0lCQWdJUVI4S0h6ZG41NTRaL1VvcmFkTng5dHpBS0JnZ3Foa2pPUFFRREF6QjFNVVF3UWdZRFZRUURERHRCY0hCc1pTQlhiM0pzWkhkcFpHVWdSR1YyWld4dmNHVnlJRkpsYkdGMGFXOXVjeUJEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURUxNQWtHQTFVRUN3d0NSell4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJMU1Ea3hPVEU1TkRRMU1Wb1hEVEkzTVRBeE16RTNORGN5TTFvd2daSXhRREErQmdOVkJBTU1OMUJ5YjJRZ1JVTkRJRTFoWXlCQmNIQWdVM1J2Y21VZ1lXNWtJR2xVZFc1bGN5QlRkRzl5WlNCU1pXTmxhWEIwSUZOcFoyNXBibWN4TERBcUJnTlZCQXNNSTBGd2NHeGxJRmR2Y214a2QybGtaU0JFWlhabGJHOXdaWElnVW1Wc1lYUnBiMjV6TVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTm5WdmhjdjdpVCs3RXg1dEJNQmdyUXNwSHpJc1hSaTBZeGZlazdsdjh3RW1qL2JIaVd0TndKcWMyQm9IenNRaUVqUDdLRklJS2c0WTh5MC9ueW51QW1qZ2dJSU1JSUNCREFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGRDh2bENOUjAxREptaWc5N2JCODVjK2xrR0taTUhBR0NDc0dBUVVGQndFQkJHUXdZakF0QmdnckJnRUZCUWN3QW9ZaGFIUjBjRG92TDJObGNuUnpMbUZ3Y0d4bExtTnZiUzkzZDJSeVp6WXVaR1Z5TURFR0NDc0dBUVVGQnpBQmhpVm9kSFJ3T2k4dmIyTnpjQzVoY0hCc1pTNWpiMjB2YjJOemNEQXpMWGQzWkhKbk5qQXlNSUlCSGdZRFZSMGdCSUlCRlRDQ0FSRXdnZ0VOQmdvcWhraUc5Mk5rQlFZQk1JSCtNSUhEQmdnckJnRUZCUWNDQWpDQnRneUJzMUpsYkdsaGJtTmxJRzl1SUhSb2FYTWdZMlZ5ZEdsbWFXTmhkR1VnWW5rZ1lXNTVJSEJoY25SNUlHRnpjM1Z0WlhNZ1lXTmpaWEIwWVc1alpTQnZaaUIwYUdVZ2RHaGxiaUJoY0hCc2FXTmhZbXhsSUhOMFlXNWtZWEprSUhSbGNtMXpJR0Z1WkNCamIyNWthWFJwYjI1eklHOW1JSFZ6WlN3Z1kyVnlkR2xtYVdOaGRHVWdjRzlzYVdONUlHRnVaQ0JqWlhKMGFXWnBZMkYwYVc5dUlIQnlZV04wYVdObElITjBZWFJsYldWdWRITXVNRFlHQ0NzR0FRVUZCd0lCRmlwb2RIUndPaTh2ZDNkM0xtRndjR3hsTG1OdmJTOWpaWEowYVdacFkyRjBaV0YxZEdodmNtbDBlUzh3SFFZRFZSME9CQllFRklGaW9HNHdNTVZBMWt1OXpKbUdOUEFWbjNlcU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBUUJnb3Foa2lHOTJOa0Jnc0JCQUlGQURBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQStxWG5SRUM3aFhJV1ZMc0x4em5qUnBJelBmN1ZIejlWL0NUbTgrTEpsclFlcG5tY1B2R0xOY1g2WFBubGNnTEFBakVBNUlqTlpLZ2c1cFE3OWtuRjRJYlRYZEt2OHZ1dElETVhEbWpQVlQzZEd2RnRzR1J3WE95d1Iya1pDZFNyZmVvdCIsIk1JSURGakNDQXB5Z0F3SUJBZ0lVSXNHaFJ3cDBjMm52VTRZU3ljYWZQVGp6Yk5jd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NakV3TXpFM01qQXpOekV3V2hjTk16WXdNekU1TURBd01EQXdXakIxTVVRd1FnWURWUVFERER0QmNIQnNaU0JYYjNKc1pIZHBaR1VnUkdWMlpXeHZjR1Z5SUZKbGJHRjBhVzl1Y3lCRFpYSjBhV1pwWTJGMGFXOXVJRUYxZEdodmNtbDBlVEVMTUFrR0ExVUVDd3dDUnpZeEV6QVJCZ05WQkFvTUNrRndjR3hsSUVsdVl5NHhDekFKQmdOVkJBWVRBbFZUTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVic1FLQzk0UHJsV21aWG5YZ3R4emRWSkw4VDBTR1luZ0RSR3BuZ24zTjZQVDhKTUViN0ZEaTRiQm1QaENuWjMvc3E2UEYvY0djS1hXc0w1dk90ZVJoeUo0NXgzQVNQN2NPQithYW85MGZjcHhTdi9FWkZibmlBYk5nWkdoSWhwSW80SDZNSUgzTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0h3WURWUjBqQkJnd0ZvQVV1N0Rlb1ZnemlKcWtpcG5ldnIzcnI5ckxKS3N3UmdZSUt3WUJCUVVIQVFFRU9qQTRNRFlHQ0NzR0FRVUZCekFCaGlwb2RIUndPaTh2YjJOemNDNWhjSEJzWlM1amIyMHZiMk56Y0RBekxXRndjR3hsY205dmRHTmhaek13TndZRFZSMGZCREF3TGpBc29DcWdLSVltYUhSMGNEb3ZMMk55YkM1aGNIQnNaUzVqYjIwdllYQndiR1Z5YjI5MFkyRm5NeTVqY213d0hRWURWUjBPQkJZRUZEOHZsQ05SMDFESm1pZzk3YkI4NWMrbGtHS1pNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVFCZ29xaGtpRzkyTmtCZ0lCQkFJRkFEQUtCZ2dxaGtqT1BRUURBd05vQURCbEFqQkFYaFNxNUl5S29nTUNQdHc0OTBCYUI2NzdDYUVHSlh1ZlFCL0VxWkdkNkNTamlDdE9udU1UYlhWWG14eGN4ZmtDTVFEVFNQeGFyWlh2TnJreFUzVGtVTUkzM3l6dkZWVlJUNHd4V0pDOTk0T3NkY1o0K1JHTnNZRHlSNWdtZHIwbkRHZz0iLCJNSUlDUXpDQ0FjbWdBd0lCQWdJSUxjWDhpTkxGUzVVd0NnWUlLb1pJemowRUF3TXdaekViTUJrR0ExVUVBd3dTUVhCd2JHVWdVbTl2ZENCRFFTQXRJRWN6TVNZd0pBWURWUVFMREIxQmNIQnNaU0JEWlhKMGFXWnBZMkYwYVc5dUlFRjFkR2h2Y21sMGVURVRNQkVHQTFVRUNnd0tRWEJ3YkdVZ1NXNWpMakVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF3TkRNd01UZ3hPVEEyV2hjTk16a3dORE13TVRneE9UQTJXakJuTVJzd0dRWURWUVFEREJKQmNIQnNaU0JTYjI5MElFTkJJQzBnUnpNeEpqQWtCZ05WQkFzTUhVRndjR3hsSUVObGNuUnBabWxqWVhScGIyNGdRWFYwYUc5eWFYUjVNUk13RVFZRFZRUUtEQXBCY0hCc1pTQkpibU11TVFzd0NRWURWUVFHRXdKVlV6QjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkpqcEx6MUFjcVR0a3lKeWdSTWMzUkNWOGNXalRuSGNGQmJaRHVXbUJTcDNaSHRmVGpqVHV4eEV0WC8xSDdZeVlsM0o2WVJiVHpCUEVWb0EvVmhZREtYMUR5eE5CMGNUZGRxWGw1ZHZNVnp0SzUxN0lEdll1VlRaWHBta09sRUtNYU5DTUVBd0hRWURWUjBPQkJZRUZMdXczcUZZTTRpYXBJcVozcjY5NjYvYXl5U3JNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Bb0dDQ3FHU000OUJBTURBMmdBTUdVQ01RQ0Q2Y0hFRmw0YVhUUVkyZTN2OUd3T0FFWkx1Tit5UmhIRkQvM21lb3locG12T3dnUFVuUFdUeG5TNGF0K3FJeFVDTUcxbWloREsxQTNVVDgyTlF6NjBpbU9sTTI3amJkb1h0MlFmeUZNbStZaGlkRGtMRjF2TFVhZ002QmdENTZLeUtBPT0iXX0.eyJ0cmFuc2FjdGlvbklkIjoiMjAwMDAwMTAzMjYwNDg0MCIsIm9yaWdpbmFsVHJhbnNhY3Rpb25JZCI6IjIwMDAwMDEwMjQ5OTMyOTkiLCJ3ZWJPcmRlckxpbmVJdGVtSWQiOiIyMDAwMDAwMTE0OTMwNjUzIiwiYnVuZGxlSWQiOiJjb20ubG9raS1wcm9qZWN0Lmxva2ktbWVzc2VuZ2VyIiwicHJvZHVjdElkIjoiY29tLmdldHNlc3Npb24ub3JnLnByb19zdWIiLCJzdWJzY3JpcHRpb25Hcm91cElkZW50aWZpZXIiOiIyMTc1MjgxNCIsInB1cmNoYXNlRGF0ZSI6MTc2MDMzNTEyOTAwMCwib3JpZ2luYWxQdXJjaGFzZURhdGUiOjE3NTkzMDE4MzMwMDAsImV4cGlyZXNEYXRlIjoxNzYwMzM1MzA5MDAwLCJxdWFudGl0eSI6MSwidHlwZSI6IkF1dG8tUmVuZXdhYmxlIFN1YnNjcmlwdGlvbiIsImluQXBwT3duZXJzaGlwVHlwZSI6IlBVUkNIQVNFRCIsInNpZ25lZERhdGUiOjE3NjA1OTIxMjI3ODgsInJldm9jYXRpb25SZWFzb24iOjAsInJldm9jYXRpb25EYXRlIjoxNzYwNTkxOTk5MDAwLCJlbnZpcm9ubWVudCI6IlNhbmRib3giLCJ0cmFuc2FjdGlvblJlYXNvbiI6IlBVUkNIQVNFIiwic3RvcmVmcm9udCI6IkFVUyIsInN0b3JlZnJvbnRJZCI6IjE0MzQ2MCIsInByaWNlIjoxOTkwLCJjdXJyZW5jeSI6IkFVRCIsImFwcFRyYW5zYWN0aW9uSWQiOiI3MDQ4OTc0Njk5MDMzODM5MTkifQ.u6CVLNCnB7KussK6KaqlL42IT75U_7Be7Bv4UPhLqCTdqBu3UWhS6uEEZpopbyTUiOHv-HygyYOqVBI1ERNAmw'
        e02_apple_refund_body_data.status = AppleStatus.ACTIVE
        e02_apple_refund_body.data = e02_apple_refund_body_data
        e02_apple_refund_body.externalPurchaseToken = None
        e02_apple_refund_body.notificationType = AppleNotificationTypeV2.REFUND
        e02_apple_refund_body.notificationUUID = 'caeda1df-9950-458d-87a7-93bb009e7391'
        e02_apple_refund_body.rawNotificationType = 'REFUND'
        e02_apple_refund_body.rawSubtype = None
        e02_apple_refund_body.signedDate = 1760592122788
        e02_apple_refund_body.subtype = None
        e02_apple_refund_body.summary = None
        e02_apple_refund_body.version = '2.0'

        # NOTE: Signed Renewal Info
        e02_apple_refund_renewal_info = AppleJWSRenewalInfoDecodedPayload()
        e02_apple_refund_renewal_info.appAccountToken = None
        e02_apple_refund_renewal_info.appTransactionId = '704897469903383919'
        e02_apple_refund_renewal_info.autoRenewProductId = 'com.getsession.org.pro_sub_3_months'
        e02_apple_refund_renewal_info.autoRenewStatus = AppleAutoRenewStatus.ON
        e02_apple_refund_renewal_info.currency = 'AUD'
        e02_apple_refund_renewal_info.eligibleWinBackOfferIds = None
        e02_apple_refund_renewal_info.environment = AppleEnvironment.SANDBOX
        e02_apple_refund_renewal_info.expirationIntent = None
        e02_apple_refund_renewal_info.gracePeriodExpiresDate = None
        e02_apple_refund_renewal_info.isInBillingRetryPeriod = None
        e02_apple_refund_renewal_info.offerDiscountType = None
        e02_apple_refund_renewal_info.offerIdentifier = None
        e02_apple_refund_renewal_info.offerPeriod = None
        e02_apple_refund_renewal_info.offerType = None
        e02_apple_refund_renewal_info.originalTransactionId = '2000001024993299'
        e02_apple_refund_renewal_info.priceIncreaseStatus = None
        e02_apple_refund_renewal_info.productId = 'com.getsession.org.pro_sub_3_months'
        e02_apple_refund_renewal_info.rawAutoRenewStatus = 1
        e02_apple_refund_renewal_info.rawEnvironment = 'Sandbox'
        e02_apple_refund_renewal_info.rawExpirationIntent = None
        e02_apple_refund_renewal_info.rawOfferDiscountType = None
        e02_apple_refund_renewal_info.rawOfferType = None
        e02_apple_refund_renewal_info.rawPriceIncreaseStatus = None
        e02_apple_refund_renewal_info.recentSubscriptionStartDate = 1760591774000
        e02_apple_refund_renewal_info.renewalDate = 1760592314000
        e02_apple_refund_renewal_info.renewalPrice = 5990
        e02_apple_refund_renewal_info.signedDate = 1760592122788

        # NOTE: Signed Transaction Info
        e02_apple_refund_tx_info = AppleJWSTransactionDecodedPayload()
        e02_apple_refund_tx_info.appAccountToken = apple_token
        e02_apple_refund_tx_info.appTransactionId = '704897469903383919'
        e02_apple_refund_tx_info.bundleId = 'com.loki-project.loki-messenger'
        e02_apple_refund_tx_info.currency = 'AUD'
        e02_apple_refund_tx_info.environment = AppleEnvironment.SANDBOX
        e02_apple_refund_tx_info.expiresDate = 1760335309000
        e02_apple_refund_tx_info.inAppOwnershipType = AppleInAppOwnershipType.PURCHASED
        e02_apple_refund_tx_info.isUpgraded = None
        e02_apple_refund_tx_info.offerDiscountType = None
        e02_apple_refund_tx_info.offerIdentifier = None
        e02_apple_refund_tx_info.offerPeriod = None
        e02_apple_refund_tx_info.offerType = None
        e02_apple_refund_tx_info.originalPurchaseDate = 1759301833000
        e02_apple_refund_tx_info.originalTransactionId = '2000001024993299'
        e02_apple_refund_tx_info.price = 1990
        e02_apple_refund_tx_info.productId = 'com.getsession.org.pro_sub_1_month'
        e02_apple_refund_tx_info.purchaseDate = 1760335129000
        e02_apple_refund_tx_info.quantity = 1
        e02_apple_refund_tx_info.rawEnvironment = 'Sandbox'
        e02_apple_refund_tx_info.rawInAppOwnershipType = 'PURCHASED'
        e02_apple_refund_tx_info.rawOfferDiscountType = None
        e02_apple_refund_tx_info.rawOfferType = None
        e02_apple_refund_tx_info.rawRevocationReason = 0
        e02_apple_refund_tx_info.rawTransactionReason = 'PURCHASE'
        e02_apple_refund_tx_info.rawType = 'Auto-Renewable Subscription'
        e02_apple_refund_tx_info.revocationDate = 1760591999000
        e02_apple_refund_tx_info.revocationReason = AppleRevocationReason.REFUNDED_DUE_TO_ISSUE
        e02_apple_refund_tx_info.signedDate = 1760592122788
        e02_apple_refund_tx_info.storefront = 'AUS'
        e02_apple_refund_tx_info.storefrontId = '143460'
        e02_apple_refund_tx_info.subscriptionGroupIdentifier = '21752814'
        e02_apple_refund_tx_info.transactionId = '2000001032604840'
        e02_apple_refund_tx_info.transactionReason = AppleTransactionReason.PURCHASE
        e02_apple_refund_tx_info.type = AppleType.AUTO_RENEWABLE_SUBSCRIPTION
        e02_apple_refund_tx_info.webOrderLineItemId = '2000000114930653'

        e02_apple_refund_decoded_notification = app_store.DecodedNotification(
            body=e02_apple_refund_body, tx_info=e02_apple_refund_tx_info, renewal_info=e02_apple_refund_renewal_info
        )
        with test.connection() as conn:
            app_store.handle_notification(
                decoded_notification=e02_apple_refund_decoded_notification,
                conn=conn,
                notification_retry_duration=datetime.timedelta(0),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: For this unit test we only test the ending state because we've already tested the
            # user flow up to this point via other tests.
            payments: list[backend.PaymentRow] = backend.get_payments_list(conn)
            assert len(payments) == 1
            assert derived_status(payments[0]) == base.PaymentStatus.Revoked
            assert payments[0].apple.original_tx_id == e00_sub_to_3_months_tx_info.originalTransactionId
            assert payments[0].apple.tx_id == e00_sub_to_3_months_tx_info.transactionId
            assert payments[0].apple.web_line_order_tx_id == e00_sub_to_3_months_tx_info.webOrderLineItemId
            assert payments[0].revoked_at == base.datetime_from_unix_ms(e02_apple_refund_tx_info.revocationDate)


def test_google_platform_handle_notification(monkeypatch, pg_database):
    with TestingContext(pg_database) as ctx:
        google_play.init(
            cloud_project_id='loki-5a81e',
            package_name='network.loki.messenger',
            cloud_subscription_name='session-pro-sub',
            subscription_product_id='session_pro',
            app_credentials_path=None,
        )

    err = base.ErrorSink()
    test_product_details = SubscriptionProductDetails(
        billing_period=GoogleDuration("P30D", err), grace_period=GoogleDuration("P2D", err)
    )
    assert not err.has()

    monkeypatch.setattr(
        "providers.google_play.api.fetch_subscription_details_for_base_plan_id",
        lambda *args, **kwargs: test_product_details,
    )
    monkeypatch.setattr("providers.google_play.api.subscription_v1_acknowledge", lambda *args, **kwargs: None)

    @dataclasses.dataclass
    class TestScenario:
        rtdn_event: base.JSONObject
        current_state: base.JSONObject

    @dataclasses.dataclass
    class TestUserCtx:
        master_key: nacl.signing.SigningKey
        rotating_key: nacl.signing.SigningKey
        payments: int
        google_obfuscated_account_id: bytes

        def __init__(self):
            self.payments = 0
            seed = bytes([0x01] * 32)
            self.master_key = nacl.signing.SigningKey(seed)
            self.rotating_key = nacl.signing.SigningKey.generate()
            self.google_obfuscated_account_id = bytes(self.master_key.verify_key)

    @dataclasses.dataclass
    class TestTx:
        purchase_token: str
        order_id: str
        event_ms: int
        expires_at: int

    def test_notification(scenario: TestScenario, ctx: TestingContext) -> TestTx:
        err_parse = base.ErrorSink()
        current_state = google_play.api.parse_get_subscription_v2_response(scenario.current_state, err_parse)
        assert not err_parse.has()
        assert current_state is not None

        monkeypatch.setattr(
            "providers.google_play.api.fetch_subscription_v2_details", lambda *args, **kwargs: current_state
        )

        event_time_ms_str = scenario.rtdn_event['eventTimeMillis']
        assert isinstance(event_time_ms_str, str)
        event_ms = int(event_time_ms_str)

        purchase_token = None
        if "subscriptionNotification" in scenario.rtdn_event:
            assert isinstance(scenario.rtdn_event["subscriptionNotification"], dict)
            purchase_token = scenario.rtdn_event["subscriptionNotification"]["purchaseToken"]
        elif "voidedNotification" in scenario.rtdn_event:
            assert isinstance(scenario.rtdn_event["voidedNotification"], dict)
            purchase_token = scenario.rtdn_event["voidedNotification"]["purchaseToken"]

        assert isinstance(purchase_token, str)

        err_rtdn = base.ErrorSink()
        parse = google_play.parse_notification(scenario.rtdn_event, err_rtdn)
        handled = False
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                handled = google_play.handle_parsed_notification(tx, parse, err_rtdn)
        assert not err_rtdn.has() and handled and len(parse.purchase_token) > 0

        order_id = current_state.line_items[0].latest_successful_order_id
        expiry_time_unix_ms = current_state.line_items[0].expiry_time.unix_milliseconds
        assert order_id is not None and len(order_id) > 0
        assert purchase_token is not None and len(purchase_token) > 0
        return TestTx(
            purchase_token=purchase_token, order_id=order_id, event_ms=event_ms, expires_at=expiry_time_unix_ms
        )

    """
    Testing Interaction Utility Functions
    """

    def get_pro_status(user_ctx: TestUserCtx, ctx: TestingContext, unix_ts_ms: int) -> base.JSONObject:
        ts = unix_ts_ms // 1000  # wire nonce is integer seconds (wire spec §3.4)
        hash_to_sign = backend.make_get_pro_status_message(
            master_pkey=user_ctx.master_key.verify_key, request_at=base.datetime_from_unix_seconds(ts)
        )
        request_body = {
            'master_pkey': bytes(user_ctx.master_key.verify_key).hex(),
            'master_sig': bytes(user_ctx.master_key.sign(hash_to_sign).signature).hex(),
            'ts': ts,
        }
        server.time_now = lambda: unix_ts_ms / 1000.0
        response = ctx.flask_client.post('/get_pro_status', json=request_body)
        server.time_now = lambda: time.time()
        response_json = response.json
        assert response_json is not None
        return response_json

    def get_payment_details(
        user_ctx: TestUserCtx, ctx: TestingContext, unix_ts_ms: int, limit: int, before: str = ''
    ) -> base.JSONObject:
        ts = unix_ts_ms // 1000  # wire nonce is integer seconds (wire spec §3.4)
        hash_to_sign = backend.make_get_payment_details_message(
            master_pkey=user_ctx.master_key.verify_key,
            request_at=base.datetime_from_unix_seconds(ts),
            limit=limit,
            before=before,
        )
        request_body = {
            'master_pkey': bytes(user_ctx.master_key.verify_key).hex(),
            'master_sig': bytes(user_ctx.master_key.sign(hash_to_sign).signature).hex(),
            'ts': ts,
            'limit': limit,
            'before': before,
        }
        server.time_now = lambda: unix_ts_ms / 1000.0
        response = ctx.flask_client.post('/get_payment_details', json=request_body)
        server.time_now = lambda: time.time()
        response_json = response.json
        assert response_json is not None
        return response_json

    def add_payment(tx: TestTx, user_ctx: TestUserCtx, ctx: TestingContext) -> int:
        add_pro_payment_tx = backend.UserPaymentTransaction()
        add_pro_payment_tx.provider = base.PaymentProvider.GooglePlayStore
        add_pro_payment_tx.google_payment_token = tx.purchase_token
        add_pro_payment_tx.google_order_id = tx.order_id
        add_pro_payment_tx.payment_id = backend.payment_id_from_user_tx(add_pro_payment_tx)
        payment_hash_to_sign = backend.make_add_pro_payment_message(
            master_pkey=user_ctx.master_key.verify_key,
            rotating_pkey=user_ctx.rotating_key.verify_key,
            payment_tx=add_pro_payment_tx,
        )
        request_body = {
            'master_pkey': bytes(user_ctx.master_key.verify_key).hex(),
            'rotating_pkey': bytes(user_ctx.rotating_key.verify_key).hex(),
            'master_sig': bytes(user_ctx.master_key.sign(payment_hash_to_sign).signature).hex(),
            'rotating_sig': bytes(user_ctx.rotating_key.sign(payment_hash_to_sign).signature).hex(),
            'payment_tx': {'provider': add_pro_payment_tx.provider.value, 'payment_id': add_pro_payment_tx.payment_id},
        }

        server.time_now = lambda: tx.event_ms / 1000.0
        ctx.flask_client.post('/add_pro_payment', json=request_body)
        server.time_now = lambda: time.time()

        return base.unix_ms_from_datetime(base.round_datetime_to_next_day(base.datetime_from_unix_ms(tx.event_ms)))

    def backend_expire_payments_at_end_of_day(event_ms: int, assert_success: bool = False):
        boundary_ms = base.unix_ms_from_datetime(
            backend.round_datetime_to_next_day_with_provider_testing_support(
                payment_provider=base.PaymentProvider.GooglePlayStore, at=base.datetime_from_unix_ms(event_ms)
            )
        )
        end_of_day_ts_ms = event_ms + boundary_ms
        with ctx.connection() as conn:
            expire_result = backend.expire_payments_revocations_and_users(
                conn=conn, now=base.datetime_from_unix_ms(end_of_day_ts_ms)
            )
        if assert_success:
            assert expire_result.success

    """
    Testing Assert Utility Functions
    """

    def assert_clean_state(ctx: TestingContext):
        with ctx.connection() as conn:
            assert not backend.get_unredeemed_payments_list(conn)
            assert not backend.get_payments_list(conn)
            assert not backend.get_revocations_list(conn)

    def assert_has_unredeemed_payment(
        tx: TestTx, plan: base.ProPlan, platform_refund_expires_at: int, ctx: TestingContext
    ):
        with ctx.connection() as conn:
            unredeemed_payments = backend.get_unredeemed_payments_list(conn)
            found = False
            for unredeemed_payment in unredeemed_payments:
                if unredeemed_payment.google_order_id == tx.order_id:
                    found = True
                    assert isinstance(unredeemed_payment, backend.PaymentRow)
                    assert unredeemed_payment.master_pkey is None
                    assert derived_status(unredeemed_payment) == base.PaymentStatus.Unredeemed
                    assert unredeemed_payment.plan == plan
                    assert unredeemed_payment.payment_provider == base.PaymentProvider.GooglePlayStore
                    assert unredeemed_payment.redeemed_at is None
                    assert unredeemed_payment.expires_at == base.datetime_from_unix_ms(tx.expires_at)
                    assert unredeemed_payment.grace_period == datetime.timedelta(0)
                    assert unredeemed_payment.platform_refund_expires_at == base.datetime_from_unix_ms(
                        platform_refund_expires_at
                    )
                    assert unredeemed_payment.revoked_at is None
                    assert unredeemed_payment.apple == backend.AppleTransaction()
                    assert unredeemed_payment.google_payment_token == tx.purchase_token
                    assert unredeemed_payment.google_order_id == tx.order_id
            assert found

    def assert_has_payment(
        tx: TestTx,
        plan: base.ProPlan,
        redeemed_ts_ms_rounded: int,
        platform_refund_expires_at: int,
        user_ctx: TestUserCtx,
        ctx: TestingContext,
    ):
        with ctx.connection() as conn:
            payments = backend.get_payments_list(conn)
            assert len(payments) == user_ctx.payments
            payment = payments[-1]
            assert isinstance(payment, backend.PaymentRow)
            assert payment.master_pkey == bytes(user_ctx.master_key.verify_key)
            assert derived_status(payment) == base.PaymentStatus.Redeemed
            assert payment.plan == plan
            assert payment.payment_provider == base.PaymentProvider.GooglePlayStore
            assert payment.redeemed_at is not None and payment.redeemed_at == base.datetime_from_unix_ms(
                redeemed_ts_ms_rounded
            )
            assert payment.expires_at == base.datetime_from_unix_ms(tx.expires_at)
            assert payment.grace_period == base.DEFAULT_GOOGLE_GRACE_PERIOD
            assert payment.platform_refund_expires_at == base.datetime_from_unix_ms(platform_refund_expires_at)
            assert payment.revoked_at is None
            assert payment.apple == backend.AppleTransaction()
            assert payment.google_payment_token == tx.purchase_token
            assert payment.google_order_id == tx.order_id

    def assert_has_user(tx: TestTx, user_ctx: TestUserCtx, ctx: TestingContext):
        with ctx.connection() as conn:
            user = backend.get_user(conn=conn, master_pkey=user_ctx.master_key.verify_key)
            assert isinstance(user, backend.UserRow)
            assert user.master_pkey == bytes(user_ctx.master_key.verify_key)
            # The user points at a live current generation with a populated 32-byte token. We do NOT
            # assert a generation count here: a generation is an epoch (item 3), reused across payments and
            # rolled only on revocation, so the count is scenario-dependent, not one-per-payment. The
            # current generation must be one of the user's, and (for these non-revoked scenarios) live.
            user_gen_ids = {row[0] for row in db.query(conn, "SELECT id FROM generations WHERE user_id = %s", user.id)}
            assert user.current_generation_id in user_gen_ids
            assert not backend.is_generation_revoked(
                conn, user.current_generation_id, base.datetime_from_unix_ms(tx.event_ms)
            )
            assert len(user.token) == backend.BLAKE2B_DIGEST_SIZE
            assert user.expires_at == base.datetime_from_unix_ms(tx.expires_at) + base.DEFAULT_GOOGLE_GRACE_PERIOD

    def assert_payment_details(
        tx: TestTx,
        pro_status: server.UserProStatus,
        payment_status: base.PaymentStatus,
        auto_renew: bool,
        grace_duration: datetime.timedelta,
        redeemed_ts_ms_rounded: int,
        platform_refund_expires_at: int,
        user_ctx: TestUserCtx,
        ctx: TestingContext,
        unix_ts_ms: int | None = None,
        revoke_unix_ts_ms: int | None = None,
    ):
        # The wire is integer seconds (upstream provider instants — here `revoked_ts` — are floats);
        # the harness/provider fixtures below are ms. `to_s` mirrors the server's floor-to-seconds so
        # a ms fixture compares against the emitted integer-seconds value.
        def to_s(ms):
            return base.unix_seconds_from_datetime(base.datetime_from_unix_ms(ms))

        status = get_pro_status(user_ctx=user_ctx, ctx=ctx, unix_ts_ms=unix_ts_ms if unix_ts_ms else tx.event_ms)
        err = base.ErrorSink()
        result = base.json_dict_require_obj(status, "result", err)
        res_auto_renewing = base.json_dict_require_bool(result, "auto_renewing", err)
        res_expiry_ts = base.json_dict_require_int(result, "expiry_ts", err)
        res_grace_period_duration = base.json_dict_require_int(result, "grace_period_duration", err)
        res_pro_status = base.json_dict_require_str_coerce_to_enum(result, "user_status", server.UserProStatus, err)
        res_latest = base.json_dict_require_obj(result, "latest_payment", err)
        assert not err.has(), status
        assert res_auto_renewing == auto_renew, json.dumps(result, indent=1)
        revoked = payment_status == base.PaymentStatus.Revoked
        if revoked:
            assert revoke_unix_ts_ms is not None
            assert res_expiry_ts == to_s(revoke_unix_ts_ms)
        else:
            expires_at = res_expiry_ts
            if res_auto_renewing:
                expires_at -= res_grace_period_duration
            assert expires_at == to_s(tx.expires_at), json.dumps(result, indent=1)
        assert res_pro_status == pro_status
        item = res_latest
        assert isinstance(item, dict)
        item_expiry_ts = base.json_dict_require_int(item, "expiry_ts", err)
        item_payment_id = base.json_dict_require_str(item, "payment_id", err)
        item_grace_duration = base.json_dict_require_int(item, "grace_period_duration", err)
        item_payment_provider = base.json_dict_require_str_coerce_to_enum(
            item, "payment_provider", base.PaymentProvider, err
        )
        item_platform_refund_expiry_ts = base.json_dict_require_int(item, "platform_refund_expiry_ts", err)
        item_redeemed_ts = base.json_dict_require_int(item, "redeemed_ts", err)
        item_revoked_ts = base.json_dict_require_float(item, "revoked_ts", err)
        item_status = base.json_dict_require_str_coerce_to_enum(item, "status", base.PaymentStatus, err)
        assert not err.has()
        assert item_expiry_ts == to_s(tx.expires_at), res_latest
        # Google `payment_id` is the opaque `token|order_id` composite (§3.5).
        assert item_payment_id == f'{tx.purchase_token}|{tx.order_id}'
        assert item_grace_duration == base.seconds_from_timedelta(grace_duration)
        assert item_payment_provider == base.PaymentProvider.GooglePlayStore
        assert item_platform_refund_expiry_ts == to_s(platform_refund_expires_at)
        assert item_redeemed_ts == to_s(redeemed_ts_ms_rounded)
        assert (
            item_revoked_ts == 0.0
            if not revoked
            else base.unix_seconds_float_from_datetime(base.datetime_from_unix_ms(tx.event_ms))
        )
        assert item_status == payment_status

    """
    Testing Common Action Functions
    """

    def test_make_purchase(
        purchase: TestScenario, plan: base.ProPlan, ctx: TestingContext, check_payment_is_unredeemed: bool = False
    ):
        tx = test_notification(purchase, ctx)
        platform_refund_expiry_unix_tx_ms = tx.event_ms + base.MILLISECONDS_IN_DAY * 2
        if check_payment_is_unredeemed:
            assert_has_unredeemed_payment(
                tx=tx, plan=plan, platform_refund_expires_at=platform_refund_expiry_unix_tx_ms, ctx=ctx
            )
        return tx, platform_refund_expiry_unix_tx_ms

    def test_make_purchase_and_claim_payment(
        purchase: TestScenario, plan: base.ProPlan, user_ctx: TestUserCtx, ctx: TestingContext
    ):
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(purchase=purchase, plan=plan, ctx=ctx)
        # Redeem subscription payment
        redeemed_ts_ms_rounded = add_payment(tx=tx, user_ctx=user_ctx, ctx=ctx)
        with ctx.connection() as conn:
            assert not backend.get_unredeemed_payments_list(conn)

        user_ctx.payments += 1
        assert_has_payment(
            tx=tx,
            plan=plan,
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)
        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        return tx, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User cancels
        3. User un-cancels
        4. User refunds
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1759723091078',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-06T03:58:10.981Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3354-3745-5570-25336',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-06T04:03:10.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336',
                    }
                ],
            },
        )
        cancel = TestScenario(  # 2. User cancels
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1759723188437',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-06T03:58:10.981Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_CANCELED',
                'latestOrderId': 'GPA.3354-3745-5570-25336',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-06T03:59:48.074Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-06T04:03:10.613Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336',
                    }
                ],
            },
        )
        uncancel = TestScenario(  # 3. User uncancels
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1759723199349',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 7,
                    'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-06T03:58:10.981Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3354-3745-5570-25336',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-06T04:03:10.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336',
                    }
                ],
            },
        )
        refund = TestScenario(  # 4. User refunds
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1759723392088',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 12,
                    'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-06T03:58:10.981Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3354-3745-5570-25336',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-06T04:03:11.808Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User cancels"""
        test_notification(cancel, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        """3. User un-cancels"""
        test_notification(uncancel, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        """4. User refunds"""
        refund_tx = test_notification(refund, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Revoked,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            revoke_unix_ts_ms=refund_tx.event_ms,
            # +1s (not +1ms): the wire nonce is integer seconds, so a sub-second margin
            # past expiry floors away — "just past expiry" is one whole second.
            unix_ts_ms=refund_tx.event_ms + 1000,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User enters grace period as subscription fails to renew
        3. User renews, exiting grace period
        4. User cancels (probably dont need this)
        5. Expires (probably dont need this)
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760056968727',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3375-6103-0197-44778',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:47:48.269Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778',
                    }
                ],
            },
        )
        grace = TestScenario(  # 2. User enters grace period as subscription fails to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760057276700',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3375-6103-0197-44778..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:52:48.269Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778',
                    }
                ],
            },
        )
        renew_after_grace = TestScenario(  # 3. User renews, exiting grace period
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760057286988',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3375-6103-0197-44778..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:52:48.269Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778..0',
                    }
                ],
            },
        )
        cancel = TestScenario(  # 4. User cancels (probably dont need this)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760057334978',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_CANCELED',
                'latestOrderId': 'GPA.3375-6103-0197-44778..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T00:48:53.285Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:52:48.269Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778..0',
                    }
                ],
            },
        )
        expire = TestScenario(  # 5. Expires (probably dont need this)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760057579735',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3375-6103-0197-44778..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T00:48:53.285Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:52:48.269Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        # Expire payments at the EOD of the resubscribe expiry_ts (note the extend expiry_ts from the grace period tx)
        backend_expire_payments_at_end_of_day(event_ms=tx_grace.event_ms, assert_success=True)

        # Now that payments up to the expiry time has been expired, this user's status should be expired (we need to also time-travel the clock past the grace period they were allocated)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """3. User renews"""
        # NOTE: We don't check that the payment is unredeemed because this renewal will get
        # auto-redeemed due to "Google" sending the notification before the auto-redeem deadline
        # which is defined as the any time before the end of account hold.
        tx_renew, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew_after_grace, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1  # Auto-redeem, so 1 extra payment was done

        """4. User cancels"""
        tx_cancel = test_notification(cancel, ctx)
        assert_payment_details(
            tx=tx_renew,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx_renew.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_cancel.event_ms,
        )

        """5. Subscription expires"""
        # status isnt expired yet as the rounded expiry time hasnt happend and the sweeper hasn't run, so there should be no status change
        tx_expire = test_notification(expire, ctx)
        assert_payment_details(
            tx=tx_renew,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx_renew.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        backend_expire_payments_at_end_of_day(event_ms=tx_expire.event_ms, assert_success=True)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_renew,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx_renew.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_expire.event_ms,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User renews 1-month subscription
        3. User renews 1-month subscription
        4. User cancels 1-month subscription
        5. Subscription expires
        6. User resubscribes
        7. User fails to renew, entering grace period
        8. User fails to renew, entering account hold
        9. User fails to renew, cancelling and expiring
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054059175',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3309-4032-8192-54127',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-09T23:59:18.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127',
                    }
                ],
            },
        )
        renew_1 = TestScenario(  # 2. User renews 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054493266',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3309-4032-8192-54127..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:04:18.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127..0',
                    }
                ],
            },
        )
        renew_2 = TestScenario(  # 3. User renews 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054662501',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3309-4032-8192-54127..1',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:09:18.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127..1',
                    }
                ],
            },
        )
        cancel = TestScenario(  # 4. User cancels 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054819931',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_CANCELED',
                'latestOrderId': 'GPA.3309-4032-8192-54127..1',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T00:06:59.489Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:09:18.613Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127..1',
                    }
                ],
            },
        )
        expire = TestScenario(  # 5. Subscription expires
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054959804',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3309-4032-8192-54127..1',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T00:06:59.489Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:09:18.613Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127..1',
                    }
                ],
            },
        )
        resubscribe = TestScenario(  # 6. User purchases (SUBSCRIPTION_PURCHASED)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760055149918',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3326-4415-9310-90534',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:17:29.313Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )
        grace = TestScenario(  # 7. User fail to renew, entering grace period (SUBSCRIPTION_IN_GRACE_PERIOD)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760055456738',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3326-4415-9310-90534..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:22:29.313Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )
        hold = TestScenario(  # 8. User fails to renew, entering account hold
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760055750572',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 5,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ON_HOLD',
                'latestOrderId': 'GPA.3326-4415-9310-90534..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:22:29.313Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )
        fail_after_hold_a = TestScenario(  # 9. User fails to renew, cancelling and expiring
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760056350982',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3326-4415-9310-90534..0',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:32:30.758Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )
        fail_after_hold_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760056353213',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3326-4415-9310-90534..0',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:32:30.758Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User renews"""
        # NOTE: Auto-redeem kicks in so claim is automatic
        test_make_purchase(purchase=renew_1, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False)
        user_ctx.payments += 1

        """3. User renews"""
        # NOTE: Auto-redeem kicks in so claim is automatic
        tx_renew_2, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew_2, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        """4. User cancels"""
        # NOTE: Auto-redeem uses the unredeemed timestamp rounded up whereas if you claim it manually, it uses the server's time
        test_notification(cancel, ctx)
        assert_payment_details(
            tx=tx_renew_2,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx_renew_2.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        """5. Subscription expires"""
        tx_expire = test_notification(expire, ctx)
        # status isnt expired yet as the rounded expiry time hasn't happened and the sweeper hasn't run, so there should be no status change
        assert_payment_details(
            tx=tx_renew_2,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx_renew_2.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        # Expire payments
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        backend_expire_payments_at_end_of_day(event_ms=tx_expire.event_ms, assert_success=True)
        assert_payment_details(
            tx=tx_renew_2,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx_renew_2.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_expire.event_ms,
        )

        """6. User purchased (SUBSCRIPTION_PURCHASED)"""
        tx_resubscribe, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = (
            test_make_purchase_and_claim_payment(
                purchase=resubscribe, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
            )
        )

        """7. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_resubscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,  # TODO: This is not a good design, should not use real-time timestamps
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        # Now that payments up to the expiry time has been expired, this user's status should be expired
        backend_expire_payments_at_end_of_day(event_ms=tx_grace.event_ms, assert_success=True)
        assert_payment_details(
            tx=tx_resubscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """8. User fails to renew (enter account hold)"""
        test_notification(hold, ctx)
        assert_payment_details(
            tx=tx_resubscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """9. User fails to renew, cancelling and expiring"""
        test_notification(fail_after_hold_a, ctx)
        test_notification(fail_after_hold_b, ctx)
        assert_payment_details(
            tx=tx_resubscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User enters grace period as they fail to renew
        3. User cancels, exiting grace period
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058070950',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'ehkfchpacbicpfpnkedempao.AO-J1OxW86ZtW-xdq2l1Xo5HkpOC2DvuqCL6xKJrMrIib5URdpVL6n0NzbSMkwyOjK6_CR2A9myRvVVqIodIxuSsEFypEByw57XoLN3NKDJPiGnK4zvodQg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:01:10.821Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3385-3546-4929-55699',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:06:10.406Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-3546-4929-55699',
                    }
                ],
            },
        )
        grace = TestScenario(  # 2. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058375847',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'ehkfchpacbicpfpnkedempao.AO-J1OxW86ZtW-xdq2l1Xo5HkpOC2DvuqCL6xKJrMrIib5URdpVL6n0NzbSMkwyOjK6_CR2A9myRvVVqIodIxuSsEFypEByw57XoLN3NKDJPiGnK4zvodQg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:01:10.821Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3385-3546-4929-55699..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:11:10.406Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-3546-4929-55699',
                    }
                ],
            },
        )
        cancel_after_grace_a = TestScenario(  # 3. User cancels, exiting grace period
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058385564',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'ehkfchpacbicpfpnkedempao.AO-J1OxW86ZtW-xdq2l1Xo5HkpOC2DvuqCL6xKJrMrIib5URdpVL6n0NzbSMkwyOjK6_CR2A9myRvVVqIodIxuSsEFypEByw57XoLN3NKDJPiGnK4zvodQg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:01:10.821Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3385-3546-4929-55699..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T01:06:25.090Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:06:25.090Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-3546-4929-55699',
                    }
                ],
            },
        )
        cancel_after_grace_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058388512',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'ehkfchpacbicpfpnkedempao.AO-J1OxW86ZtW-xdq2l1Xo5HkpOC2DvuqCL6xKJrMrIib5URdpVL6n0NzbSMkwyOjK6_CR2A9myRvVVqIodIxuSsEFypEByw57XoLN3NKDJPiGnK4zvodQg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:01:10.821Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3385-3546-4929-55699..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T01:06:25.090Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:06:25.090Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-3546-4929-55699',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        backend_expire_payments_at_end_of_day(event_ms=tx_grace.event_ms, assert_success=True)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """3. User cancels, exiting grace period"""
        test_notification(cancel_after_grace_a, ctx)
        test_notification(cancel_after_grace_b, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User enters grace period as they fail to renew
        3. User enters account hold as they continue to fail to renew
        4. User cancels
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058562006',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3385-4424-2558-38000',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:14:21.418Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )
        grace = TestScenario(  # 2. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058876825',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3385-4424-2558-38000..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:19:21.418Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )
        hold = TestScenario(  # 3. User enters account hold as they continue to fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760059162455',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 5,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ON_HOLD',
                'latestOrderId': 'GPA.3385-4424-2558-38000..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:19:21.418Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )
        cancel_after_hold_a = TestScenario(  # 4. User cancels
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760059762429',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3385-4424-2558-38000..0',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:29:22.310Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )
        cancel_after_hold_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760059764910',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3385-4424-2558-38000..0',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:29:22.310Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User resubscribed"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        # Expire payments at the EOD of the resubscribe expiry_ts (not the extend expiry_ts from the grace period tx)
        backend_expire_payments_at_end_of_day(event_ms=tx_grace.event_ms, assert_success=True)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """3. User fails to renew (enter account hold)"""
        test_notification(hold, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """4. User cancels"""
        test_notification(cancel_after_hold_a, ctx)
        test_notification(cancel_after_hold_b, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User enters grace period as they fail to renew
        3. User enters account hold as they continue to fail to renew
        4. User renews, exiting account hold
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760063571318',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'fiamkojbeobfecknhdfhfgdk.AO-J1OxpMbHczoHY4AbpJsd9gwqzTs-_9zpEGMedCUMXkjrvBgTVdNyl0eowweuNYlVYTR7_D1NN_LYO8U8ScP8cnqbzZ5qB_TrWWQtXif7Es6Xp2PEE1SI',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:32:51.206Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3340-4002-2060-79596',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:37:50.765Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-4002-2060-79596',
                    }
                ],
            },
        )
        grace = TestScenario(  # 2. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760063877258',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'fiamkojbeobfecknhdfhfgdk.AO-J1OxpMbHczoHY4AbpJsd9gwqzTs-_9zpEGMedCUMXkjrvBgTVdNyl0eowweuNYlVYTR7_D1NN_LYO8U8ScP8cnqbzZ5qB_TrWWQtXif7Es6Xp2PEE1SI',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:32:51.206Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3340-4002-2060-79596..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:42:50.765Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-4002-2060-79596',
                    }
                ],
            },
        )
        hold = TestScenario(  # 3. User enters account hold as they continue to fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064172032',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 5,
                    'purchaseToken': 'fiamkojbeobfecknhdfhfgdk.AO-J1OxpMbHczoHY4AbpJsd9gwqzTs-_9zpEGMedCUMXkjrvBgTVdNyl0eowweuNYlVYTR7_D1NN_LYO8U8ScP8cnqbzZ5qB_TrWWQtXif7Es6Xp2PEE1SI',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:32:51.206Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ON_HOLD',
                'latestOrderId': 'GPA.3340-4002-2060-79596..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:42:50.765Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-4002-2060-79596',
                    }
                ],
            },
        )
        renew = TestScenario(  # 4. User renews, exiting account hold (SUBSCRIPTION_RECOVERED)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064181132',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 1,
                    'purchaseToken': 'fiamkojbeobfecknhdfhfgdk.AO-J1OxpMbHczoHY4AbpJsd9gwqzTs-_9zpEGMedCUMXkjrvBgTVdNyl0eowweuNYlVYTR7_D1NN_LYO8U8ScP8cnqbzZ5qB_TrWWQtXif7Es6Xp2PEE1SI',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:32:51.206Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3340-4002-2060-79596..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:48:00.760Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-4002-2060-79596..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User resubscribed"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        backend_expire_payments_at_end_of_day(event_ms=tx_grace.event_ms, assert_success=True)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """3. User fails to renew (enter account hold)"""
        test_notification(hold, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """4. User renews (SUBSCRIPTION_RECOVERED)"""
        # NOTE: Auto-redeem kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_payment(
            tx=tx,
            plan=base.ProPlan.OneMonth,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User changes to 3-month plan
        3. User renews
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064664489',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'djmaggipjlbmnncfpnaiecgp.AO-J1OzsodQ6LAqNSpZq4F8pvQCko4BhEvKfI8x4JU95p3v0lVVEIis2J-L8WwifcHwYGuCl0fZ4Tjby9Cyig9R5NUYVGqq156Gezco_-Dbw-pyHAZWVM3E',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:51:04.303Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3361-2060-7612-01550',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:56:03.854Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3361-2060-7612-01550',
                    }
                ],
            },
        )
        change_plan_a = TestScenario(  # 2. User changes to 3-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064707992',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'nbcpbihedkkbpihikkahjhhn.AO-J1OzYWzZdp7VGTVIrZH_WBoLTIBlRN8F_LB5Pu3DK0Hk4GtZzcZzS6tRsVLBLUNH19SxsI6Yq4DFMvyh-SHGT35BXUPg_jufa03is3zDblMMA_FWSwQ4',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:51:47.820Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3346-9218-7706-30541',
                'linkedPurchaseToken': 'djmaggipjlbmnncfpnaiecgp.AO-J1OzsodQ6LAqNSpZq4F8pvQCko4BhEvKfI8x4JU95p3v0lVVEIis2J-L8WwifcHwYGuCl0fZ4Tjby9Cyig9R5NUYVGqq156Gezco_-Dbw-pyHAZWVM3E',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:56:07.125Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3346-9218-7706-30541',
                    }
                ],
            },
        )
        change_plan_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064712021',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'djmaggipjlbmnncfpnaiecgp.AO-J1OzsodQ6LAqNSpZq4F8pvQCko4BhEvKfI8x4JU95p3v0lVVEIis2J-L8WwifcHwYGuCl0fZ4Tjby9Cyig9R5NUYVGqq156Gezco_-Dbw-pyHAZWVM3E',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:51:04.303Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3361-2060-7612-01550',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:51:47.692Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3361-2060-7612-01550',
                    }
                ],
            },
        )
        renew = TestScenario(  # 3. User renews
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065012245',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'nbcpbihedkkbpihikkahjhhn.AO-J1OzYWzZdp7VGTVIrZH_WBoLTIBlRN8F_LB5Pu3DK0Hk4GtZzcZzS6tRsVLBLUNH19SxsI6Yq4DFMvyh-SHGT35BXUPg_jufa03is3zDblMMA_FWSwQ4',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:51:47.820Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3346-9218-7706-30541..0',
                'linkedPurchaseToken': 'djmaggipjlbmnncfpnaiecgp.AO-J1OzsodQ6LAqNSpZq4F8pvQCko4BhEvKfI8x4JU95p3v0lVVEIis2J-L8WwifcHwYGuCl0fZ4Tjby9Cyig9R5NUYVGqq156Gezco_-Dbw-pyHAZWVM3E',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:06:07.125Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3346-9218-7706-30541..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User changes to 3-month plan"""
        test_make_purchase_and_claim_payment(
            purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
        )
        test_notification(change_plan_b, ctx)

        """3. User renews"""
        # NOTE: Auto-renew kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.ThreeMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User changes to 3-month plan
        3. User enters grace period as they fail to renew
        4. User renews, exiting grace period
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065659150',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:39.032Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3361-4036-2635-52589',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:12:38.652Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3361-4036-2635-52589',
                    }
                ],
            },
        )
        change_plan_a = TestScenario(  # 2. User changes to 3-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065678442',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'cmmdicdefdehlffhmchedffo.AO-J1OwdBoWT8t_cCjOY_aa1RcIG6QK31BNBXtXtrNIAqpDQg9w_po6fRIv1vqYPxQFXsay8LjarIwmtamkt4U8moGkk-oq5yLXOUbH8yzpt2JoXhqD9C_U',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:58.213Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3307-6442-0359-63641',
                'linkedPurchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:12:41.697Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-6442-0359-63641',
                    }
                ],
            },
        )
        change_plan_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065680270',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:39.032Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3361-4036-2635-52589',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:07:58.101Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3361-4036-2635-52589',
                    }
                ],
            },
        )
        grace = TestScenario(  # 3. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065966693',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'cmmdicdefdehlffhmchedffo.AO-J1OwdBoWT8t_cCjOY_aa1RcIG6QK31BNBXtXtrNIAqpDQg9w_po6fRIv1vqYPxQFXsay8LjarIwmtamkt4U8moGkk-oq5yLXOUbH8yzpt2JoXhqD9C_U',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:58.213Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3307-6442-0359-63641..0',
                'linkedPurchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:17:41.697Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-6442-0359-63641',
                    }
                ],
            },
        )
        renew = TestScenario(  # 4. User renews, exiting grace period
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065984697',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'cmmdicdefdehlffhmchedffo.AO-J1OwdBoWT8t_cCjOY_aa1RcIG6QK31BNBXtXtrNIAqpDQg9w_po6fRIv1vqYPxQFXsay8LjarIwmtamkt4U8moGkk-oq5yLXOUbH8yzpt2JoXhqD9C_U',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:58.213Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3307-6442-0359-63641..0',
                'linkedPurchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:22:41.697Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-6442-0359-63641..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User changes to 3-month plan"""
        tx_change_plan, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = (
            test_make_purchase_and_claim_payment(
                purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
            )
        )
        test_notification(change_plan_b, ctx)

        """3. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        backend_expire_payments_at_end_of_day(event_ms=tx_grace.event_ms, assert_success=True)

        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """4. User renews"""
        # NOTE: Auto-renew kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.ThreeMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User changes to 3-month plan
        3. User enters grace period as they fail to renew
        4. User enters account hold as they continue to fail to renew
        5. User renews, exiting account hold
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760066883333',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:03.223Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3360-4209-1350-91491',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:33:02.513Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3360-4209-1350-91491',
                    }
                ],
            },
        )
        change_plan_a = TestScenario(  # 2. User changes to 3-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760066932029',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'dilmafpdglapmhabknlhjgje.AO-J1OxX-ApsyARxtSAGIzIXOlhvpK6OCxjuqC5DJzPrO51Os6gHNZq3gPgMaaZc-dsJ-QwYj3oa4PP49HT-ZXoptya257BXC7ggHtIbdB7fnLXatIkETws',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:51.780Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3385-9037-2688-17153',
                'linkedPurchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:33:04.239Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3385-9037-2688-17153',
                    }
                ],
            },
        )
        change_plan_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760066934397',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:03.223Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3360-4209-1350-91491',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:28:51.636Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3360-4209-1350-91491',
                    }
                ],
            },
        )
        grace = TestScenario(  # 3. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760067219187',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'dilmafpdglapmhabknlhjgje.AO-J1OxX-ApsyARxtSAGIzIXOlhvpK6OCxjuqC5DJzPrO51Os6gHNZq3gPgMaaZc-dsJ-QwYj3oa4PP49HT-ZXoptya257BXC7ggHtIbdB7fnLXatIkETws',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:51.780Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3385-9037-2688-17153..0',
                'linkedPurchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:38:04.239Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3385-9037-2688-17153',
                    }
                ],
            },
        )
        hold = TestScenario(  # 4. User enters account hold as they continue to fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760067515427',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 5,
                    'purchaseToken': 'dilmafpdglapmhabknlhjgje.AO-J1OxX-ApsyARxtSAGIzIXOlhvpK6OCxjuqC5DJzPrO51Os6gHNZq3gPgMaaZc-dsJ-QwYj3oa4PP49HT-ZXoptya257BXC7ggHtIbdB7fnLXatIkETws',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:51.780Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ON_HOLD',
                'latestOrderId': 'GPA.3385-9037-2688-17153..0',
                'linkedPurchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:38:04.239Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3385-9037-2688-17153',
                    }
                ],
            },
        )
        renew = TestScenario(  # 5. User renews, exiting account hold
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760067523842',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 1,
                    'purchaseToken': 'dilmafpdglapmhabknlhjgje.AO-J1OxX-ApsyARxtSAGIzIXOlhvpK6OCxjuqC5DJzPrO51Os6gHNZq3gPgMaaZc-dsJ-QwYj3oa4PP49HT-ZXoptya257BXC7ggHtIbdB7fnLXatIkETws',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:51.780Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3385-9037-2688-17153..0',
                'linkedPurchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:48:43.405Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3385-9037-2688-17153..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User changes to 3-month plan"""
        tx_change_plan, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = (
            test_make_purchase_and_claim_payment(
                purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
            )
        )
        test_notification(change_plan_b, ctx)

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        backend_expire_payments_at_end_of_day(event_ms=tx_grace.event_ms, assert_success=True)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """3. User fails to renew (enter account hold)"""
        test_notification(hold, ctx)
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.timedelta_from_ms(test_product_details.grace_period.milliseconds),
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + test_product_details.grace_period.milliseconds,
        )

        """4. User renews"""
        # NOTE: Auto-renew kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.ThreeMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User changes to 3-month plan
        3. User changes to 1-month plan
        4. User renews
        """

        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068190568',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'akknlgeihdpojligdpliahkd.AO-J1OylF_FKqn-mgcFGEP0uPJ3m81pAyz65LNRR2FA7zTmxDLqhzyqAFVlWI_kZ9UKJ6WVTSgCOL8VuyRYw3zjBD_WicdU00dywAxNEvA8RxOEBgt8_A4c',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:49:50.459Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3380-4949-2236-27006',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:54:50.029Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3380-4949-2236-27006',
                    }
                ],
            },
        )
        change_plan_a = TestScenario(  # 2. User changes to 3-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068218921',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'ghmgjhcnkdnbhloomlbkdnkn.AO-J1OwyF695Pxv_uwqpulIkOeL5B21_Q1qKNGqVrD7-_Sm4_dkN9pcpRQC1WSlyT32YweRIbuoLIJzJ2VhfbY9VUGyD801SZSiUmRUf62WF1MKu4PzSj-Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:50:18.696Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3307-0514-1298-32110',
                'linkedPurchaseToken': 'akknlgeihdpojligdpliahkd.AO-J1OylF_FKqn-mgcFGEP0uPJ3m81pAyz65LNRR2FA7zTmxDLqhzyqAFVlWI_kZ9UKJ6WVTSgCOL8VuyRYw3zjBD_WicdU00dywAxNEvA8RxOEBgt8_A4c',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:54:54.238Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-0514-1298-32110',
                    }
                ],
            },
        )
        change_plan_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068221351',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'akknlgeihdpojligdpliahkd.AO-J1OylF_FKqn-mgcFGEP0uPJ3m81pAyz65LNRR2FA7zTmxDLqhzyqAFVlWI_kZ9UKJ6WVTSgCOL8VuyRYw3zjBD_WicdU00dywAxNEvA8RxOEBgt8_A4c',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:49:50.459Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3380-4949-2236-27006',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:50:18.593Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3380-4949-2236-27006',
                    }
                ],
            },
        )
        change_plan_back_a = TestScenario(  # 3. User changes to 1-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068282443',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'ndpndadhkkmikonjoplconhp.AO-J1OzO9SK-_SBR9g-TCmf6CodhY-D57xpbXWFbGSp90W49E04JmmJNkjTAYfJXj1C7p6nfo7iHtBTU9SPoG2ov0CCU5b9URNQZfkuozZzdsYWnCe5GFps',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:51:22.253Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3306-9365-6055-58193',
                'linkedPurchaseToken': 'ghmgjhcnkdnbhloomlbkdnkn.AO-J1OwyF695Pxv_uwqpulIkOeL5B21_Q1qKNGqVrD7-_Sm4_dkN9pcpRQC1WSlyT32YweRIbuoLIJzJ2VhfbY9VUGyD801SZSiUmRUf62WF1MKu4PzSj-Q',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:54:59.698Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3306-9365-6055-58193',
                    }
                ],
            },
        )
        change_plan_back_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068283977',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'ghmgjhcnkdnbhloomlbkdnkn.AO-J1OwyF695Pxv_uwqpulIkOeL5B21_Q1qKNGqVrD7-_Sm4_dkN9pcpRQC1WSlyT32YweRIbuoLIJzJ2VhfbY9VUGyD801SZSiUmRUf62WF1MKu4PzSj-Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:50:18.696Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3307-0514-1298-32110',
                'linkedPurchaseToken': 'akknlgeihdpojligdpliahkd.AO-J1OylF_FKqn-mgcFGEP0uPJ3m81pAyz65LNRR2FA7zTmxDLqhzyqAFVlWI_kZ9UKJ6WVTSgCOL8VuyRYw3zjBD_WicdU00dywAxNEvA8RxOEBgt8_A4c',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:51:22.124Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-0514-1298-32110',
                    }
                ],
            },
        )
        renew = TestScenario(  # 4. User renews
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068505712',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'ndpndadhkkmikonjoplconhp.AO-J1OzO9SK-_SBR9g-TCmf6CodhY-D57xpbXWFbGSp90W49E04JmmJNkjTAYfJXj1C7p6nfo7iHtBTU9SPoG2ov0CCU5b9URNQZfkuozZzdsYWnCe5GFps',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:51:22.253Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3306-9365-6055-58193..0',
                'linkedPurchaseToken': 'ghmgjhcnkdnbhloomlbkdnkn.AO-J1OwyF695Pxv_uwqpulIkOeL5B21_Q1qKNGqVrD7-_Sm4_dkN9pcpRQC1WSlyT32YweRIbuoLIJzJ2VhfbY9VUGyD801SZSiUmRUf62WF1MKu4PzSj-Q',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:59:59.698Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3306-9365-6055-58193..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User changes to 3-month plan"""
        tx_change_plan, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = (
            test_make_purchase_and_claim_payment(
                purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
            )
        )
        test_notification(change_plan_b, ctx)

        """3. User changes to 1-month plan"""
        tx_change_plan, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = (
            test_make_purchase_and_claim_payment(
                purchase=change_plan_back_a, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
            )
        )
        test_notification(change_plan_back_b, ctx)

        """4. User renews"""
        # NOTE: Auto-renew kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=base.unix_ms_from_datetime(
                backend.to_redeemed_at(base.datetime_from_unix_ms(tx.event_ms))
            ),
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 3-month subscription
        2. Renews
        3. User cancels
        3. Expires
        """

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 12-month subscription
        2. Renews
        3. User cancels
        3. Expires
        """

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 3-month subscription
        2. User changes to 1-month subscription
        3. Renews
        """

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 12-month subscription
        2. User changes to 1-month subscription
        3. Renews
        """

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. Developer refunds subscription (removing entitlement)
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760069459190',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'aciongiofnlcagplnndcfhnf.AO-J1OyRJ1NXBfFEzDi14GkTdi6d1iJ5XudWH7CY5pMziU2IExCSZHIkc0LXnsqvFr6qxdlSOjuwm2UpaJ4_ev47EPJS3ndl2v_uiHhnztkzLNhE1LUMArA',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T04:10:59.084Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3340-2850-4674-78454',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T04:15:58.601Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-2850-4674-78454',
                    }
                ],
            },
        )
        refund_a = TestScenario(  # 2. Developer refunds subscription (removing entitlement)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760069492722',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 12,
                    'purchaseToken': 'aciongiofnlcagplnndcfhnf.AO-J1OyRJ1NXBfFEzDi14GkTdi6d1iJ5XudWH7CY5pMziU2IExCSZHIkc0LXnsqvFr6qxdlSOjuwm2UpaJ4_ev47EPJS3ndl2v_uiHhnztkzLNhE1LUMArA',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T04:10:59.084Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3340-2850-4674-78454',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T04:11:32.330Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T04:11:32.330Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-2850-4674-78454',
                    }
                ],
            },
        )
        refund_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760069494987',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'aciongiofnlcagplnndcfhnf.AO-J1OyRJ1NXBfFEzDi14GkTdi6d1iJ5XudWH7CY5pMziU2IExCSZHIkc0LXnsqvFr6qxdlSOjuwm2UpaJ4_ev47EPJS3ndl2v_uiHhnztkzLNhE1LUMArA',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T04:10:59.084Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3340-2850-4674-78454',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T04:11:32.330Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T04:11:32.330Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-2850-4674-78454',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms, redeemed_ts_ms_rounded = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. Developer refunds subscription (removing entitlement)"""
        # Note that, refund_a is the event that causes the user in question to be revoked. Hence the
        # timestamp that we pass into the verify function uses event 'a'
        tx_refund_a = test_notification(refund_a, ctx)
        test_notification(refund_b, ctx)

        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Revoked,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            redeemed_ts_ms_rounded=redeemed_ts_ms_rounded,
            platform_refund_expires_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_refund_a.event_ms + 1000,  # +1s (wire nonce is integer seconds) to cross the expiry threshold
            revoke_unix_ts_ms=tx_refund_a.event_ms,
        )

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. Developer refunds subscription (removing entitlement)
        3. User purchases 1-month subscription
        4. User renews
        """

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 12-month subscription
        2. Developer refunds subscription (removing entitlement)
        3. User purchases 12-month subscription
        4. User renews
        """

    with TestingContext(pg_database, provider_testing_env=True) as ctx:
        """
        1. User purchases 1-month subscription, but does not redeem it.
        2. Developer refunds subscription (removing entitlement)
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760580587012',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'pnogbppobfdciojgdfgnmeal.AO-J1OxovjqCbzOzNldcpyo1pj4Equw02PLT12L4S1YoQjj6jzPOuYO7AoLrIBAIPS3tAUqHuST716b0a80dlpRriOeMpr6eOxk9aiXpokO2CYOZ7bSOPgs',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-16T02:09:46.878Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3396-6433-5991-21923',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-16T02:14:46.394Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3396-6433-5991-21923',
                    }
                ],
            },
        )
        renew = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760580615882',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'pnogbppobfdciojgdfgnmeal.AO-J1OxovjqCbzOzNldcpyo1pj4Equw02PLT12L4S1YoQjj6jzPOuYO7AoLrIBAIPS3tAUqHuST716b0a80dlpRriOeMpr6eOxk9aiXpokO2CYOZ7bSOPgs',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-16T02:09:46.878Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3396-6433-5991-21923..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-16T02:15:09.687Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3396-6433-5991-21923..0',
                    }
                ],
            },
        )
        refund_a = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760580644292',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 12,
                    'purchaseToken': 'pnogbppobfdciojgdfgnmeal.AO-J1OxovjqCbzOzNldcpyo1pj4Equw02PLT12L4S1YoQjj6jzPOuYO7AoLrIBAIPS3tAUqHuST716b0a80dlpRriOeMpr6eOxk9aiXpokO2CYOZ7bSOPgs',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-16T02:09:46.878Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3396-6433-5991-21923..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-16T02:10:44.089Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-16T02:10:44.089Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3396-6433-5991-21923..0',
                    }
                ],
            },
        )
        refund_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760580647465',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'pnogbppobfdciojgdfgnmeal.AO-J1OxovjqCbzOzNldcpyo1pj4Equw02PLT12L4S1YoQjj6jzPOuYO7AoLrIBAIPS3tAUqHuST716b0a80dlpRriOeMpr6eOxk9aiXpokO2CYOZ7bSOPgs',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-16T02:09:46.878Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3396-6433-5991-21923..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-16T02:10:44.089Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-16T02:10:44.089Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3396-6433-5991-21923..0',
                    }
                ],
            },
        )
        assert_clean_state(ctx)
        """1. User purchases 1-month subscription, but does not redeem it."""
        tx = test_make_purchase(purchase=purchase, plan=base.ProPlan.OneMonth, ctx=ctx)[0]
        tx = test_make_purchase(purchase=renew, plan=base.ProPlan.OneMonth, ctx=ctx)[0]
        with ctx.connection() as conn:
            unredeemed_payments = backend.get_unredeemed_payments_list(conn)
        for payment in unredeemed_payments:
            assert derived_status(payment) == base.PaymentStatus.Unredeemed

        """2. Developer refunds subscription (removing entitlement)"""
        test_notification(refund_a, ctx)
        with ctx.connection() as conn:
            unredeemed_payments = backend.get_unredeemed_payments_list(conn)
        for payment in unredeemed_payments:
            assert derived_status(payment) == base.PaymentStatus.Revoked
        test_notification(refund_b, ctx)
        for payment in unredeemed_payments:
            assert derived_status(payment) == base.PaymentStatus.Revoked
