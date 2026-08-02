'''
Shared scaffolding for the test suite: the Flask/DB context, the client flows every provider
test replays, and the credit fixture.
'''

import collections.abc
import contextlib
import pprint
import flask
import nacl.signing
import nacl.bindings
import nacl.public
import os
import pendulum
import werkzeug
import dataclasses
import typing
import enum
import psycopg
import psycopg_pool
import traceback
from providers import google_play
import backend
import base
import minting
import server
from providers import app_store
import db
from appstoreserverlibrary.models.ResponseBodyV2DecodedPayload import (
    ResponseBodyV2DecodedPayload as AppleResponseBodyV2DecodedPayload,
)


def pk_hex(pk: bytes | nacl.signing.VerifyKey | None) -> str:
    return 'None' if pk is None else bytes(pk).hex()


def derived_status(payment: backend.PaymentRow, at: pendulum.DateTime | None = None) -> base.PaymentStatus:
    """A payment's status is derived from its timestamps, not stored (see backend.derive_payment_status).

    These assertions check the *latched* facts — redeemed / revoked — which do not depend on the
    observation time (revoked short-circuits; purchase is always before expiry), so by default we
    observe at the payment's purchase instant. Pass `at` to probe the one time-relative boundary,
    expiry, explicitly (e.g. `payment.expiry_at` to assert Expired)."""
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
    saved_renewal_allowance: pendulum.Duration = base.RENEWAL_LATENCY_ALLOWANCE

    def __init__(self, db_url_factory: typing.Callable[[], str], provider_testing_env: bool = False):
        self.db_url_factory = db_url_factory
        self.provider_testing_env = provider_testing_env

    def __enter__(self):
        base.PROVIDER_TESTING_ENV = self.provider_testing_env
        self.saved_renewal_allowance = base.RENEWAL_LATENCY_ALLOWANCE
        if base.PROVIDER_TESTING_ENV:
            base.RENEWAL_LATENCY_ALLOWANCE = base.duration_from_ms(google_play.api.testing_renewal_latency_allowance_ms)

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
        base.RENEWAL_LATENCY_ALLOWANCE = self.saved_renewal_allowance
        return False

    @contextlib.contextmanager
    def connection(self) -> collections.abc.Iterator[psycopg.Connection]:
        with db.connection() as conn:
            yield conn


def _google_subscription_parse(monkeypatch):
    # Shared setup for the two below: fetch succeeds (returns a non-None sentinel), reaching the parse step.
    monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', lambda *a, **k: object())
    return google_play.ParsedNotification(
        payload_type=google_play.ParsedNotificationPayloadType.Subscription,
        purchase_token='tok-xyz',
        package_name='pkg',
        event_time_ms=1,
    )


def _redeem_and_prove(conn, backend_key, master_key, rotating_key, request_at):
    """The reflow's client flow: generate_pro_proof reconciles any pending payments for the key (redeeming
    whatever the mule registered, bound by the master-key-derived account-id) and returns the proof.
    Replaces the retired verify_and_add_pro_payment in tests that seed a payment then 'redeem' it."""
    msg = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, request_at=request_at
    )
    return backend.generate_pro_proof(
        conn=conn,
        signing_key=backend_key,
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=request_at,
        master_sig=bytes(master_key.sign(msg).signature),
        rotating_sig=bytes(rotating_key.sign(msg).signature),
    )


def _grant_voucher(conn, master_key, at, duration, plan=None):
    """Mint an out-of-band credit for `master_key`, claimed on the spot -- the CLI voucher path. The only
    way to create a payment no store witnessed, so a test cannot accidentally exercise a shape production
    can no longer produce."""
    with db.transaction(conn) as tx:
        minting.mint_payment(
            tx,
            master_pkey=master_key.verify_key,
            provider=base.PaymentProvider.SessionFoundation,
            plan=plan if plan is not None else base.ProPlan.OneMonth,
            now=at,
            duration=duration,
        )


def _grant_and_get_offset(conn, backend_key, master_key, rotating_key, granted_at, expiry_at, plan=None):
    """Grant a voucher long enough to run to `expiry_at` and return the account's proof-expiry offset.

    `granted_at` must be a UTC day boundary for the entitlement to end exactly at `expiry_at`: a credit is
    anchored at its day-rounded redemption instant, so granting at any other time of day runs the
    entitlement to the following midnight plus the length. Callers that assert on the resulting expiry need
    `base.round_datetime_to_next_day` first; callers that only read the offset back do not care."""
    _grant_voucher(conn, master_key, at=granted_at, duration=expiry_at - granted_at, plan=plan)
    return backend.get_user(conn, master_key.verify_key).proof_expiry_offset


def _prove_at(conn, backend_key, master_key, rotating_key, request_at):
    with db.transaction(conn) as tx:
        return backend.build_current_entitlement_proof(
            tx, master_key.verify_key, rotating_key.verify_key, request_at, backend_key
        )


class _CreditFixture:
    """Scaffolding for the credit scenarios: mint credits, seed store subscriptions, run the drain at a
    chosen instant, and read back what the account is entitled to.

    Everything takes an explicit instant. The drain's whole contract is "charge the span since this
    account's checkpoint", so being able to place mints, lapses, refunds and passes at chosen instants is
    what makes the scenarios expressible at all -- and it means none of them depend on the wall clock.
    """

    def __init__(self, conn, now: pendulum.DateTime):
        self.conn = conn
        self.master_key = nacl.signing.SigningKey.generate()
        self.pkey = self.master_key.verify_key
        self.now = now

    def mint(self, length: pendulum.Duration, at: pendulum.DateTime | None = None) -> int:
        """Grant a credit of `length`, claimed immediately (the CLI voucher path). Returns its payment id."""
        with db.transaction(self.conn) as tx:
            minted = minting.mint_payment(
                tx,
                master_pkey=self.pkey,
                provider=base.PaymentProvider.SessionFoundation,
                plan=base.ProPlan.OneMonth,
                now=at if at is not None else self.now,
                duration=length,
            )
        assert minted.redeemed
        return self.payment_id_of(minted.payment_tx.stf_order_id)

    def payment_id_of(self, stf_order_id: str) -> int:
        return db.query_scalar(
            self.conn, 'SELECT payment_id FROM stf_payment_details WHERE order_id = %s', stf_order_id
        )

    def subscribe(
        self,
        expiry_at: pendulum.DateTime,
        purchased_at: pendulum.DateTime | None = None,
        auto_renewing: bool = True,
        grace: pendulum.Duration | None = None,
    ) -> base.PaymentProviderTransaction:
        """Seed a store subscription (Google) and claim it, as the mule + a client request would."""
        tx_ids = base.PaymentProviderTransaction()
        tx_ids.provider = base.PaymentProvider.GooglePlayStore
        tx_ids.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        tx_ids.google_order_id = 'DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        err = base.ErrorSink()
        purchased = purchased_at if purchased_at is not None else self.now
        backend.add_unredeemed_payment(
            self.conn,
            payment_tx=tx_ids,
            plan=base.ProPlan.OneMonth,
            purchased_at=purchased,
            expiry_at=expiry_at,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(self.pkey),
            err=err,
        )
        assert not err.msg_list, err.msg_list
        assert backend.reconcile_pending_payments(self.conn, self.pkey, redeemed_at=purchased) >= 1
        if not auto_renewing or grace is not None:
            with db.transaction(self.conn) as tx:
                backend.update_payment_renewal_info(
                    tx, payment_tx=tx_ids, grace_period=grace, auto_renewing=None if auto_renewing else False, err=err
                )
            assert not err.msg_list, err.msg_list
        return tx_ids

    def drain(self, at: pendulum.DateTime, stale_after: pendulum.Duration | None = None) -> int:
        """Run one drain pass as of `at`. `stale_after` defaults to zero so a scenario can place passes
        wherever it likes rather than having to wait out the production staleness threshold."""
        return backend.drain_due_credits(
            self.conn, now=at, stale_after=stale_after if stale_after is not None else pendulum.duration()
        )

    def expiry(self) -> pendulum.DateTime:
        return backend.get_user(self.conn, self.pkey).expiry_at

    def checkpoint(self) -> pendulum.DateTime | None:
        return db.query_scalar(
            self.conn, 'SELECT credits_checkpoint_at FROM users WHERE master_pkey = %s', bytes(self.pkey)
        )

    def remaining(self, payment_id: int) -> pendulum.Duration:
        return db.query_scalar(self.conn, 'SELECT credit_remaining FROM payments WHERE id = %s', payment_id)

    def total_remaining(self) -> pendulum.Duration:
        return db.query_scalar(
            self.conn,
            '''SELECT COALESCE(SUM(credit_remaining), '0'::interval) FROM payments p JOIN users u ON u.id = p.user_id
               WHERE u.master_pkey = %s AND p.revoked_at IS NULL''',
            bytes(self.pkey),
        )


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
        f'{prefix}decoded_notification = app_store.DecodedNotification('
        f'body={prefix}body, tx_info={prefix}tx_info, renewal_info={prefix}renewal_info)'
    )
    print(
        f'_ = app_store.handle_notification(decoded_notification={prefix}decoded_notification, conn=test.conn, err=err)'
    )
