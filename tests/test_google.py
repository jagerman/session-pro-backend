'''
The Google Play provider: notification handling in isolation, and the recorded RTDN sequences
replayed end to end.
'''

import json
import nacl.signing
import nacl.bindings
import nacl.public
import os
import pendulum
import time
import dataclasses
from providers import google_play
from providers.google_play.types import GoogleDuration, SubscriptionProductDetails
import backend
import base
import server
import db

from tests.helpers import derived_status, TestingContext, _google_subscription_parse, _redeem_and_prove


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
            expiry_at=base.EPOCH,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=os.urandom(32),
            err=err,
            needs_ack=needs_ack,
        )
        assert not err.msg_list, err.msg_list

    def flag(conn, token):
        return db.query_scalar(
            conn, 'SELECT needs_ack FROM google_play_payment_details WHERE payment_token = %s', token
        )

    tok_ok = os.urandom(32).hex()
    tok_crashed = os.urandom(32).hex()
    tok_fail = os.urandom(32).hex()
    tok_already = os.urandom(32).hex()

    with db.connection() as conn:
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
        expiry_at: int

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
            purchase_token=purchase_token, order_id=order_id, event_ms=event_ms, expiry_at=expiry_time_unix_ms
        )

    """
    Testing Interaction Utility Functions
    """

    def get_pro_status(user_ctx: TestUserCtx, ctx: TestingContext, unix_ts_ms: int) -> base.JSONObject:
        ts = unix_ts_ms // 1000  # wire nonce is integer seconds (wire spec §1.1)
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
        ts = unix_ts_ms // 1000  # wire nonce is integer seconds (wire spec §1.1)
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
        # Redeem the mule-registered payment for this user: reconcile binds it by the master-key
        # account-id (the reflow replaces the old /add_pro_payment round-trip).
        with ctx.connection() as conn:
            backend.reconcile_pending_payments(
                conn,
                user_ctx.master_key.verify_key,
                redeemed_at=backend.to_redeemed_at(base.datetime_from_unix_ms(tx.event_ms)),
            )
        return base.unix_ms_from_datetime(base.round_datetime_to_next_day(base.datetime_from_unix_ms(tx.event_ms)))

    def run_prune_at_end_of_day(event_ms: int):
        boundary_ms = base.unix_ms_from_datetime(
            backend.round_datetime_to_next_day_with_provider_testing_support(
                payment_provider=base.PaymentProvider.GooglePlayStore, at=base.datetime_from_unix_ms(event_ms)
            )
        )
        end_of_day = base.datetime_from_unix_ms(event_ms + boundary_ms)
        with ctx.connection() as conn:
            backend.delete_expired_apple_notification_uuids(conn, now=end_of_day)
            backend.delete_expired_google_notifications(conn, now=end_of_day)

    """
    Testing Assert Utility Functions
    """

    def assert_clean_state(ctx: TestingContext):
        with ctx.connection() as conn:
            assert not backend.get_unredeemed_payments_list(conn)
            assert not backend.get_payments_list(conn)
            assert not backend.get_revocations_list(conn)

    def assert_has_unredeemed_payment(
        tx: TestTx, plan: base.ProPlan, platform_refund_expiry_at: int, ctx: TestingContext
    ):
        with ctx.connection() as conn:
            unredeemed_payments = backend.get_unredeemed_payments_list(conn)
            found = False
            for unredeemed_payment in unredeemed_payments:
                if unredeemed_payment.google_order_id == tx.order_id:
                    found = True
                    assert isinstance(unredeemed_payment, backend.PaymentRow)
                    assert unredeemed_payment.master_pkey is None
                    assert unredeemed_payment.plan == plan
                    assert unredeemed_payment.payment_provider == base.PaymentProvider.GooglePlayStore
                    assert unredeemed_payment.redeemed_at is None
                    assert unredeemed_payment.expiry_at == base.datetime_from_unix_ms(tx.expiry_at)
                    assert unredeemed_payment.grace_period == pendulum.duration()
                    assert unredeemed_payment.platform_refund_expiry_at == base.datetime_from_unix_ms(
                        platform_refund_expiry_at
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
        platform_refund_expiry_at: int,
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
            assert payment.expiry_at == base.datetime_from_unix_ms(tx.expiry_at)
            assert payment.grace_period == base.DEFAULT_GOOGLE_GRACE_PERIOD
            assert payment.platform_refund_expiry_at == base.datetime_from_unix_ms(platform_refund_expiry_at)
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
            # assert a generation count here: a generation is an epoch, reused across payments and
            # rolled only on revocation, so the count is scenario-dependent, not one-per-payment. The
            # current generation must be one of the user's, and (for these non-revoked scenarios) live.
            user_gen_ids = {row[0] for row in db.query(conn, "SELECT id FROM generations WHERE user_id = %s", user.id)}
            assert user.current_generation_id in user_gen_ids
            assert not backend.is_generation_revoked(
                conn, user.current_generation_id, base.datetime_from_unix_ms(tx.event_ms)
            )
            assert len(user.token) == backend.BLAKE2B_DIGEST_SIZE
            assert user.expiry_at == base.datetime_from_unix_ms(tx.expiry_at) + base.DEFAULT_GOOGLE_GRACE_PERIOD

    def assert_payment_details(
        tx: TestTx,
        pro_status: server.UserProStatus,
        payment_status: base.PaymentStatus,
        auto_renew: bool,
        grace_duration: pendulum.Duration,
        platform_refund_expiry_at: int,
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
            expiry_at = res_expiry_ts
            if res_auto_renewing:
                expiry_at -= res_grace_period_duration
            assert expiry_at == to_s(tx.expiry_at), json.dumps(result, indent=1)
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
        item_revoked_ts = base.json_dict_require_float(item, "revoked_ts", err)
        item_status = base.json_dict_require_str_coerce_to_enum(item, "status", base.PaymentStatus, err)
        assert not err.has()
        assert item_expiry_ts == to_s(tx.expiry_at), res_latest
        # Google `payment_id` is the opaque `token|order_id` composite (backend-owned; §5.2).
        assert item_payment_id == f'{tx.purchase_token}|{tx.order_id}'
        assert item_grace_duration == base.seconds_from_duration(grace_duration)
        assert item_payment_provider == base.PaymentProvider.GooglePlayStore
        assert item_platform_refund_expiry_ts == to_s(platform_refund_expiry_at)
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
                tx=tx, plan=plan, platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms, ctx=ctx
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        return tx, platform_refund_expiry_unix_tx_ms

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
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        # Expire payments at the EOD of the resubscribe expiry_ts (note the extend expiry_ts from the grace period tx)
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)

        # Now that payments up to the expiry time has been expired, this user's status should be expired (we need to also time-travel the clock past the grace period they were allocated)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        run_prune_at_end_of_day(event_ms=tx_expire.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_renew,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        # Expire payments
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        run_prune_at_end_of_day(event_ms=tx_expire.event_ms)
        assert_payment_details(
            tx=tx_renew_2,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=base.DEFAULT_GOOGLE_GRACE_PERIOD,
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_expire.event_ms,
        )

        """6. User purchased (SUBSCRIPTION_PURCHASED)"""
        tx_resubscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=resubscribe, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """7. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_resubscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        # Now that payments up to the expiry time has been expired, this user's status should be expired
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        assert_payment_details(
            tx=tx_resubscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        # Expire payments at the EOD of the resubscribe expiry_ts (not the extend expiry_ts from the grace period tx)
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
        tx_change_plan, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
        )
        test_notification(change_plan_b, ctx)

        """3. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)

        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
        tx_change_plan, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
        )
        test_notification(change_plan_b, ctx)

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            grace_duration=base.duration_from_ms(test_product_details.grace_period.milliseconds),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
        tx_change_plan, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
        )
        test_notification(change_plan_b, ctx)

        """3. User changes to 1-month plan"""
        tx_change_plan, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=change_plan_back_a, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
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
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
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
            assert payment.redeemed_at is None

        """2. Developer refunds subscription (removing entitlement)"""
        test_notification(refund_a, ctx)
        with ctx.connection() as conn:
            unredeemed_payments = backend.get_unredeemed_payments_list(conn)
        for payment in unredeemed_payments:
            assert derived_status(payment) == base.PaymentStatus.Revoked
        test_notification(refund_b, ctx)
        for payment in unredeemed_payments:
            assert derived_status(payment) == base.PaymentStatus.Revoked


# ----------------------------------------------------------------------------------------------------
# Characterisation of the convergence defects (see the simplify-google-processing findings).
#
# These pin what the type-dispatching handler does TODAY, including where that is wrong. Each one names
# the defect it captures; the reconcile rewrite is expected to invert them deliberately, not by accident.
# ----------------------------------------------------------------------------------------------------

_UPGRADE_ACCOUNT_SEED = bytes([0x42] * 32)


def _google_snapshot(
    *,
    state: str,
    expiry: str,
    order_id: str,
    obfuscated_account_id: bytes,
    base_plan: str = 'session-pro-1-month',
    auto_renew: bool = True,
    linked_purchase_token: str | None = None,
    start_time: str = '2026-01-01T00:00:00.000Z',
) -> base.JSONObject:
    """One `purchases.subscriptionsv2.get` response body, as the handler would fetch it."""
    result: base.JSONObject = {
        'kind': 'androidpublisher#subscriptionPurchaseV2',
        'startTime': start_time,
        'regionCode': 'AU',
        'subscriptionState': state,
        'latestOrderId': order_id,
        'testPurchase': {},
        'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
        'externalAccountIdentifiers': {'obfuscatedExternalAccountId': obfuscated_account_id.hex()},
        'lineItems': [
            {
                'productId': 'session_pro',
                'expiryTime': expiry,
                'autoRenewingPlan': {
                    'autoRenewEnabled': auto_renew,
                    'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                },
                'offerDetails': {'basePlanId': base_plan, 'offerTags': ['tag']},
                'latestSuccessfulOrderId': order_id,
            }
        ],
    }
    if linked_purchase_token is not None:
        result['linkedPurchaseToken'] = linked_purchase_token
    return result


def _drive_google_rtdn(
    monkeypatch, ctx, *, notification_type: int, purchase_token: str, event_ms: int, snapshot: base.JSONObject
) -> tuple[bool, base.ErrorSink]:
    """Push one subscription RTDN through handle_parsed_notification against `snapshot`.

    Unlike the driver inside test_google_platform_handle_notification this does NOT assert success: these
    tests are about the paths where handling silently does nothing, or fails and wedges.
    """
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    err_parse = base.ErrorSink()
    details = google_play.api.parse_get_subscription_v2_response(snapshot, err_parse)
    assert not err_parse.has() and details is not None
    monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', lambda *a, **k: details)
    monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda *a, **k: None)

    rtdn: base.JSONObject = {
        'version': '1.0',
        'packageName': 'network.loki.messenger',
        'eventTimeMillis': str(event_ms),
        'subscriptionNotification': {
            'version': '1.0',
            'notificationType': notification_type,
            'purchaseToken': purchase_token,
            'subscriptionId': 'session_pro',
        },
    }
    err = base.ErrorSink()
    parse = google_play.parse_notification(rtdn, err)
    with ctx.connection() as conn:
        with db.transaction(conn) as tx:
            handled = google_play.handle_parsed_notification(tx, parse, err)
    return handled, err


def _payment_rows(ctx) -> list[tuple]:
    with ctx.connection() as conn:
        return db.query(
            conn,
            '''
            SELECT gd.order_id, p.expiry_at, p.revoked_at
            FROM   payments p JOIN google_play_payment_details gd ON gd.payment_id = p.id
            ORDER BY p.id
            ''',
        ).fetchall()


def test_google_purchase_against_a_stale_state_is_silently_dropped(monkeypatch, pg_database):
    # CHARACTERISATION of finding 3.1. The PURCHASED branch gates on the state of a FRESHLY FETCHED
    # snapshot (notifications.py), while the notification type comes from the message. Process a PURCHASED
    # once the store already reads CANCELED -- the user bought, then turned auto-renew off, and our
    # subscriber was down in between -- and the guard fails, so the branch is skipped ENTIRELY.
    #
    # The damning part is the two asserts on `handled`/`err`: nothing is recorded, yet handling reports
    # success, so the pull loop acks the message and Google never redelivers it. A purchase token is the one
    # fact in this system that cannot be re-fetched (no endpoint enumerates subscribers), so this is an
    # unrecoverable paid-but-no-Pro.
    #
    # The follow-up CANCELED then wedges: its own guard matches, but the UPDATE it performs finds no row,
    # which is reported as failure -> tx.cancel -> never acked -> retried with backoff forever, waiting on a
    # row that can never appear.
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)
        token = 'tok-purchased-then-cancelled'
        snapshot = _google_snapshot(
            state='SUBSCRIPTION_STATE_CANCELED',
            expiry='2026-02-01T00:00:00.000Z',
            order_id='GPA.1111-2222-3333-44444',
            obfuscated_account_id=account_id,
            auto_renew=False,
        )

        handled, err = _drive_google_rtdn(
            monkeypatch, ctx, notification_type=4, purchase_token=token, event_ms=1767225600000, snapshot=snapshot
        )
        assert not _payment_rows(ctx), 'the purchase was dropped -- this is the defect being pinned'
        assert handled is True, 'and reported as handled, so the pull loop acks it and it is gone for good'
        assert not err.has(), 'silently: no error is raised for the operator to see'

        # The cancellation for the same token now has nothing to update.
        handled, err = _drive_google_rtdn(
            monkeypatch, ctx, notification_type=3, purchase_token=token, event_ms=1767312000000, snapshot=snapshot
        )
        assert handled is False and err.has(), 'so this one fails and is retried forever'


def test_google_upgrade_revokes_every_consumed_cycle(monkeypatch, pg_database):
    # CHARACTERISATION of findings 3.3 and 3.6. A monthly subscriber who switches plans gets a NEW purchase
    # token, and the new subscription's snapshot names the old one in linkedPurchaseToken. The handler
    # responds by calling add_google_revocation on the old token -- whose SELECT carries no ORDER BY and no
    # LIMIT, so it revokes EVERY cycle ever recorded under that token, not the live one.
    #
    # Consumed cycles that ended months earlier are therefore stamped revoked_at = the upgrade instant, and
    # get_payment_details reports them to the client as `revoked`. Nothing was refunded. That is revoked_at
    # coming to mean "this payment never existed", which CLAUDE.md's invariant forbids.
    #
    # Its comment claims to "Select the newest google transaction"; it does not.
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)
        old_token = 'tok-monthly'
        cycles = [
            ('GPA.9000-0000-0000-00001', '2026-02-01T00:00:00.000Z', 1767225600000),
            ('GPA.9000-0000-0000-00001..0', '2026-03-01T00:00:00.000Z', 1769904000000),
            ('GPA.9000-0000-0000-00001..1', '2026-04-01T00:00:00.000Z', 1772323200000),
        ]
        for index, (order_id, expiry, event_ms) in enumerate(cycles):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4 if index == 0 else 2,  # PURCHASED, then RENEWED
                purchase_token=old_token,
                event_ms=event_ms,
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=expiry,
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()
        assert len(_payment_rows(ctx)) == 3

        # The switch: one PURCHASED, on a new token, naming the old one.
        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token='tok-annual',
            event_ms=1773532800000,  # 2026-03-15, mid-way through the third month
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2027-03-15T00:00:00.000Z',
                order_id='GPA.8000-0000-0000-00002',
                obfuscated_account_id=account_id,
                base_plan='session-pro-12-months',
                linked_purchase_token=old_token,
            ),
        )
        assert handled and not err.has()

        rows = _payment_rows(ctx)
        assert len(rows) == 4
        revoked = {order_id: revoked_at for order_id, _, revoked_at in rows}
        assert revoked['GPA.8000-0000-0000-00002'] is None, 'the replacement itself survives'
        # All three monthly cycles are revoked, including the two that had already run to completion.
        assert all(revoked[order_id] is not None for order_id, _, _ in cycles)
        consumed = revoked['GPA.9000-0000-0000-00001']
        assert consumed is not None
        expired_at = [expiry_at for order_id, expiry_at, _ in rows if order_id == 'GPA.9000-0000-0000-00001'][0]
        assert consumed > expired_at, 'revoked at the upgrade instant, long after this cycle actually ended'


def test_google_upgrade_broadcasts_a_revocation_for_an_account_that_never_lapsed(monkeypatch, pg_database):
    # CHARACTERISATION of findings 3.4 and 3.5. Same upgrade as above, but with the subscription CLAIMED, so
    # the payments carry a user_id and the revocation path actually reaches its broadcast decision.
    #
    # That decision runs BEFORE the replacement payment is inserted (the linked-token revoke is the first
    # statement in the PURCHASED branch, the insert comes after), so it judges an account that appears to
    # have nothing left -- and rolls the generation, invalidating every outstanding proof, and publishes an
    # entry into the revocation list that every client downloads for the 31-day retention. The account's
    # coverage never lapsed for an instant: it upgraded.
    #
    # Which of the two branches is taken is decided by the LAST row of an unordered SELECT (finding 3.4), so
    # the value pinned below is the one this fixture produces; it is not a guarantee of the code's shape.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        old_token = 'tok-monthly'

        for index, (order_id, expiry, event_ms) in enumerate(
            [
                ('GPA.9000-0000-0000-00001', '2026-02-01T00:00:00.000Z', 1767225600000),
                ('GPA.9000-0000-0000-00001..0', '2026-03-01T00:00:00.000Z', 1769904000000),
                ('GPA.9000-0000-0000-00001..1', '2026-04-01T00:00:00.000Z', 1772323200000),
            ]
        ):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4 if index == 0 else 2,
                purchase_token=old_token,
                event_ms=event_ms,
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=expiry,
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()

        # Claim the subscription: the account now has a generation, and outstanding proofs to protect.
        claimed_at = base.datetime_from_unix_ms(1773187200000)  # 2026-03-11, inside the third cycle
        with ctx.connection() as conn:
            _redeem_and_prove(conn, ctx.backend_key, master_key, rotating_key, claimed_at)
            generation_before = backend.get_user(conn, master_key.verify_key).current_generation_id
            assert not backend.get_revocations_list(conn)

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token='tok-annual',
            event_ms=1773532800000,  # 2026-03-15
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2027-03-15T00:00:00.000Z',
                order_id='GPA.8000-0000-0000-00002',
                obfuscated_account_id=account_id,
                base_plan='session-pro-12-months',
                linked_purchase_token=old_token,
            ),
        )
        assert handled and not err.has()

        upgraded_at = base.datetime_from_unix_ms(1773532800000)
        with ctx.connection() as conn:
            user = backend.get_user(conn, master_key.verify_key)
            revocations = backend.get_revocations_list(conn)
            assert len(revocations) == 1, 'an entry every client downloads for the 31-day retention'
            assert revocations[0].generation_id == generation_before, 'the generation the account was using'

            # No replacement generation is allocated, because at that instant the account has no usable
            # payment: the old cycles were just revoked and the annual one has not been inserted yet. So the
            # account is left POINTING AT a revoked generation, with every outstanding proof invalidated.
            assert user.current_generation_id == generation_before

            # And its expiry is left at the upgrade instant -- the account reads as lapsed. The replacement
            # payment is inserted unredeemed, and _lookup_user_expiry filters on user_id, so the recompute
            # inside the revoke path cannot see it; it sees only the coverage it just revoked.
            assert user.expiry_at == upgraded_at

        # It self-heals on the account's next request, which claims the replacement before recomputing.
        with ctx.connection() as conn:
            _redeem_and_prove(conn, ctx.backend_key, master_key, rotating_key, upgraded_at)
            assert backend.get_user(conn, master_key.verify_key).expiry_at > upgraded_at
