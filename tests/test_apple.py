'''
The Apple App Store provider: the notification catch-up, and the recorded notification sequences
replayed end to end.
'''

import nacl.signing
import nacl.bindings
import nacl.public
import os
import pendulum
import typing
import psycopg_pool
import backend
import base
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

from tests.helpers import derived_status, TestingContext, _redeem_and_prove


def test_apple_catchup_isolates_a_bad_notification(monkeypatch, pg_database):
    # A notification Apple could not deliver is recoverable only through the history API, and a single
    # unhandleable one must not take the others with it. It used to: every notification shared one
    # transaction, so the first failure rolled back the ones already handled beside it AND left the
    # checkpoint unmoved, pinning the window behind it so nothing later was ever recovered again.
    from providers import app_store

    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    at = pendulum.datetime(2026, 7, 31, 12, 0)

    # Three notifications; the middle one raises, which is how several real branches fail (an
    # unconfigured SKU, an offer with an unexpected expiresDate) rather than reporting through the sink.
    payloads = ['good-1', 'boom', 'good-2']

    class StubHistoryItem:
        def __init__(self, payload: str):
            self.signedPayload = payload
            self.sendAttempts: list[typing.Any] = []

    class StubResponse:
        def __init__(self):
            self.notificationHistory = [StubHistoryItem(p) for p in payloads]
            self.hasMore = False
            self.paginationToken = None

    requested: list[typing.Any] = []

    class StubApiClient:
        def get_notification_history(self, pagination_token, notification_history_request):
            requested.append(notification_history_request)
            return StubResponse()

    class StubVerifier:
        def verify_and_decode_notification(self, payload: str) -> str:
            return payload

    def stub_decode(resp, verifier, err):
        if resp == 'boom':
            raise AssertionError('Invalid apple plan_id')
        body = AppleResponseBodyV2DecodedPayload()
        body.notificationUUID = f'uuid-{resp}'
        body.signedDate = base.unix_ms_from_datetime(at)
        return app_store.DecodedNotification(body=body)

    # handle_notification_tx is exercised for real; short-circuit it to "handled" so the test is about the
    # loop's isolation rather than any one notification type's semantics.
    def stub_handle(decoded_notification, tx, retry_duration, err):
        backend.apple_add_notification_uuid(
            tx, uuid=decoded_notification.body.notificationUUID, expires_at=at + 1 * base.DAY
        )
        return True

    monkeypatch.setattr(app_store, 'decoded_notification_from_apple_response_body_v2', stub_decode)
    monkeypatch.setattr(app_store, 'handle_notification_tx', stub_handle)

    core = app_store.Core(
        typing.cast(typing.Any, StubApiClient()), typing.cast(typing.Any, StubVerifier()), max_history_lookup_in_days=30
    )

    with db.connection() as conn:
        before = backend.get_global_datetime(conn, 'apple_notification_checkpoint_at')
        assert before == base.EPOCH  # never checkpointed
        app_store.catchup_on_missed_notifications(core=core, sql_conn=conn, now=at)

        # The good notifications either side of the failure were both recorded, and the bad one was not.
        with db.transaction(conn) as tx:
            assert backend.apple_notification_uuid_is_in_db(tx, 'uuid-good-1')
            assert backend.apple_notification_uuid_is_in_db(tx, 'uuid-good-2')
            assert not backend.apple_notification_uuid_is_in_db(tx, 'uuid-boom')

        # And the checkpoint advanced despite the failure, so recovery is not pinned behind it.
        assert backend.get_global_datetime(conn, 'apple_notification_checkpoint_at') == at

        # A first run with no checkpoint asks from the oldest history Apple will serve; the next run
        # re-reads an overlapping window rather than resuming exactly where this one stopped.
        assert base.datetime_from_unix_ms(requested[0].startDate) == at - 30 * base.DAY
        assert base.datetime_from_unix_ms(requested[0].endDate) == at
        later = at + 5 * base.HOUR
        app_store.catchup_on_missed_notifications(core=core, sql_conn=conn, now=later)
        assert base.datetime_from_unix_ms(requested[1].startDate) == at - app_store.NOTIFICATION_HISTORY_OVERLAP
    pool.close()


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
                expiry_at=base.datetime_from_unix_ms(expires_ms),
                purchased_at=base.datetime_from_unix_ms(expires_ms - (30 * base.MILLISECONDS_IN_DAY)),
                platform_refund_expiry_at=base.datetime_from_unix_ms(expires_ms),
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
                decoded_notification=decoded, conn=conn, notification_retry_duration=pendulum.duration(), err=err
            )
            assert not err.has(), err.msg_list
            assert handled

            # Then the stored value is the grace DURATION, not the absolute date,
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 1
            assert payment_list[0].grace_period == base.duration_from_ms(grace_len_ms)
            # and `expiry + grace` resolves to exactly gracePeriodExpiresDate (the absolute instant).
            assert payment_list[0].expiry_at is not None
            assert payment_list[0].expiry_at + payment_list[0].grace_period == base.datetime_from_unix_ms(
                renewal_info.gracePeriodExpiresDate
            )


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
    now = base.utc_now()
    redeemed_at = base.round_datetime_to_next_day(now)
    original_tx = os.urandom(8).hex()
    tx_id = os.urandom(8).hex()
    expiry_at = redeemed_at + 90 * base.DAY

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
            expiry_at=expiry_at,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=app_store.uuid_from_master_pk(bytes(master_key.verify_key)),
            err=err,
        )
        assert not err.has(), err.msg_list

        _redeem_and_prove(db_conn, backend_key, master_key, rotating_key, now)

        with db.transaction(db_conn) as tx:
            user_before = backend.get_user_and_payments(tx, master_key.verify_key).user
        gen_before, token_before, expiry_before = (
            user_before.current_generation_id,
            user_before.token,
            user_before.expiry_at,
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
            assert reinstated.expiry_at == expiry_before  # original window restored, not extended
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
            assert again.expiry_at == expiry_before
    finally:
        db_engine.putconn(db_conn)
        db_engine.close()


def test_platform_apple(pg_database):
    err = base.ErrorSink()

    # One Session account is claimed then auto-redeemed across every phase below; the client sets this
    # UUID as each purchase's appAccountToken, so the notifications carry it and the redeem (and the
    # later auto-redeems) bind against it.
    master_key = nacl.signing.SigningKey.generate()
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
                decoded_notification=notification, conn=conn, notification_retry_duration=pendulum.duration(), err=err
            )
            assert not err.has(), err.msg_list

            # NOTE: Subscription renewal should be unredeemed
            unredeemed_list: list[backend.PaymentRow] = backend.get_unredeemed_payments_list(conn)
            assert len(unredeemed_list) == 1
            assert unredeemed_list[0].master_pkey is None
            assert unredeemed_list[0].redeemed_at is None
            assert unredeemed_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert unredeemed_list[0].apple.original_tx_id == tx_info.originalTransactionId
            assert unredeemed_list[0].apple.tx_id == tx_info.transactionId
            assert unredeemed_list[0].apple.web_line_order_tx_id == tx_info.webOrderLineItemId

        # NOTE: Claim the payment. Redemption now happens via reconcile, which binds the mule-registered
        # payment by the master-key-derived account-id -- the reflow replaces the old /add_pro_payment
        # call. This renewal is dated in the past, so we assert the binding (proof issuance is covered by
        # the generate_pro_proof tests).
        with test.connection() as conn:
            redeemed_at = base.round_datetime_to_next_day(base.datetime_from_unix_ms(tx_info.signedDate))
            assert backend.reconcile_pending_payments(conn, master_key.verify_key, redeemed_at=redeemed_at) == 1
            assert not backend.get_unredeemed_payments_list(conn)
            assert backend.get_user(conn, master_key.verify_key).found

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
                notification_retry_duration=pendulum.duration(),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: Subscription purchase is unredeemed
            unredeemed_list = backend.get_unredeemed_payments_list(conn)
            assert len(unredeemed_list) == 1
            assert unredeemed_list[0].master_pkey is None
            assert unredeemed_list[0].plan == base.ProPlan.OneMonth
            assert unredeemed_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert unredeemed_list[0].auto_renewing
            assert unredeemed_list[0].purchased_at == base.datetime_from_unix_ms(tx_info.purchaseDate)
            assert unredeemed_list[0].redeemed_at is None
            assert unredeemed_list[0].expiry_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert unredeemed_list[0].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert unredeemed_list[0].platform_refund_expiry_at == base.datetime_from_unix_ms(tx_info.expiresDate)
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
                notification_retry_duration=pendulum.duration(),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: Check payment is still in the DB and that auto-renewing was turned off
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 1
            assert payment_list[0].master_pkey is None
            assert payment_list[0].plan == base.ProPlan.OneMonth
            assert payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert not payment_list[0].auto_renewing
            assert payment_list[0].purchased_at == base.datetime_from_unix_ms(tx_info.purchaseDate)
            assert payment_list[0].redeemed_at is None
            assert payment_list[0].expiry_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert payment_list[0].platform_refund_expiry_at == base.datetime_from_unix_ms(tx_info.expiresDate)
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
                notification_retry_duration=pendulum.duration(),
                err=err,
            )
            assert not err.has(), err.msg_list

            # NOTE: The payment expires as per Apple's notification. We don't have to do anything
            # necessarily as our proofs will self-expire.

            # NOTE: Check payment is still in the DB
            payment_list = backend.get_payments_list(conn)
            assert len(payment_list) == 1
            assert payment_list[0].master_pkey is None
            assert payment_list[0].plan == base.ProPlan.OneMonth
            assert payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert payment_list[0].purchased_at == base.datetime_from_unix_ms(tx_info.purchaseDate)
            assert payment_list[0].redeemed_at is None
            assert payment_list[0].expiry_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert payment_list[0].platform_refund_expiry_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].revoked_at is None
            assert payment_list[0].apple.original_tx_id == tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id == tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id == tx_info.webOrderLineItemId

        # NOTE: Run the housekeeping sweep at an instant past the payment's expiry
        with test.connection() as conn:
            past_expiry = payment_list[0].expiry_at + pendulum.duration(milliseconds=1)
            backend.delete_expired_apple_notification_uuids(conn, now=past_expiry)
            backend.delete_expired_google_notifications(conn, now=past_expiry)

            # NOTE: The sweep leaves the payment untouched — expiry is derived on read, never marked.
            payment_list = backend.get_payments_list(conn)

            assert len(payment_list) == 1
            assert payment_list[0].master_pkey is None
            assert payment_list[0].plan == base.ProPlan.OneMonth
            assert payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
            assert payment_list[0].purchased_at == base.datetime_from_unix_ms(tx_info.purchaseDate)
            assert payment_list[0].redeemed_at is None
            assert payment_list[0].expiry_at == base.datetime_from_unix_ms(tx_info.expiresDate)
            assert payment_list[0].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert payment_list[0].platform_refund_expiry_at == base.datetime_from_unix_ms(tx_info.expiresDate)
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
                notification_retry_duration=pendulum.duration(),
                err=err,
            )
            assert not err.has(), err.msg_list
            unredeemed_payment_list = backend.get_unredeemed_payments_list(conn)

        assert len(unredeemed_payment_list) == 1
        assert unredeemed_payment_list[0].master_pkey is None
        assert unredeemed_payment_list[0].plan == base.ProPlan.ThreeMonth
        assert unredeemed_payment_list[0].payment_provider == base.PaymentProvider.iOSAppStore
        assert unredeemed_payment_list[0].auto_renewing
        assert unredeemed_payment_list[0].purchased_at == base.datetime_from_unix_ms(
            e00_sub_to_3_months_tx_info.purchaseDate
        )
        assert unredeemed_payment_list[0].redeemed_at is None
        assert unredeemed_payment_list[0].expiry_at == base.datetime_from_unix_ms(
            e00_sub_to_3_months_tx_info.expiresDate
        )
        assert unredeemed_payment_list[0].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
        assert unredeemed_payment_list[0].platform_refund_expiry_at == base.datetime_from_unix_ms(
            e00_sub_to_3_months_tx_info.expiresDate
        )
        assert unredeemed_payment_list[0].revoked_at is None
        assert unredeemed_payment_list[0].apple.original_tx_id == e00_sub_to_3_months_tx_info.originalTransactionId
        assert unredeemed_payment_list[0].apple.tx_id == e00_sub_to_3_months_tx_info.transactionId
        assert unredeemed_payment_list[0].apple.web_line_order_tx_id == e00_sub_to_3_months_tx_info.webOrderLineItemId

        # NOTE: Then redeem the payment (reconcile binds it by the master-key-derived account-id).
        with test.connection() as conn:
            redeemed_at = base.round_datetime_to_next_day(
                base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.purchaseDate)
            )
            assert backend.reconcile_pending_payments(conn, master_key.verify_key, redeemed_at=redeemed_at) == 1

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
        assert payment_list[0].expiry_at == base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.expiresDate)
        assert payment_list[0].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
        assert payment_list[0].platform_refund_expiry_at == base.datetime_from_unix_ms(
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
                notification_retry_duration=pendulum.duration(),
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
            assert payment_list[0].expiry_at == base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.expiresDate)
            assert payment_list[0].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert payment_list[0].platform_refund_expiry_at == base.datetime_from_unix_ms(
                e00_sub_to_3_months_tx_info.expiresDate
            )
            assert payment_list[0].revoked_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)
            assert payment_list[0].apple.original_tx_id == e00_sub_to_3_months_tx_info.originalTransactionId
            assert payment_list[0].apple.tx_id == e00_sub_to_3_months_tx_info.transactionId
            assert payment_list[0].apple.web_line_order_tx_id == e00_sub_to_3_months_tx_info.webOrderLineItemId
            assert payment_list[0].revoked_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.purchaseDate)

            # NOTE: The previous payment was revoked, but it won't be in the revocation list: it was already
            # expiring within the day, and revoke_payments_by_id_internal's day-boundary early-out skips
            # broadcasting a payment that is on its way out regardless.
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
            assert payment_list[1].expiry_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.expiresDate)
            assert payment_list[1].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert payment_list[1].platform_refund_expiry_at == base.datetime_from_unix_ms(
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
                notification_retry_duration=pendulum.duration(),
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
                notification_retry_duration=pendulum.duration(),
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
            assert payment_list[-1].expiry_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.expiresDate)
            assert payment_list[-1].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert payment_list[-1].platform_refund_expiry_at == base.datetime_from_unix_ms(
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
                notification_retry_duration=pendulum.duration(),
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
            assert payment_list[0].expiry_at == base.datetime_from_unix_ms(e00_sub_to_3_months_tx_info.expiresDate)
            assert payment_list[0].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert payment_list[0].platform_refund_expiry_at == base.datetime_from_unix_ms(
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
            assert payment_list[-1].expiry_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.expiresDate)
            assert payment_list[-1].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert payment_list[-1].platform_refund_expiry_at == base.datetime_from_unix_ms(
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
                notification_retry_duration=pendulum.duration(),
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
                notification_retry_duration=pendulum.duration(),
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
            assert payment_list[-1].expiry_at == base.datetime_from_unix_ms(e01_upgrade_to_1wk_tx_info.expiresDate)
            assert payment_list[-1].grace_period == base.RENEWAL_LATENCY_ALLOWANCE
            assert payment_list[-1].platform_refund_expiry_at == base.datetime_from_unix_ms(
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
                notification_retry_duration=pendulum.duration(),
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
                notification_retry_duration=pendulum.duration(),
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
                notification_retry_duration=pendulum.duration(),
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
